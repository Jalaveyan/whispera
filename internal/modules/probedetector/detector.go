package probedetector

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"whispera/internal/logger"
)

var log = logger.Module("probedetector")

type Config struct {
	MaxAuthFailures int
	FailWindow      time.Duration
	BlockDuration   time.Duration

	RequireDNSQuery bool
	DNSQueryWindow  time.Duration

	CheckSNIOwnership bool
	OwnPublicIPs      []string
	SNICacheExpiry    time.Duration

	EscalatingBans     bool
	MaxBanEscalation   int
	BurstThreshold     int
	BurstWindow        time.Duration
}

func DefaultConfig() Config {
	return Config{
		MaxAuthFailures: 5,
		FailWindow:      5 * time.Minute,
		BlockDuration:   30 * time.Minute,

		RequireDNSQuery: false,
		DNSQueryWindow:  90 * time.Second,

		CheckSNIOwnership: false,
		SNICacheExpiry:    5 * time.Minute,

		EscalatingBans:   true,
		MaxBanEscalation: 5,
		BurstThreshold:   10,
		BurstWindow:      30 * time.Second,
	}
}

type blockEntry struct {
	until      time.Time
	reason     string
	escalation int
}

type dnsEntry struct {
	at          time.Time
	resolvedIPs []string
}

type sniCacheEntry struct {
	ips     []string
	fetched time.Time
}

type Detector struct {
	cfg Config

	mu       sync.RWMutex
	failures map[string][]time.Time
	blocked  map[string]blockEntry
	dnsLog   map[string]map[string]dnsEntry
	sniCache map[string]sniCacheEntry

	banHistory map[string]int

	ownIPs map[string]struct{}

	cleanupStop chan struct{}
}

func New(cfg Config) *Detector {
	if cfg.MaxAuthFailures <= 0 {
		cfg.MaxAuthFailures = 5
	}
	if cfg.FailWindow <= 0 {
		cfg.FailWindow = 5 * time.Minute
	}
	if cfg.BlockDuration <= 0 {
		cfg.BlockDuration = 30 * time.Minute
	}
	if cfg.DNSQueryWindow <= 0 {
		cfg.DNSQueryWindow = 90 * time.Second
	}
	if cfg.SNICacheExpiry <= 0 {
		cfg.SNICacheExpiry = 5 * time.Minute
	}

	d := &Detector{
		cfg:         cfg,
		failures:    make(map[string][]time.Time),
		blocked:     make(map[string]blockEntry),
		dnsLog:      make(map[string]map[string]dnsEntry),
		sniCache:    make(map[string]sniCacheEntry),
		banHistory:  make(map[string]int),
		ownIPs:      make(map[string]struct{}),
		cleanupStop: make(chan struct{}),
	}

	for _, ip := range cfg.OwnPublicIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			d.ownIPs[ip] = struct{}{}
		}
	}
	if len(d.ownIPs) == 0 {
		d.autoDetectOwnIPs()
	}

	return d
}

func (d *Detector) Start() {
	go d.cleanupLoop()
}

func (d *Detector) Stop() {
	close(d.cleanupStop)
}

func (d *Detector) RecordDNSQuery(clientAddr, hostname string, resolvedIPs []string) {
	ip := extractIP(clientAddr)
	if ip == "" {
		return
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))

	d.mu.Lock()
	if d.dnsLog[ip] == nil {
		d.dnsLog[ip] = make(map[string]dnsEntry)
	}
	d.dnsLog[ip][hostname] = dnsEntry{
		at:          time.Now(),
		resolvedIPs: resolvedIPs,
	}
	d.mu.Unlock()
}

func (d *Detector) RecordAuthFailure(clientAddr string) {
	ip := extractIP(clientAddr)
	if ip == "" {
		return
	}

	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	d.failures[ip] = append(d.failures[ip], now)
	d.failures[ip] = pruneOlderThan(d.failures[ip], now.Add(-d.cfg.FailWindow))

	threshold := d.cfg.MaxAuthFailures

	if d.cfg.BurstThreshold > 0 && d.cfg.BurstWindow > 0 {
		burstCutoff := now.Add(-d.cfg.BurstWindow)
		burstCount := 0
		for _, t := range d.failures[ip] {
			if t.After(burstCutoff) {
				burstCount++
			}
		}
		if burstCount >= d.cfg.BurstThreshold {
			threshold = 1
		}
	}

	if len(d.failures[ip]) >= threshold {
		banDuration := d.cfg.BlockDuration
		escalation := 0

		if d.cfg.EscalatingBans {
			escalation = d.banHistory[ip]
			if escalation > d.cfg.MaxBanEscalation {
				escalation = d.cfg.MaxBanEscalation
			}
			for i := 0; i < escalation; i++ {
				banDuration *= 2
			}
			d.banHistory[ip] = escalation + 1
		}

		d.blocked[ip] = blockEntry{
			until:      now.Add(banDuration),
			reason:     fmt.Sprintf("%d auth failures in %v (escalation=%d)", len(d.failures[ip]), d.cfg.FailWindow, escalation),
			escalation: escalation,
		}
		delete(d.failures, ip)
		log.Info("[probe] blocked %s for %v (escalation=%d): too many auth failures", ip, banDuration, escalation)
	}
}

func (d *Detector) RecordAuthSuccess(clientAddr string) {
	ip := extractIP(clientAddr)
	if ip == "" {
		return
	}
	d.mu.Lock()
	delete(d.failures, ip)
	d.mu.Unlock()
}

func (d *Detector) CheckConnection(clientAddr, sni string) (allowed bool, reason string) {
	ip := extractIP(clientAddr)
	if ip == "" {
		return true, ""
	}

	d.mu.RLock()
	entry, isBlocked := d.blocked[ip]
	d.mu.RUnlock()

	if isBlocked {
		if time.Now().Before(entry.until) {
			return false, fmt.Sprintf("IP blocked until %s: %s", entry.until.Format(time.RFC3339), entry.reason)
		}
		d.mu.Lock()
		delete(d.blocked, ip)
		d.mu.Unlock()
	}

	if sni == "" {
		return true, ""
	}
	sniNorm := strings.ToLower(sni)

	if d.cfg.RequireDNSQuery {
		d.mu.RLock()
		entry, hasDNS := d.dnsLog[ip][sniNorm]
		d.mu.RUnlock()

		if !hasDNS || time.Since(entry.at) > d.cfg.DNSQueryWindow {
			d.RecordAuthFailure(clientAddr)
			return false, fmt.Sprintf("no recent DNS query for %q from %s (window=%v)", sni, ip, d.cfg.DNSQueryWindow)
		}

		if len(entry.resolvedIPs) > 0 && len(d.ownIPs) > 0 {
			overlap := false
			for _, resolved := range entry.resolvedIPs {
				if _, owned := d.ownIPs[resolved]; owned {
					overlap = true
					break
				}
			}
			if !overlap {
				d.RecordAuthFailure(clientAddr)
				return false, fmt.Sprintf(
					"DNS for %q returned %v, none match server IPs %v — possible DNS interception or direct probe",
					sni, entry.resolvedIPs, d.ownIPsList(),
				)
			}
		}
	}

	if d.cfg.CheckSNIOwnership && len(d.ownIPs) > 0 {
		resolvedIPs, err := d.resolveSNI(sniNorm)
		if err != nil {
			log.Debug("[probe] SNI resolution failed for %q: %v — allowing", sni, err)
		} else {
			overlap := false
			for _, resolved := range resolvedIPs {
				if _, owned := d.ownIPs[resolved]; owned {
					overlap = true
					break
				}
			}
			if !overlap {
				d.RecordAuthFailure(clientAddr)
				return false, fmt.Sprintf("SNI %q does not resolve to this server (got %v, own=%v)",
					sni, resolvedIPs, d.ownIPsList())
			}
		}
	}

	return true, ""
}

func (d *Detector) AddOwnIP(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	d.mu.Lock()
	d.ownIPs[ip] = struct{}{}
	d.mu.Unlock()
}

func (d *Detector) BlockIP(clientAddr, reason string) {
	ip := extractIP(clientAddr)
	if ip == "" {
		return
	}
	d.mu.Lock()
	d.blocked[ip] = blockEntry{
		until:  time.Now().Add(d.cfg.BlockDuration),
		reason: reason,
	}
	d.mu.Unlock()
	log.Info("[probe] manually blocked %s: %s", ip, reason)
}

func (d *Detector) UnblockIP(clientAddr string) {
	ip := extractIP(clientAddr)
	if ip == "" {
		ip = clientAddr
	}
	d.mu.Lock()
	delete(d.blocked, ip)
	delete(d.failures, ip)
	d.mu.Unlock()
	log.Info("[probe] unblocked %s", ip)
}

func (d *Detector) IsBlocked(clientAddr string) bool {
	ip := extractIP(clientAddr)
	if ip == "" {
		return false
	}
	d.mu.RLock()
	entry, ok := d.blocked[ip]
	d.mu.RUnlock()
	return ok && time.Now().Before(entry.until)
}

func (d *Detector) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return map[string]interface{}{
		"blocked_ips":      len(d.blocked),
		"tracked_ips":      len(d.failures),
		"dns_log_size":     len(d.dnsLog),
		"sni_cache":        len(d.sniCache),
		"own_ips":          d.ownIPsList(),
		"require_dns":      d.cfg.RequireDNSQuery,
		"check_sni_own":    d.cfg.CheckSNIOwnership,
		"escalating_bans":  d.cfg.EscalatingBans,
		"repeat_offenders": len(d.banHistory),
	}
}


func (d *Detector) resolveSNI(domain string) ([]string, error) {
	d.mu.RLock()
	cached, ok := d.sniCache[domain]
	d.mu.RUnlock()

	if ok && time.Since(cached.fetched) < d.cfg.SNICacheExpiry {
		return cached.ips, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.sniCache[domain] = sniCacheEntry{ips: addrs, fetched: time.Now()}
	d.mu.Unlock()

	return addrs, nil
}

func (d *Detector) autoDetectOwnIPs() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			d.ownIPs[ip.String()] = struct{}{}
		}
	}
	if len(d.ownIPs) > 0 {
		log.Info("[probe] auto-detected own IPs: %v", d.ownIPsList())
	}
}

func (d *Detector) ownIPsList() []string {
	out := make([]string, 0, len(d.ownIPs))
	for ip := range d.ownIPs {
		out = append(out, ip)
	}
	return out
}

func (d *Detector) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-d.cleanupStop:
			return
		case <-ticker.C:
			d.cleanup()
		}
	}
}

func (d *Detector) cleanup() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	for ip, entry := range d.blocked {
		if now.After(entry.until) {
			delete(d.blocked, ip)
		}
	}

	cutoff := now.Add(-d.cfg.FailWindow)
	for ip, ts := range d.failures {
		pruned := pruneOlderThan(ts, cutoff)
		if len(pruned) == 0 {
			delete(d.failures, ip)
		} else {
			d.failures[ip] = pruned
		}
	}

	dnsCutoff := now.Add(-d.cfg.DNSQueryWindow * 10)
	for ip, domains := range d.dnsLog {
		for domain, e := range domains {
			if e.at.Before(dnsCutoff) {
				delete(domains, domain)
			}
		}
		if len(domains) == 0 {
			delete(d.dnsLog, ip)
		}
	}

	for domain, entry := range d.sniCache {
		if now.Sub(entry.fetched) > d.cfg.SNICacheExpiry*2 {
			delete(d.sniCache, domain)
		}
	}
}

func extractIP(addr string) string {
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if net.ParseIP(addr) != nil {
			return addr
		}
		return ""
	}
	return host
}

func pruneOlderThan(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for _, t := range ts {
		if !t.Before(cutoff) {
			ts[i] = t
			i++
		}
	}
	return ts[:i]
}
