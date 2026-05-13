package dnsmodule

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/adblock"
	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "dns.resolver"
	ModuleVersion = "1.0.0"

	DefaultCacheSize = 10000
	DefaultCacheTTL  = 5 * time.Minute
)

type Config struct {
	Upstream        string
	FakeIPEnabled   bool
	FakeIPRange     string
	CacheEnabled    bool
	CacheSize       int
	CacheTTL        time.Duration
	BlockingEnabled bool
	BlockLists      []string
	DialContext     func(ctx context.Context, network, address string) (net.Conn, error)
	// BypassFunc, if set, is called before resolving. When it returns true the
	// domain is resolved via the OS resolver (system DNS) regardless of Upstream.
	// Use this to integrate split-tunnel hostname bypass.
	BypassFunc func(hostname string) bool

	// BypassResolver, if set, is used instead of net.DefaultResolver when
	// resolving bypass-listed domains. Set this to a resolver that always dials
	// directly (never through the VPN tunnel) so that system DNS changes after
	// VPN connects do not affect bypass-domain resolution.
	BypassResolver *net.Resolver
}

func DefaultConfig() *Config {
	return &Config{
		Upstream:        "8.8.8.8:53",
		FakeIPEnabled:   false,
		FakeIPRange:     "198.18.0.0/15",
		CacheEnabled:    true,
		CacheSize:       DefaultCacheSize,
		CacheTTL:        DefaultCacheTTL,
		BlockingEnabled: false,
	}
}

func (c *Config) Validate() error {
	_ = c.Upstream
	if c.CacheSize <= 0 {
		c.CacheSize = DefaultCacheSize
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = DefaultCacheTTL
	}
	return nil
}

type cacheEntry struct {
	IPs       []net.IP
	ExpiresAt time.Time
}

type Resolver struct {
	*base.Module
	config    *Config
	cache     map[string]*cacheEntry
	cacheMu   sync.RWMutex
	dialCtx   func(ctx context.Context, network, address string) (net.Conn, error)
	dialCtxMu sync.RWMutex

	fakeIPNet     *net.IPNet
	fakeIPNext    uint32
	fakeIPMu      sync.Mutex
	fakeIPMap     map[string]net.IP
	fakeIPReverse map[string]string

	blockList   map[string]bool
	blockListMu sync.RWMutex

	queries     uint64
	cacheHits   uint64
	cacheMisses uint64
	blocked     uint64
	errors      uint64
}

func New(cfg *Config) (*Resolver, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	r := &Resolver{
		Module:        base.NewModule(ModuleName, ModuleVersion, nil),
		config:        cfg,
		cache:         make(map[string]*cacheEntry),
		fakeIPMap:     make(map[string]net.IP),
		fakeIPReverse: make(map[string]string),
		blockList:     make(map[string]bool),
	}

	if cfg.FakeIPEnabled {
		_, ipnet, err := net.ParseCIDR(cfg.FakeIPRange)
		if err == nil {
			r.fakeIPNet = ipnet
		}
	}

	return r, nil
}

func (r *Resolver) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := r.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if dnsCfg, ok := cfg.(*Config); ok {
		r.config = dnsCfg
	}

	return nil
}

func (r *Resolver) Start() error {
	if err := r.Module.Start(); err != nil {
		return err
	}

	go r.cacheCleanupLoop()

	r.SetHealthy(true, fmt.Sprintf("DNS resolver running (upstream: %s)", r.config.Upstream))
	r.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"upstream": r.config.Upstream,
		"cache":    r.config.CacheEnabled,
		"fake_ip":  r.config.FakeIPEnabled,
	})

	return nil
}

func (r *Resolver) Stop() error {
	r.PublishEvent(events.EventTypeModuleStopped, nil)
	return r.Module.Stop()
}

func (r *Resolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	atomic.AddUint64(&r.queries, 1)
	r.UpdateActivity()
	if r.isBlocked(domain) {
		atomic.AddUint64(&r.blocked, 1)
		return nil, fmt.Errorf("domain blocked: %s", domain)
	}

	// Bypass check: domains on the split-tunnel whitelist are resolved via a
	// fixed direct resolver (BypassResolver or net.DefaultResolver) so they
	// always get their real regional IPs even after the VPN tunnel changes
	// the system DNS upstream.
	if r.config.BypassFunc != nil && r.config.BypassFunc(domain) {
		resolver := r.config.BypassResolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addrs, err := resolver.LookupIPAddr(ctx, domain)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, nil
	}

	if r.config.CacheEnabled {
		if ips := r.getFromCache(domain); ips != nil {
			atomic.AddUint64(&r.cacheHits, 1)
			return ips, nil
		}
		atomic.AddUint64(&r.cacheMisses, 1)
	}

	if r.config.FakeIPEnabled {
		ip := r.getFakeIP(domain)
		return []net.IP{ip}, nil
	}
	ips, err := r.resolveUpstream(ctx, domain)
	if err != nil {
		atomic.AddUint64(&r.errors, 1)
		return nil, err
	}

	if r.config.CacheEnabled && len(ips) > 0 {
		r.addToCache(domain, ips)
	}

	return ips, nil
}

func (r *Resolver) ResolveToString(ctx context.Context, domain string) (string, error) {
	ips, err := r.Resolve(ctx, domain)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs for domain: %s", domain)
	}
	return ips[0].String(), nil
}

func (r *Resolver) LookupFakeIP(ip net.IP) (string, bool) {
	r.fakeIPMu.Lock()
	defer r.fakeIPMu.Unlock()
	domain, ok := r.fakeIPReverse[ip.String()]
	return domain, ok
}

func (r *Resolver) AddBlockedDomain(domain string) {
	r.blockListMu.Lock()
	r.blockList[domain] = true
	r.blockListMu.Unlock()
}

func (r *Resolver) RemoveBlockedDomain(domain string) {
	r.blockListMu.Lock()
	delete(r.blockList, domain)
	r.blockListMu.Unlock()
}

func (r *Resolver) ClearCache() {
	r.cacheMu.Lock()
	r.cache = make(map[string]*cacheEntry)
	r.cacheMu.Unlock()
}

func (r *Resolver) isBlocked(domain string) bool {
	if adblock.Global.IsBlockedDNS(domain) {
		return true
	}

	if !r.config.BlockingEnabled {
		return false
	}

	r.blockListMu.RLock()
	defer r.blockListMu.RUnlock()

	if r.blockList[domain] {
		return true
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if r.blockList[domain[i+1:]] {
				return true
			}
		}
	}

	return false
}

func (r *Resolver) getFromCache(domain string) []net.IP {
	r.cacheMu.RLock()
	entry, ok := r.cache[domain]
	r.cacheMu.RUnlock()

	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}

	return entry.IPs
}

func (r *Resolver) addToCache(domain string, ips []net.IP) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if len(r.cache) >= r.config.CacheSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range r.cache {
			if oldestKey == "" || v.ExpiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.ExpiresAt
			}
		}
		delete(r.cache, oldestKey)
	}

	r.cache[domain] = &cacheEntry{
		IPs:       ips,
		ExpiresAt: time.Now().Add(r.config.CacheTTL),
	}
}

func (r *Resolver) getFakeIP(domain string) net.IP {
	r.fakeIPMu.Lock()
	defer r.fakeIPMu.Unlock()
	if ip, ok := r.fakeIPMap[domain]; ok {
		return ip
	}

	if r.fakeIPNet == nil {
		return net.ParseIP("198.18.0.1")
	}

	baseIP := r.fakeIPNet.IP.To4()
	if baseIP == nil {
		return net.ParseIP("198.18.0.1")
	}

	r.fakeIPNext++
	ip := make(net.IP, 4)
	copy(ip, baseIP)

	offset := r.fakeIPNext
	ip[3] = byte(offset)
	ip[2] = byte(offset >> 8)

	r.fakeIPMap[domain] = ip
	r.fakeIPReverse[ip.String()] = domain

	return ip
}

func (r *Resolver) SetDialContext(dialFn func(ctx context.Context, network, address string) (net.Conn, error)) {
	r.dialCtxMu.Lock()
	r.dialCtx = dialFn
	r.dialCtxMu.Unlock()
}

func (r *Resolver) resolveUpstream(ctx context.Context, domain string) ([]net.IP, error) {
	r.dialCtxMu.RLock()
	dialFn := r.dialCtx
	r.dialCtxMu.RUnlock()

	r.cacheMu.RLock()
	upstream := r.config.Upstream
	r.cacheMu.RUnlock()

	// DoH upstream: https://... → use DNS-over-HTTPS (RFC 8484).
	if strings.HasPrefix(upstream, "https://") {
		return r.resolveDoH(ctx, upstream, domain)
	}

	// Empty or "system" upstream → use OS resolver directly.
	if upstream == "" || strings.EqualFold(upstream, "system") {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, len(addrs))
		for i, a := range addrs {
			ips[i] = a.IP
		}
		return ips, nil
	}

	// When a tunnel dial function is available, we must use TCP DNS (RFC 5966)
	// because the mux stream is TCP-like. The stdlib net.Resolver issues UDP-style
	// datagrams by default (no 2-byte length prefix), which breaks over a TCP
	// stream. We send a raw TCP DNS query instead.
	if dialFn != nil {
		ips, err := r.resolveTCPDNS(ctx, dialFn, upstream, domain)
		if err == nil {
			return ips, nil
		}
		// Fallback: try direct UDP to upstream if tunnel path failed.
	}

	// Direct UDP DNS to the configured upstream.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr := upstream
			if !strings.Contains(addr, ":") {
				addr += ":53"
			}
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp4", addr)
		},
	}
	return resolver.LookupIP(ctx, "ip4", domain)
}

// resolveDoH resolves a domain via DNS-over-HTTPS (RFC 8484 wire format POST).
// If a tunnel dialFn is configured it is used as the underlying TCP dialer so
// the DoH query travels through the tunnel; otherwise a direct HTTPS connection
// is made (works when the ISP blocks port 53 but allows 443).
func (r *Resolver) resolveDoH(ctx context.Context, endpoint, domain string) ([]net.IP, error) {
	r.dialCtxMu.RLock()
	dialFn := r.dialCtx
	r.dialCtxMu.RUnlock()

	msg := buildDNSMsg(domain)

	var transport http.RoundTripper
	if dialFn != nil {
		transport = &http.Transport{
			DialContext:     dialFn,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		}
	} else {
		transport = &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		}
	}

	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(msg))
	if err != nil {
		return nil, fmt.Errorf("doh: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: server returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, fmt.Errorf("doh: read body: %w", err)
	}

	return parseDNSResponse(body)
}

// resolveTCPDNS sends a DNS A-query over a TCP-like connection obtained via
// dialFn (e.g. a tunnel mux stream). RFC 5966 TCP DNS uses a 2-byte length
// prefix before each message.
func (r *Resolver) resolveTCPDNS(ctx context.Context, dialFn func(context.Context, string, string) (net.Conn, error), upstream, domain string) ([]net.IP, error) {
	addr := upstream
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	conn, err := dialFn(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dns dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Build a minimal A-record query.
	msg := buildDNSMsg(domain)

	// TCP DNS: 2-byte big-endian length prefix.
	lenBuf := [2]byte{byte(len(msg) >> 8), byte(len(msg))}
	conn.Write(lenBuf[:])
	conn.Write(msg)

	// Read response length.
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("tcp dns read len: %w", err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen < 12 || respLen > 65535 {
		return nil, fmt.Errorf("tcp dns: invalid response length %d", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("tcp dns read body: %w", err)
	}

	return parseDNSResponse(resp)
}

// buildDNSMsg constructs a minimal DNS A-query wire message (no length prefix).
func buildDNSMsg(domain string) []byte {
	id := [2]byte{0x12, 0x34}
	buf := []byte{
		id[0], id[1], // ID
		0x01, 0x00, // Flags: standard query, recursion desired
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00)       // root label
	buf = append(buf, 0x00, 0x01) // QTYPE = A
	buf = append(buf, 0x00, 0x01) // QCLASS = IN
	return buf
}

// parseDNSResponse extracts A and AAAA records from a raw DNS wire-format response.
func parseDNSResponse(response []byte) ([]net.IP, error) {
	if len(response) < 12 {
		return nil, fmt.Errorf("dns response too short (%d bytes)", len(response))
	}
	rcode := response[3] & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("dns error rcode=%d", rcode)
	}
	ancount := int(response[6])<<8 | int(response[7])
	if ancount == 0 {
		return nil, fmt.Errorf("dns: no answers")
	}

	offset := 12
	// Skip question section.
	for offset < len(response) {
		if response[offset] == 0 {
			offset++
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset += int(response[offset]) + 1
	}
	offset += 4 // skip QTYPE + QCLASS

	var ips []net.IP
	for i := 0; i < ancount && offset < len(response); i++ {
		// Skip name (may be pointer or label sequence).
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++ // null terminator
		}
		if offset+10 > len(response) {
			break
		}
		rtype := int(response[offset])<<8 | int(response[offset+1])
		offset += 8 // type(2) + class(2) + ttl(4)
		rdlen := int(response[offset])<<8 | int(response[offset+1])
		offset += 2
		if offset+rdlen > len(response) {
			break
		}
		if rtype == 1 && rdlen == 4 { // A record
			ip := make(net.IP, 4)
			copy(ip, response[offset:offset+4])
			ips = append(ips, ip)
		} else if rtype == 28 && rdlen == 16 { // AAAA record
			ip := make(net.IP, 16)
			copy(ip, response[offset:offset+16])
			ips = append(ips, ip)
		}
		offset += rdlen
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dns: no A/AAAA records in response")
	}
	return ips, nil
}

func (r *Resolver) cacheCleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for r.IsRunning() {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			r.cleanupCache()
		}
	}
}

func (r *Resolver) cleanupCache() {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	now := time.Now()
	for key, entry := range r.cache {
		if now.After(entry.ExpiresAt) {
			delete(r.cache, key)
		}
	}
}

func (r *Resolver) SetUpstream(upstream string) {
	// Normalize "system" to empty string (use OS resolver).
	if strings.EqualFold(upstream, "system") {
		upstream = ""
	}
	r.cacheMu.Lock()
	r.config.Upstream = upstream
	// Flush cache so stale entries don't shadow the new upstream.
	r.cache = make(map[string]*cacheEntry)
	r.cacheMu.Unlock()
}

func (r *Resolver) GetUpstream() string {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return r.config.Upstream
}

func (r *Resolver) HealthCheck() interfaces.HealthStatus {
	status := r.Module.HealthCheck()

	status.Details["upstream"] = r.config.Upstream
	status.Details["queries"] = atomic.LoadUint64(&r.queries)
	status.Details["cache_hits"] = atomic.LoadUint64(&r.cacheHits)
	status.Details["cache_misses"] = atomic.LoadUint64(&r.cacheMisses)
	status.Details["blocked"] = atomic.LoadUint64(&r.blocked)
	status.Details["errors"] = atomic.LoadUint64(&r.errors)

	r.cacheMu.RLock()
	status.Details["cache_size"] = len(r.cache)
	r.cacheMu.RUnlock()

	r.fakeIPMu.Lock()
	status.Details["fake_ip_count"] = len(r.fakeIPMap)
	r.fakeIPMu.Unlock()

	r.blockListMu.RLock()
	status.Details["block_list_size"] = len(r.blockList)
	r.blockListMu.RUnlock()

	return status
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
