package dns

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
	"whispera/common/cache"
	"whispera/common/runtime/base"
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
	BypassFunc      func(hostname string) bool
	BypassResolver  *net.Resolver
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
	if c.CacheSize <= 0 {
		c.CacheSize = DefaultCacheSize
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = DefaultCacheTTL
	}
	return nil
}

type Resolver struct {
	*base.Module
	config     *Config
	cache      *cache.LRUCache[[]net.IP]
	upstreamMu sync.RWMutex
	dialCtx    func(ctx context.Context, network, address string) (net.Conn, error)
	dialCtxMu  sync.RWMutex

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
		cache:         cache.NewLRUCache[[]net.IP](cfg.CacheSize),
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

func NewResolver(cfg *Config) *Resolver {
	r, _ := New(cfg)
	return r
}

func (r *Resolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	if ip := net.ParseIP(domain); ip != nil {
		return []net.IP{ip}, nil
	}
	atomic.AddUint64(&r.queries, 1)
	r.UpdateActivity()
	if r.isBlocked(domain) {
		atomic.AddUint64(&r.blocked, 1)
		return nil, fmt.Errorf("domain blocked: %s", domain)
	}

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
		if ips, _ := r.cache.Get(ctx, domain); ips != nil {
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
		_ = r.cache.Set(ctx, domain, ips, r.config.CacheTTL)
	}

	return ips, nil
}

func (r *Resolver) SetDialContext(dialFn func(ctx context.Context, network, address string) (net.Conn, error)) {
	r.dialCtxMu.Lock()
	r.dialCtx = dialFn
	r.dialCtxMu.Unlock()
}

func (r *Resolver) SetUpstream(upstream string) {
	if strings.EqualFold(upstream, "system") {
		upstream = ""
	}
	r.upstreamMu.Lock()
	r.config.Upstream = upstream
	r.upstreamMu.Unlock()
	r.cache.Clear()
}

func (r *Resolver) GetUpstream() string {
	r.upstreamMu.RLock()
	defer r.upstreamMu.RUnlock()
	return r.config.Upstream
}

func (r *Resolver) isBlocked(domain string) bool {
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

func (r *Resolver) resolveUpstream(ctx context.Context, domain string) ([]net.IP, error) {
	r.dialCtxMu.RLock()
	dialFn := r.dialCtx
	r.dialCtxMu.RUnlock()

	r.upstreamMu.RLock()
	upstream := r.config.Upstream
	r.upstreamMu.RUnlock()

	if strings.HasPrefix(upstream, "https://") {
		return r.resolveDoH(ctx, upstream, domain)
	}

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

	if dialFn != nil {
		ips, err := r.resolveTCPDNS(ctx, dialFn, upstream, domain)
		if err == nil {
			return ips, nil
		}
		if ips, err2 := r.resolveDoH(ctx, dohFallbackFor(upstream), domain); err2 == nil {
			return ips, nil
		}
		return nil, err
	}

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
	ips, err := resolver.LookupIP(ctx, "ip4", domain)
	if err == nil {
		return ips, nil
	}
	return r.resolveDoH(ctx, dohFallbackFor(upstream), domain)
}

func dohFallbackFor(upstream string) string {
	host := strings.TrimSuffix(upstream, ":53")
	host = strings.Split(host, ":")[0]
	switch host {
	case "8.8.8.8", "8.8.4.4", "dns.google":
		return "https://dns.google/dns-query"
	case "9.9.9.9", "149.112.112.112":
		return "https://dns.quad9.net/dns-query"
	case "94.140.14.14", "94.140.15.15":
		return "https://dns.adguard.com/dns-query"
	default:
		return "https://1.1.1.1/dns-query"
	}
}

func (r *Resolver) resolveDoH(ctx context.Context, endpoint, domain string) ([]net.IP, error) {
	r.dialCtxMu.RLock()
	dialFn := r.dialCtx
	r.dialCtxMu.RUnlock()

	msg := buildDNSMsg(domain)

	var transport http.RoundTripper
	if dialFn != nil {
		transport = &http.Transport{
			DialContext:       dialFn,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
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

	msg := buildDNSMsg(domain)
	lenBuf := [2]byte{byte(len(msg) >> 8), byte(len(msg))}
	conn.Write(lenBuf[:])
	conn.Write(msg)

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

func buildDNSMsg(domain string) []byte {
	id := [2]byte{0x12, 0x34}
	buf := []byte{
		id[0], id[1],
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x01)
	buf = append(buf, 0x00, 0x01)
	return buf
}

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
	offset += 4

	var ips []net.IP
	for i := 0; i < ancount && offset < len(response); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rtype := int(response[offset])<<8 | int(response[offset+1])
		offset += 8
		rdlen := int(response[offset])<<8 | int(response[offset+1])
		offset += 2
		if offset+rdlen > len(response) {
			break
		}
		if rtype == 1 && rdlen == 4 {
			ip := make(net.IP, 4)
			copy(ip, response[offset:offset+4])
			ips = append(ips, ip)
		} else if rtype == 28 && rdlen == 16 {
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
