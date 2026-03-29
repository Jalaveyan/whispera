package dnsmodule

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

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

	if upstream == "" {
		return net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if dialFn != nil {
				return dialFn(ctx, network, upstream)
			}
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp4", upstream)
		},
	}

	return resolver.LookupIP(ctx, "ip4", domain)
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
	r.cacheMu.Lock()
	r.config.Upstream = upstream
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
