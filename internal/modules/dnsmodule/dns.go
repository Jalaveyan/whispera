// Package dnsmodule provides DNS resolution module for VPN
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

// Config holds DNS resolver configuration
type Config struct {
	Upstream        string        // Upstream DNS server
	FakeIPEnabled   bool          // Enable Fake-IP
	FakeIPRange     string        // Fake-IP range (e.g., "198.18.0.0/15")
	CacheEnabled    bool          // Enable DNS cache
	CacheSize       int           // Cache size
	CacheTTL        time.Duration // Cache TTL
	BlockingEnabled bool          // Enable DNS blocking
	BlockLists      []string      // Block list URLs
}

// DefaultConfig returns default DNS configuration
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

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Upstream == "" {
		c.Upstream = "8.8.8.8:53"
	}
	if c.CacheSize <= 0 {
		c.CacheSize = DefaultCacheSize
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = DefaultCacheTTL
	}
	return nil
}

// cacheEntry represents a DNS cache entry
type cacheEntry struct {
	IPs       []net.IP
	ExpiresAt time.Time
}

// Resolver implements DNS resolution for VPN
type Resolver struct {
	*base.Module
	config *Config

	// DNS cache
	cache   map[string]*cacheEntry
	cacheMu sync.RWMutex

	// Fake-IP pool
	fakeIPNet     *net.IPNet
	fakeIPNext    uint32
	fakeIPMu      sync.Mutex
	fakeIPMap     map[string]net.IP // domain -> fake IP
	fakeIPReverse map[string]string // fake IP -> domain

	// Block list
	blockList   map[string]bool
	blockListMu sync.RWMutex

	// Stats
	queries     uint64
	cacheHits   uint64
	cacheMisses uint64
	blocked     uint64
	errors      uint64
}

// New creates a new DNS resolver
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

	// Parse Fake-IP range
	if cfg.FakeIPEnabled {
		_, ipnet, err := net.ParseCIDR(cfg.FakeIPRange)
		if err == nil {
			r.fakeIPNet = ipnet
		}
	}

	return r, nil
}

// Init initializes the DNS resolver
func (r *Resolver) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := r.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if dnsCfg, ok := cfg.(*Config); ok {
		r.config = dnsCfg
	}

	return nil
}

// Start starts the DNS resolver
func (r *Resolver) Start() error {
	if err := r.Module.Start(); err != nil {
		return err
	}

	// Start cache cleanup
	go r.cacheCleanupLoop()

	r.SetHealthy(true, fmt.Sprintf("DNS resolver running (upstream: %s)", r.config.Upstream))
	r.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"upstream": r.config.Upstream,
		"cache":    r.config.CacheEnabled,
		"fake_ip":  r.config.FakeIPEnabled,
	})

	return nil
}

// Stop stops the DNS resolver
func (r *Resolver) Stop() error {
	r.PublishEvent(events.EventTypeModuleStopped, nil)
	return r.Module.Stop()
}

// Resolve resolves a domain name to IP addresses
func (r *Resolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	atomic.AddUint64(&r.queries, 1)
	r.UpdateActivity()

	// Check block list
	if r.isBlocked(domain) {
		atomic.AddUint64(&r.blocked, 1)
		return nil, fmt.Errorf("domain blocked: %s", domain)
	}

	// Check cache
	if r.config.CacheEnabled {
		if ips := r.getFromCache(domain); ips != nil {
			atomic.AddUint64(&r.cacheHits, 1)
			return ips, nil
		}
		atomic.AddUint64(&r.cacheMisses, 1)
	}

	// Fake-IP mode
	if r.config.FakeIPEnabled {
		ip := r.getFakeIP(domain)
		return []net.IP{ip}, nil
	}

	// Real DNS resolution
	ips, err := r.resolveUpstream(ctx, domain)
	if err != nil {
		atomic.AddUint64(&r.errors, 1)
		return nil, err
	}

	// Cache result
	if r.config.CacheEnabled && len(ips) > 0 {
		r.addToCache(domain, ips)
	}

	return ips, nil
}

// ResolveToString resolves a domain to a string IP
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

// LookupFakeIP returns the domain for a fake IP
func (r *Resolver) LookupFakeIP(ip net.IP) (string, bool) {
	r.fakeIPMu.Lock()
	defer r.fakeIPMu.Unlock()
	domain, ok := r.fakeIPReverse[ip.String()]
	return domain, ok
}

// AddBlockedDomain adds a domain to the block list
func (r *Resolver) AddBlockedDomain(domain string) {
	r.blockListMu.Lock()
	r.blockList[domain] = true
	r.blockListMu.Unlock()
}

// RemoveBlockedDomain removes a domain from the block list
func (r *Resolver) RemoveBlockedDomain(domain string) {
	r.blockListMu.Lock()
	delete(r.blockList, domain)
	r.blockListMu.Unlock()
}

// ClearCache clears the DNS cache
func (r *Resolver) ClearCache() {
	r.cacheMu.Lock()
	r.cache = make(map[string]*cacheEntry)
	r.cacheMu.Unlock()
}

// isBlocked checks if a domain is blocked
func (r *Resolver) isBlocked(domain string) bool {
	if !r.config.BlockingEnabled {
		return false
	}

	r.blockListMu.RLock()
	defer r.blockListMu.RUnlock()

	// Check exact match
	if r.blockList[domain] {
		return true
	}

	// Check parent domains
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if r.blockList[domain[i+1:]] {
				return true
			}
		}
	}

	return false
}

// getFromCache retrieves IPs from cache
func (r *Resolver) getFromCache(domain string) []net.IP {
	r.cacheMu.RLock()
	entry, ok := r.cache[domain]
	r.cacheMu.RUnlock()

	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}

	return entry.IPs
}

// addToCache adds IPs to cache
func (r *Resolver) addToCache(domain string, ips []net.IP) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	// Evict old entries if cache is full
	if len(r.cache) >= r.config.CacheSize {
		// Simple eviction: remove oldest entry
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

// getFakeIP returns or creates a fake IP for a domain
func (r *Resolver) getFakeIP(domain string) net.IP {
	r.fakeIPMu.Lock()
	defer r.fakeIPMu.Unlock()

	// Check existing mapping
	if ip, ok := r.fakeIPMap[domain]; ok {
		return ip
	}

	// Generate new fake IP
	if r.fakeIPNet == nil {
		return net.ParseIP("198.18.0.1")
	}

	baseIP := r.fakeIPNet.IP.To4()
	if baseIP == nil {
		return net.ParseIP("198.18.0.1")
	}

	// Increment and create new IP
	r.fakeIPNext++
	ip := make(net.IP, 4)
	copy(ip, baseIP)

	// Add offset
	offset := r.fakeIPNext
	ip[3] = byte(offset)
	ip[2] = byte(offset >> 8)

	// Store mappings
	r.fakeIPMap[domain] = ip
	r.fakeIPReverse[ip.String()] = domain

	return ip
}

// resolveUpstream resolves a domain using upstream DNS
func (r *Resolver) resolveUpstream(ctx context.Context, domain string) ([]net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			return d.DialContext(ctx, "udp4", r.config.Upstream)
		},
	}

	return resolver.LookupIP(ctx, "ip4", domain)
}

// cacheCleanupLoop periodically cleans expired cache entries
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

// cleanupCache removes expired cache entries
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

// HealthCheck returns health status
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

// Factory creates DNS resolver modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
