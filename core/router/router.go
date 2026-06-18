package router

import (
	"container/list"
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"whispera/common/routing"
	"whispera/common/runtime/base"
	"whispera/common/runtime/events"
	"whispera/common/runtime/interfaces"
	"whispera/common/runtime/registry"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "routing.engine"
	ModuleVersion = "1.0.0"
)

type Config struct {
	DefaultDestination interfaces.Destination
	MaxRules           int
	EnableCache        bool
	CacheSize          int
}

func DefaultConfig() *Config {
	return &Config{
		DefaultDestination: interfaces.Destination{
			Type: interfaces.DestinationDirect,
		},
		MaxRules:    1000,
		EnableCache: true,
		CacheSize:   10000,
	}
}

func (c *Config) Validate() error {
	if c.MaxRules <= 0 {
		c.MaxRules = 1000
	}
	if c.CacheSize <= 0 {
		c.CacheSize = 10000
	}
	return nil
}

type lruEntry struct {
	key   string
	value *interfaces.Destination
	elem  *list.Element
}

type lruCache struct {
	mu    sync.RWMutex
	items map[string]*lruEntry
	list  *list.List
	max   int
}

func newLRUCache(maxSize int) *lruCache {
	return &lruCache{
		items: make(map[string]*lruEntry, maxSize),
		list:  list.New(),
		max:   maxSize,
	}
}

func (c *lruCache) Get(key string) (*interfaces.Destination, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		c.list.MoveToFront(entry.elem)
		return entry.value, true
	}
	return nil, false
}

func (c *lruCache) Put(key string, value *interfaces.Destination) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		entry.value = value
		c.list.MoveToFront(entry.elem)
		return
	}

	if c.list.Len() >= c.max {
		if oldest := c.list.Back(); oldest != nil {
			c.list.Remove(oldest)
			if e, ok := oldest.Value.(*lruEntry); ok {
				delete(c.items, e.key)
			}
		}
	}

	entry := &lruEntry{key: key, value: value}
	entry.elem = c.list.PushFront(entry)
	c.items[key] = entry
}

func (c *lruCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*lruEntry, c.max)
	c.list.Init()
}

func (c *lruCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.list.Len()
}

type Engine struct {
	*base.Module
	config *Config

	mu    sync.RWMutex
	rules []interfaces.RoutingRule
	byID  map[string]*interfaces.RoutingRule

	cache *lruCache

	routeHits   uint64
	routeMisses uint64
	cacheHits   uint64
	cacheMisses uint64

	geoMu  sync.RWMutex
	geoRtr *routing.Router
}

func New(cfg *Config) (*Engine, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	e := &Engine{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		rules:  make([]interfaces.RoutingRule, 0),
		byID:   make(map[string]*interfaces.RoutingRule),
		cache:  newLRUCache(cfg.CacheSize),
	}

	return e, nil
}

func (e *Engine) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := e.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if routerCfg, ok := cfg.(*Config); ok {
		e.config = routerCfg
	}

	return nil
}

func (e *Engine) Start() error {
	if err := e.Module.Start(); err != nil {
		return err
	}

	e.SetHealthy(true, "router running")
	e.PublishEvent(events.EventTypeModuleStarted, nil)
	return nil
}

func (e *Engine) Stop() error {
	e.PublishEvent(events.EventTypeModuleStopped, nil)
	return e.Module.Stop()
}

func (e *Engine) Route(ctx context.Context, packet *interfaces.Packet) (*interfaces.Destination, error) {
	e.UpdateActivity()

	if e.config.EnableCache {
		if dest := e.checkCache(packet); dest != nil {
			atomic.AddUint64(&e.cacheHits, 1)
			atomic.AddUint64(&e.routeHits, 1)
			return dest, nil
		}
		atomic.AddUint64(&e.cacheMisses, 1)
	}

	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	for _, rule := range rules {
		if e.matchRule(&rule, packet) {
			atomic.AddUint64(&e.routeHits, 1)
			dest := &rule.Destination

			if e.config.EnableCache {
				e.updateCache(packet, dest)
			}

			return dest, nil
		}
	}

	atomic.AddUint64(&e.routeMisses, 1)
	return &e.config.DefaultDestination, nil
}

func (e *Engine) matchRule(rule *interfaces.RoutingRule, packet *interfaces.Packet) bool {
	for _, cond := range rule.Conditions {
		if !e.matchCondition(&cond, packet) {
			return false
		}
	}
	return true
}

func (e *Engine) matchCondition(cond *interfaces.RuleCondition, packet *interfaces.Packet) bool {
	switch cond.Field {
	case "dst_ip":
		return e.matchIP(packet.DstAddr, cond)
	case "src_ip":
		return e.matchIP(packet.SrcAddr, cond)
	case "dst_port":
		return e.matchPort(packet.DstAddr, cond)
	case "src_port":
		return e.matchPort(packet.SrcAddr, cond)
	case "domain":
		return e.matchDomain(cond)
	case "protocol":
		return e.matchProtocol(packet, cond)
	case "session_id":
		return e.matchSessionID(packet, cond)
	default:
		return false
	}
}

func (e *Engine) matchIP(addr net.Addr, cond *interfaces.RuleCondition) bool {
	if addr == nil {
		return false
	}

	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	default:
		return false
	}

	switch cond.Operator {
	case "eq":
		if s, ok := cond.Value.(string); ok {
			return ip.String() == s
		}
	case "cidr":
		if s, ok := cond.Value.(string); ok {
			_, cidr, err := net.ParseCIDR(s)
			if err != nil {
				return false
			}
			return cidr.Contains(ip)
		}
	case "in":
		if list, ok := cond.Value.([]string); ok {
			for _, v := range list {
				if ip.String() == v {
					return true
				}
			}
		}
	}

	return false
}

func (e *Engine) matchPort(addr net.Addr, cond *interfaces.RuleCondition) bool {
	if addr == nil {
		return false
	}

	var port int
	switch a := addr.(type) {
	case *net.UDPAddr:
		port = a.Port
	case *net.TCPAddr:
		port = a.Port
	default:
		return false
	}

	switch cond.Operator {
	case "eq":
		if v, ok := cond.Value.(int); ok {
			return port == v
		}
	case "in":
		if list, ok := cond.Value.([]int); ok {
			for _, v := range list {
				if port == v {
					return true
				}
			}
		}
	case "range":
		if r, ok := cond.Value.([]int); ok && len(r) == 2 {
			return port >= r[0] && port <= r[1]
		}
	}

	return false
}

func (e *Engine) matchDomain(cond *interfaces.RuleCondition) bool {
	domain, ok := cond.Value.(string)
	if !ok {
		return false
	}

	switch cond.Operator {
	case "eq":
		return false
	case "contains":
		return false
	case "suffix":
		return false
	case "regex":
		return false
	}

	_ = domain
	return false
}

func (e *Engine) matchProtocol(_ *interfaces.Packet, _ *interfaces.RuleCondition) bool {
	return false
}

func (e *Engine) matchSessionID(packet *interfaces.Packet, cond *interfaces.RuleCondition) bool {
	switch cond.Operator {
	case "eq":
		if v, ok := cond.Value.(uint32); ok {
			return packet.SessionID == v
		}
	case "in":
		if list, ok := cond.Value.([]uint32); ok {
			for _, v := range list {
				if packet.SessionID == v {
					return true
				}
			}
		}
	}
	return false
}

func (e *Engine) checkCache(packet *interfaces.Packet) *interfaces.Destination {
	if packet.DstAddr != nil {
		if dest, ok := e.cache.Get(packet.DstAddr.String()); ok {
			return dest
		}
	}
	return nil
}

func (e *Engine) updateCache(packet *interfaces.Packet, dest *interfaces.Destination) {
	if packet.DstAddr != nil {
		e.cache.Put(packet.DstAddr.String(), dest)
	}
}

func (e *Engine) AddRule(rule interfaces.RoutingRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.byID[rule.ID]; exists {
		return fmt.Errorf("rule %s already exists", rule.ID)
	}

	if len(e.rules) >= e.config.MaxRules {
		return fmt.Errorf("max rules reached (%d)", e.config.MaxRules)
	}

	e.rules = append(e.rules, rule)
	e.byID[rule.ID] = &e.rules[len(e.rules)-1]

	sort.Slice(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})

	e.byID = make(map[string]*interfaces.RoutingRule)
	for i := range e.rules {
		e.byID[e.rules[i].ID] = &e.rules[i]
	}

	e.clearCache()

	e.UpdateActivity()
	return nil
}

func (e *Engine) RemoveRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.byID[id]; !exists {
		return fmt.Errorf("rule %s not found", id)
	}

	newRules := make([]interfaces.RoutingRule, 0, len(e.rules)-1)
	for _, r := range e.rules {
		if r.ID != id {
			newRules = append(newRules, r)
		}
	}
	e.rules = newRules

	delete(e.byID, id)

	e.clearCache()

	e.UpdateActivity()
	return nil
}

func (e *Engine) UpdateRules(rules []interfaces.RoutingRule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	seen := make(map[string]bool)
	for _, r := range rules {
		if r.ID == "" {
			return fmt.Errorf("rule ID is required")
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule ID: %s", r.ID)
		}
		seen[r.ID] = true
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	e.rules = rules
	e.byID = make(map[string]*interfaces.RoutingRule)
	for i := range e.rules {
		e.byID[e.rules[i].ID] = &e.rules[i]
	}

	e.clearCache()

	e.UpdateActivity()
	return nil
}

func (e *Engine) GetRules() []interfaces.RoutingRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]interfaces.RoutingRule, len(e.rules))
	copy(rules, e.rules)
	return rules
}

func (e *Engine) GetRule(id string) (*interfaces.RoutingRule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rule, exists := e.byID[id]
	if !exists {
		return nil, false
	}
	return rule, true
}

func (e *Engine) clearCache() {
	e.cache.Clear()
}

func (e *Engine) CacheDomain(domain string, dest *interfaces.Destination) {
	domain = strings.ToLower(domain)
	e.cache.Put("domain:"+domain, dest)
}

func (e *Engine) LookupDomain(domain string) (*interfaces.Destination, bool) {
	domain = strings.ToLower(domain)
	return e.cache.Get("domain:" + domain)
}

func (e *Engine) HealthCheck() interfaces.HealthStatus {
	status := e.Module.HealthCheck()

	e.mu.RLock()
	ruleCount := len(e.rules)
	e.mu.RUnlock()

	cacheSize := e.cache.Len()

	status.Details["rule_count"] = ruleCount
	status.Details["cache_size"] = cacheSize
	status.Details["route_hits"] = atomic.LoadUint64(&e.routeHits)
	status.Details["route_misses"] = atomic.LoadUint64(&e.routeMisses)
	status.Details["cache_hits"] = atomic.LoadUint64(&e.cacheHits)
	status.Details["cache_misses"] = atomic.LoadUint64(&e.cacheMisses)

	return status
}

type Stats struct {
	RuleCount       int
	IPCacheSize     int
	DomainCacheSize int
	RouteHits       uint64
	RouteMisses     uint64
	CacheHits       uint64
	CacheMisses     uint64
}

func (e *Engine) GetStats() Stats {
	e.mu.RLock()
	ruleCount := len(e.rules)
	e.mu.RUnlock()

	cacheSize := e.cache.Len()

	return Stats{
		RuleCount:       ruleCount,
		IPCacheSize:     cacheSize,
		DomainCacheSize: cacheSize,
		RouteHits:       atomic.LoadUint64(&e.routeHits),
		RouteMisses:     atomic.LoadUint64(&e.routeMisses),
		CacheHits:       atomic.LoadUint64(&e.cacheHits),
		CacheMisses:     atomic.LoadUint64(&e.cacheMisses),
	}
}

func (e *Engine) LoadGeoIPFile(path string) error {
	e.geoMu.Lock()
	defer e.geoMu.Unlock()
	if e.geoRtr == nil {
		e.geoRtr = routing.NewRouter()
	}
	return e.geoRtr.LoadGeoIPFile(path)
}

func (e *Engine) LoadGeoSiteFile(path string) error {
	e.geoMu.Lock()
	defer e.geoMu.Unlock()
	if e.geoRtr == nil {
		e.geoRtr = routing.NewRouter()
	}
	return e.geoRtr.LoadGeoSiteFile(path)
}

func (e *Engine) LoadGeoData(dir string) error {
	e.geoMu.Lock()
	defer e.geoMu.Unlock()
	if e.geoRtr == nil {
		e.geoRtr = routing.NewRouter()
	}
	return e.geoRtr.LoadGeoData(dir)
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
