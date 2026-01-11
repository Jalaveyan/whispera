// Package balancer implements advanced load balancing with latency-based routing
// and weighted distribution for multi-server setups
package balancer

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("balancer")

const (
	ModuleName    = "routing.balancer"
	ModuleVersion = "1.0.0"

	// Health check defaults
	defaultHealthCheckInterval = 30 * time.Second
	defaultHealthCheckTimeout  = 5 * time.Second
	defaultUnhealthyThreshold  = 3
	defaultHealthyThreshold    = 2
)

// Strategy defines the load balancing strategy
type Strategy string

const (
	StrategyRoundRobin Strategy = "round_robin"
	StrategyRandom     Strategy = "random"
	StrategyWeighted   Strategy = "weighted"
	StrategyLatency    Strategy = "latency"
	StrategyLeastConn  Strategy = "least_conn"
	StrategyIPHash     Strategy = "ip_hash"
	StrategyFailover   Strategy = "failover"
)

// ServerState represents the health state of a server
type ServerState int

const (
	StateUnknown   ServerState = 0
	StateHealthy   ServerState = 1
	StateUnhealthy ServerState = 2
	StateDraining  ServerState = 3
)

// Server represents a backend server
type Server struct {
	// Configuration
	Address  string
	Weight   int
	Priority int
	Tags     map[string]string

	// State
	state ServerState
	mu    sync.RWMutex

	// Metrics
	latency    time.Duration
	latencies  []time.Duration
	activeConn int32
	totalConn  uint64
	failures   uint32
	successes  uint32

	// Health check
	lastCheck   time.Time
	lastSuccess time.Time
	lastFailure time.Time
}

// NewServer creates a new server
func NewServer(address string, weight int) *Server {
	if weight <= 0 {
		weight = 1
	}
	return &Server{
		Address:   address,
		Weight:    weight,
		state:     StateUnknown,
		latencies: make([]time.Duration, 0, 100),
		Tags:      make(map[string]string),
	}
}

// GetState returns the server state
func (s *Server) GetState() ServerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// SetState sets the server state
func (s *Server) SetState(state ServerState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// GetLatency returns the average latency
func (s *Server) GetLatency() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latency
}

// AddLatencySample adds a latency measurement
func (s *Server) AddLatencySample(latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.latencies = append(s.latencies, latency)
	if len(s.latencies) > 100 {
		s.latencies = s.latencies[1:]
	}

	// Calculate exponential moving average
	if len(s.latencies) == 1 {
		s.latency = latency
	} else {
		// EMA with alpha = 0.2
		s.latency = time.Duration(float64(s.latency)*0.8 + float64(latency)*0.2)
	}
}

// RecordSuccess records a successful request
func (s *Server) RecordSuccess() {
	atomic.AddUint32(&s.successes, 1)
	atomic.StoreUint32(&s.failures, 0)
	s.mu.Lock()
	s.lastSuccess = time.Now()
	s.mu.Unlock()
}

// RecordFailure records a failed request
func (s *Server) RecordFailure() {
	atomic.AddUint32(&s.failures, 1)
	s.mu.Lock()
	s.lastFailure = time.Now()
	s.mu.Unlock()
}

// Config holds balancer configuration
type Config struct {
	// Strategy for load balancing
	Strategy Strategy

	// Servers list
	Servers []*Server

	// Health check settings
	HealthCheckEnabled  bool
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
	HealthCheckPath     string
	UnhealthyThreshold  int
	HealthyThreshold    int

	// Latency settings
	LatencyWindowSize int
	LatencyThreshold  time.Duration

	// Failover settings
	FailoverOnError bool
	MaxRetries      int

	// Session affinity
	StickySession  bool
	SessionTimeout time.Duration
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Strategy:            StrategyLatency,
		HealthCheckEnabled:  true,
		HealthCheckInterval: defaultHealthCheckInterval,
		HealthCheckTimeout:  defaultHealthCheckTimeout,
		UnhealthyThreshold:  defaultUnhealthyThreshold,
		HealthyThreshold:    defaultHealthyThreshold,
		LatencyWindowSize:   100,
		LatencyThreshold:    500 * time.Millisecond,
		FailoverOnError:     true,
		MaxRetries:          3,
		StickySession:       false,
		SessionTimeout:      5 * time.Minute,
	}
}

// Balancer implements load balancing
type Balancer struct {
	*base.Module
	config *Config

	mu      sync.RWMutex
	servers []*Server

	// Round-robin state
	rrIndex uint64

	// Session affinity
	sessions sync.Map // clientIP -> serverAddress

	// Weighted selection
	weightedServers []string
	totalWeight     int

	// Health checking
	healthChecker *HealthChecker
	stopCh        chan struct{}
}

// New creates a new balancer
func New(cfg *Config) (*Balancer, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	b := &Balancer{
		Module:  base.NewModule(ModuleName, ModuleVersion, nil),
		config:  cfg,
		servers: cfg.Servers,
		stopCh:  make(chan struct{}),
	}

	// Build weighted server list
	b.rebuildWeightedList()

	// Create health checker
	if cfg.HealthCheckEnabled {
		b.healthChecker = NewHealthChecker(b, cfg)
	}

	return b, nil
}

// rebuildWeightedList rebuilds the weighted server selection list
func (b *Balancer) rebuildWeightedList() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.weightedServers = nil
	b.totalWeight = 0

	for _, s := range b.servers {
		if s.GetState() != StateUnhealthy {
			for i := 0; i < s.Weight; i++ {
				b.weightedServers = append(b.weightedServers, s.Address)
			}
			b.totalWeight += s.Weight
		}
	}
}

// Select selects a server based on the configured strategy
func (b *Balancer) Select(ctx context.Context, clientIP string) (*Server, error) {
	b.mu.RLock()
	servers := b.servers
	b.mu.RUnlock()

	// Filter healthy servers
	healthy := make([]*Server, 0, len(servers))
	for _, s := range servers {
		if s.GetState() != StateUnhealthy {
			healthy = append(healthy, s)
		}
	}

	if len(healthy) == 0 {
		return nil, fmt.Errorf("no healthy servers available")
	}

	// Check sticky session
	if b.config.StickySession {
		if addr, ok := b.sessions.Load(clientIP); ok {
			for _, s := range healthy {
				if s.Address == addr.(string) {
					return s, nil
				}
			}
		}
	}

	var selected *Server

	switch b.config.Strategy {
	case StrategyRoundRobin:
		selected = b.selectRoundRobin(healthy)
	case StrategyRandom:
		selected = b.selectRandom(healthy)
	case StrategyWeighted:
		selected = b.selectWeighted(healthy)
	case StrategyLatency:
		selected = b.selectLatency(healthy)
	case StrategyLeastConn:
		selected = b.selectLeastConn(healthy)
	case StrategyIPHash:
		selected = b.selectIPHash(healthy, clientIP)
	case StrategyFailover:
		selected = b.selectFailover(healthy)
	default:
		selected = b.selectRoundRobin(healthy)
	}

	if selected == nil {
		return nil, fmt.Errorf("failed to select server")
	}

	// Store session
	if b.config.StickySession {
		b.sessions.Store(clientIP, selected.Address)
		// Expire session after timeout
		go func() {
			time.Sleep(b.config.SessionTimeout)
			b.sessions.Delete(clientIP)
		}()
	}

	return selected, nil
}

// selectRoundRobin selects using round-robin
func (b *Balancer) selectRoundRobin(servers []*Server) *Server {
	idx := atomic.AddUint64(&b.rrIndex, 1) - 1
	return servers[idx%uint64(len(servers))]
}

// selectRandom selects randomly
func (b *Balancer) selectRandom(servers []*Server) *Server {
	return servers[rand.Intn(len(servers))]
}

// selectWeighted selects based on weights
func (b *Balancer) selectWeighted(servers []*Server) *Server {
	// Calculate total weight of healthy servers
	totalWeight := 0
	for _, s := range servers {
		totalWeight += s.Weight
	}

	if totalWeight == 0 {
		return servers[0]
	}

	// Random weighted selection
	r := rand.Intn(totalWeight)
	for _, s := range servers {
		r -= s.Weight
		if r < 0 {
			return s
		}
	}

	return servers[0]
}

// selectLatency selects based on lowest latency
func (b *Balancer) selectLatency(servers []*Server) *Server {
	// Sort by latency
	sorted := make([]*Server, len(servers))
	copy(sorted, servers)
	sort.Slice(sorted, func(i, j int) bool {
		li := sorted[i].GetLatency()
		lj := sorted[j].GetLatency()
		// Prefer servers with measured latency
		if li == 0 && lj > 0 {
			return false
		}
		if lj == 0 && li > 0 {
			return true
		}
		return li < lj
	})

	// Add some randomness among similar latency servers
	// to avoid thundering herd
	threshold := b.config.LatencyThreshold / 10
	candidates := make([]*Server, 0)
	best := sorted[0].GetLatency()

	for _, s := range sorted {
		l := s.GetLatency()
		if l == 0 || l <= best+threshold {
			candidates = append(candidates, s)
		}
	}

	if len(candidates) == 0 {
		return sorted[0]
	}

	return candidates[rand.Intn(len(candidates))]
}

// selectLeastConn selects based on least active connections
func (b *Balancer) selectLeastConn(servers []*Server) *Server {
	var selected *Server
	minConn := int32(1<<31 - 1)

	for _, s := range servers {
		conn := atomic.LoadInt32(&s.activeConn)
		// Weight-adjusted connection count
		adjusted := conn * 100 / int32(s.Weight)
		if adjusted < minConn {
			minConn = adjusted
			selected = s
		}
	}

	if selected == nil {
		return servers[0]
	}

	return selected
}

// selectIPHash selects based on client IP hash
func (b *Balancer) selectIPHash(servers []*Server, clientIP string) *Server {
	// Simple hash function
	hash := uint32(0)
	for _, c := range clientIP {
		hash = hash*31 + uint32(c)
	}
	return servers[hash%uint32(len(servers))]
}

// selectFailover selects first healthy server by priority
func (b *Balancer) selectFailover(servers []*Server) *Server {
	// Sort by priority
	sorted := make([]*Server, len(servers))
	copy(sorted, servers)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	return sorted[0]
}

// Dial connects to a selected server
func (b *Balancer) Dial(ctx context.Context, clientIP string) (net.Conn, *Server, error) {
	var lastErr error

	for retry := 0; retry <= b.config.MaxRetries; retry++ {
		server, err := b.Select(ctx, clientIP)
		if err != nil {
			return nil, nil, err
		}

		// Track connection
		atomic.AddInt32(&server.activeConn, 1)
		atomic.AddUint64(&server.totalConn, 1)

		// Measure connection time
		start := time.Now()

		conn, err := net.DialTimeout("tcp", server.Address, b.config.HealthCheckTimeout)
		if err != nil {
			atomic.AddInt32(&server.activeConn, -1)
			server.RecordFailure()

			// Check if should mark unhealthy
			if atomic.LoadUint32(&server.failures) >= uint32(b.config.UnhealthyThreshold) {
				server.SetState(StateUnhealthy)
				log.Warn("Server %s marked unhealthy", server.Address)
			}

			lastErr = err

			if b.config.FailoverOnError {
				continue
			}
			return nil, nil, err
		}

		// Record success
		latency := time.Since(start)
		server.AddLatencySample(latency)
		server.RecordSuccess()

		// Wrap connection to track close
		return &trackedConn{
			Conn:   conn,
			server: server,
		}, server, nil
	}

	return nil, nil, fmt.Errorf("all retries failed: %w", lastErr)
}

// trackedConn wraps a connection to track stats
type trackedConn struct {
	net.Conn
	server *Server
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		atomic.AddInt32(&c.server.activeConn, -1)
	}
	return c.Conn.Close()
}

// AddServer adds a server to the pool
func (b *Balancer) AddServer(server *Server) {
	b.mu.Lock()
	b.servers = append(b.servers, server)
	b.mu.Unlock()
	b.rebuildWeightedList()
}

// RemoveServer removes a server from the pool
func (b *Balancer) RemoveServer(address string) {
	b.mu.Lock()
	for i, s := range b.servers {
		if s.Address == address {
			b.servers = append(b.servers[:i], b.servers[i+1:]...)
			break
		}
	}
	b.mu.Unlock()
	b.rebuildWeightedList()
}

// GetServers returns all servers
func (b *Balancer) GetServers() []*Server {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]*Server, len(b.servers))
	copy(result, b.servers)
	return result
}

// HealthChecker performs health checks on servers
type HealthChecker struct {
	balancer *Balancer
	config   *Config
	stopCh   chan struct{}
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(b *Balancer, cfg *Config) *HealthChecker {
	return &HealthChecker{
		balancer: b,
		config:   cfg,
		stopCh:   make(chan struct{}),
	}
}

// Start starts the health checker
func (h *HealthChecker) Start() {
	go h.run()
}

// Stop stops the health checker
func (h *HealthChecker) Stop() {
	close(h.stopCh)
}

// run executes health checks periodically
func (h *HealthChecker) run() {
	ticker := time.NewTicker(h.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.checkAll()
		}
	}
}

// checkAll checks all servers
func (h *HealthChecker) checkAll() {
	servers := h.balancer.GetServers()

	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			h.check(s)
		}(server)
	}
	wg.Wait()

	// Rebuild weighted list after health check
	h.balancer.rebuildWeightedList()
}

// check performs a health check on a single server
func (h *HealthChecker) check(server *Server) {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", server.Address, h.config.HealthCheckTimeout)
	if err != nil {
		server.RecordFailure()

		failures := atomic.LoadUint32(&server.failures)
		if failures >= uint32(h.config.UnhealthyThreshold) {
			if server.GetState() != StateUnhealthy {
				server.SetState(StateUnhealthy)
				log.Warn("Server %s marked unhealthy after %d failures", server.Address, failures)
			}
		}
		return
	}
	conn.Close()

	// Record latency
	latency := time.Since(start)
	server.AddLatencySample(latency)
	server.RecordSuccess()

	// Check if server should become healthy again
	successes := atomic.LoadUint32(&server.successes)
	if successes >= uint32(h.config.HealthyThreshold) {
		if server.GetState() != StateHealthy {
			server.SetState(StateHealthy)
			log.Info("Server %s marked healthy (latency: %v)", server.Address, latency)
		}
	}

	server.mu.Lock()
	server.lastCheck = time.Now()
	server.mu.Unlock()
}

// Interface implementations

func (b *Balancer) Init(ctx context.Context) error {
	return nil
}

func (b *Balancer) Start(ctx context.Context) error {
	if b.healthChecker != nil {
		b.healthChecker.Start()
	}
	return nil
}

func (b *Balancer) Stop(ctx context.Context) error {
	close(b.stopCh)
	if b.healthChecker != nil {
		b.healthChecker.Stop()
	}
	return nil
}

func (b *Balancer) Stats() map[string]interface{} {
	servers := b.GetServers()

	serverStats := make([]map[string]interface{}, len(servers))
	for i, s := range servers {
		serverStats[i] = map[string]interface{}{
			"address":     s.Address,
			"state":       s.GetState(),
			"weight":      s.Weight,
			"latency_ms":  s.GetLatency().Milliseconds(),
			"active_conn": atomic.LoadInt32(&s.activeConn),
			"total_conn":  atomic.LoadUint64(&s.totalConn),
			"failures":    atomic.LoadUint32(&s.failures),
		}
	}

	return map[string]interface{}{
		"strategy": string(b.config.Strategy),
		"servers":  serverStats,
	}
}
