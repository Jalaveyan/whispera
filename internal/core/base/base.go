package base

import (
	"context"
	"io"
	"log"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

type Module struct {
	mu           sync.RWMutex
	name         string
	version      string
	deps         []string
	ctx          context.Context
	cancel       context.CancelFunc
	running      bool
	healthy      bool
	healthMsg    string
	eventBus     events.EventBus
	lastActivity time.Time
}

func NewModule(name, version string, deps []string) *Module {
	return &Module{
		name:         name,
		version:      version,
		deps:         deps,
		healthy:      true,
		healthMsg:    "initialized",
		lastActivity: time.Now(),
	}
}

func (m *Module) Name() string {
	return m.name
}

func (m *Module) Version() string {
	return m.version
}
func (m *Module) Dependencies() []string {
	return m.deps
}

func (m *Module) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ctx, m.cancel = context.WithCancel(ctx)
	m.healthMsg = "initialized"
	return nil
}

func (m *Module) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.running = true
	m.healthy = true
	m.healthMsg = "running"
	m.lastActivity = time.Now()
	return nil
}

func (m *Module) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
	}
	m.running = false
	m.healthMsg = "stopped"
	return nil
}

func (m *Module) HealthCheck() interfaces.HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return interfaces.HealthStatus{
		Healthy:     m.healthy,
		Message:     m.healthMsg,
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"running":       m.running,
			"last_activity": m.lastActivity,
		},
	}
}

func (m *Module) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

func (m *Module) Context() context.Context {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ctx
}

func (m *Module) SetHealthy(healthy bool, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = healthy
	m.healthMsg = msg
}

func (m *Module) SetEventBus(bus events.EventBus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventBus = bus
}

func (m *Module) EventBus() events.EventBus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.eventBus
}

func (m *Module) PublishEvent(eventType string, data interface{}) {
	m.mu.RLock()
	bus := m.eventBus
	m.mu.RUnlock()

	if bus != nil {
		bus.PublishAsync(events.NewEvent(eventType, m.name, data))
	}
}

func (m *Module) UpdateActivity() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastActivity = time.Now()
}

func (m *Module) LastActivity() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastActivity
}

type WorkerPool struct {
	workers  int
	workChan chan func()
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	started  bool
}

func NewWorkerPool(workers int, queueSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		workers:  workers,
		workChan: make(chan func(), queueSize),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (wp *WorkerPool) Start() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.started {
		return
	}
	wp.started = true

	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case work, ok := <-wp.workChan:
			if !ok {
				return
			}
			work()
		}
	}
}

func (wp *WorkerPool) Submit(work func()) bool {
	select {
	case wp.workChan <- work:
		return true
	case <-wp.ctx.Done():
		return false
	}
}

func (wp *WorkerPool) SubmitAsync(work func()) {
	select {
	case wp.workChan <- work:
	case <-wp.ctx.Done():
	}
}

func (wp *WorkerPool) TrySubmit(work func()) bool {
	select {
	case wp.workChan <- work:
		return true
	default:
		return false
	}
}

func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	if !wp.started {
		wp.mu.Unlock()
		return
	}
	wp.mu.Unlock()

	wp.cancel()
	close(wp.workChan)
	wp.wg.Wait()
}

type RateLimiter struct {
	mu        sync.Mutex
	rate      float64
	burst     int
	tokens    float64
	lastCheck time.Time
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:      rate,
		burst:     burst,
		tokens:    float64(burst),
		lastCheck: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastCheck).Seconds()
	rl.lastCheck = now

	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}

	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) SetRate(rate float64, burst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rate = rate
	rl.burst = burst
}

type CircuitBreaker struct {
	mu            sync.Mutex
	failures      int
	threshold     int
	timeout       time.Duration
	state         CircuitState
	lastFailure   time.Time
	onStateChange func(CircuitState)
}

type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		timeout:   timeout,
		state:     CircuitClosed,
	}
}

func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()

	switch cb.state {
	case CircuitOpen:
		if time.Since(cb.lastFailure) > cb.timeout {
			cb.setState(CircuitHalfOpen)
		} else {
			cb.mu.Unlock()
			return ErrCircuitOpen
		}
	case CircuitHalfOpen:

	}
	cb.mu.Unlock()

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailure = time.Now()
		if cb.failures >= cb.threshold {
			cb.setState(CircuitOpen)
		}
		return err
	}

	cb.failures = 0
	if cb.state == CircuitHalfOpen {
		cb.setState(CircuitClosed)
	}
	return nil
}

func (cb *CircuitBreaker) setState(state CircuitState) {
	if cb.state != state {
		cb.state = state
		if cb.onStateChange != nil {
			cb.onStateChange(state)
		}
	}
}

func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

func (cb *CircuitBreaker) OnStateChange(fn func(CircuitState)) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.onStateChange = fn
}

var ErrCircuitOpen = &CircuitError{Message: "circuit breaker is open"}

type CircuitError struct {
	Message string
}

func (e *CircuitError) Error() string {
	return e.Message
}

type GoroutineLimiter struct {
	sem     chan struct{}
	active  int64
	dropped int64
	limit   int
}

func NewGoroutineLimiter(limit int) *GoroutineLimiter {
	return &GoroutineLimiter{
		sem:   make(chan struct{}, limit),
		limit: limit,
	}
}

func (gl *GoroutineLimiter) Go(fn func()) bool {
	select {
	case gl.sem <- struct{}{}:
		atomic.AddInt64(&gl.active, 1)
		go func() {
			defer func() {
				<-gl.sem
				atomic.AddInt64(&gl.active, -1)
			}()
			fn()
		}()
		return true
	default:
		atomic.AddInt64(&gl.dropped, 1)
		return false
	}
}

func (gl *GoroutineLimiter) GoWithTimeout(fn func(), timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case gl.sem <- struct{}{}:
		atomic.AddInt64(&gl.active, 1)
		go func() {
			defer func() {
				<-gl.sem
				atomic.AddInt64(&gl.active, -1)
			}()
			fn()
		}()
		return true
	case <-t.C:
		atomic.AddInt64(&gl.dropped, 1)
		return false
	}
}

func (gl *GoroutineLimiter) Active() int64  { return atomic.LoadInt64(&gl.active) }
func (gl *GoroutineLimiter) Dropped() int64 { return atomic.LoadInt64(&gl.dropped) }
func (gl *GoroutineLimiter) Limit() int     { return gl.limit }

type MemoryWatchdog struct {
	softLimit   uint64
	hardLimit   uint64
	checkPeriod time.Duration
	onPressure  func(allocMB uint64)
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewMemoryWatchdog(softLimitMB, hardLimitMB uint64, period time.Duration) *MemoryWatchdog {
	ctx, cancel := context.WithCancel(context.Background())
	return &MemoryWatchdog{
		softLimit:   softLimitMB * 1024 * 1024,
		hardLimit:   hardLimitMB * 1024 * 1024,
		checkPeriod: period,
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (mw *MemoryWatchdog) OnPressure(fn func(allocMB uint64)) {
	mw.onPressure = fn
}

func (mw *MemoryWatchdog) Start() {
	go func() {
		ticker := time.NewTicker(mw.checkPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-mw.ctx.Done():
				return
			case <-ticker.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				if ms.Alloc > mw.hardLimit {
					log.Printf("[MemoryWatchdog] HARD limit exceeded: %dMB (limit %dMB), forcing GC",
						ms.Alloc/1024/1024, mw.hardLimit/1024/1024)
					runtime.GC()
					runtime.ReadMemStats(&ms)
					if ms.Alloc > mw.hardLimit {
						log.Printf("[MemoryWatchdog] still above hard limit after GC: %dMB", ms.Alloc/1024/1024)
					}
				} else if ms.Alloc > mw.softLimit {
					log.Printf("[MemoryWatchdog] soft limit exceeded: %dMB (limit %dMB)",
						ms.Alloc/1024/1024, mw.softLimit/1024/1024)
					if mw.onPressure != nil {
						mw.onPressure(ms.Alloc / 1024 / 1024)
					}
				}
			}
		}
	}()
}

func (mw *MemoryWatchdog) Stop() {
	mw.cancel()
}

type Metrics struct {
	mu       sync.RWMutex
	counters map[string]int64
	gauges   map[string]float64
}

func NewMetrics() *Metrics {
	return &Metrics{
		counters: make(map[string]int64),
		gauges:   make(map[string]float64),
	}
}

func (m *Metrics) Increment(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name]++
}

func (m *Metrics) Add(name string, value int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name] += value
}

func (m *Metrics) SetGauge(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[name] = value
}

func (m *Metrics) GetCounter(name string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.counters[name]
}

func (m *Metrics) GetGauge(name string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gauges[name]
}

func (m *Metrics) Snapshot() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]interface{})
	for k, v := range m.counters {
		result["counter."+k] = v
	}
	for k, v := range m.gauges {
		result["gauge."+k] = v
	}
	return result
}

func GetPublicIP() string {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org?format=text")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}
