package lifecycle

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
)


type Manager struct {
	mu              sync.RWMutex
	registry        registry.Registry
	eventBus        events.EventBus
	ctx             context.Context
	cancel          context.CancelFunc
	shutdownTimeout time.Duration
	gracefulStop    bool
	running         bool

	onStart    []func() error
	onStop     []func() error
	onReload   []func() error
	onShutdown []func()
}


type Config struct {
	ShutdownTimeout time.Duration
	GracefulStop    bool
}
func DefaultConfig() Config {
	return Config{
		ShutdownTimeout: 30 * time.Second,
		GracefulStop:    true,
	}
}


func NewManager(cfg Config) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		registry:        registry.NewRegistry(),
		eventBus:        events.NewEventBus(100),
		ctx:             ctx,
		cancel:          cancel,
		shutdownTimeout: cfg.ShutdownTimeout,
		gracefulStop:    cfg.GracefulStop,
		onStart:         make([]func() error, 0),
		onStop:          make([]func() error, 0),
		onReload:        make([]func() error, 0),
		onShutdown:      make([]func(), 0),
	}

	m.registry.SetEventBus(m.eventBus)
	return m
}


func (m *Manager) Register(module interfaces.Module) error {
	return m.registry.Register(module)
}
func (m *Manager) RegisterFunc(name string, createFn func() (interfaces.Module, error)) error {
	module, err := createFn()
	if err != nil {
		return fmt.Errorf("failed to create module %s: %w", name, err)
	}
	return m.Register(module)
}


func (m *Manager) Get(name string) (interfaces.Module, bool) {
	return m.registry.Get(name)
}
func (m *Manager) MustGet(name string) interfaces.Module {
	module, ok := m.registry.Get(name)
	if !ok {
		panic(fmt.Sprintf("module %s not found", name))
	}
	return module
}


func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("lifecycle manager already running")
	}

	log.Println("[Lifecycle] Starting application...")

	
	for _, cb := range m.onStart {
		if err := cb(); err != nil {
			return fmt.Errorf("pre-start callback failed: %w", err)
		}
	}

	
	if err := m.registry.StartAll(m.ctx); err != nil {
		return fmt.Errorf("failed to start modules: %w", err)
	}

	m.running = true
	log.Println("[Lifecycle] Application started successfully")
	return nil
}


func recoverPanic(idx int) {
	if r := recover(); r != nil {
		log.Printf("[Lifecycle] onShutdown[%d] panic: %v", idx, r)
	}
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	log.Println("[Lifecycle] Stopping application...")

	
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), m.shutdownTimeout)
	defer shutdownCancel()

	
	for _, cb := range m.onStop {
		if err := cb(); err != nil {
			log.Printf("[Lifecycle] Pre-stop callback error: %v", err)
		}
	}

	
	if err := m.registry.StopAll(shutdownCtx); err != nil {
		log.Printf("[Lifecycle] Error stopping modules: %v", err)
	}


	m.cancel()

	// Каждый onShutdown callback ограничиваем 5s. Раньше любой зависший
	// callback (например, net.Close на активном соединении) держал shutdown
	// дольше systemd TimeoutStopSec → SIGKILL.
	const cbTimeout = 5 * time.Second
	for i, cb := range m.onShutdown {
		done := make(chan struct{})
		go func(c func()) { defer close(done); defer recoverPanic(i); c() }(cb)
		select {
		case <-done:
		case <-time.After(cbTimeout):
			log.Printf("[Lifecycle] onShutdown[%d] timeout %s — продолжаем", i, cbTimeout)
		}
	}

	
	m.eventBus.Close()

	m.running = false
	log.Println("[Lifecycle] Application stopped")
	return nil
}


func (m *Manager) Run() error {
	if err := m.Start(); err != nil {
		return err
	}

	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGHUP:
				log.Println("[Lifecycle] Received SIGHUP, reloading configuration...")
				if err := m.Reload(); err != nil {
					log.Printf("[Lifecycle] Reload error: %v", err)
				}
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("[Lifecycle] Received %v, initiating shutdown...", sig)
				return m.Stop()
			}
		case <-m.ctx.Done():
			return m.Stop()
		}
	}
}


func (m *Manager) Reload() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	log.Println("[Lifecycle] Reloading configuration...")

	
	for _, cb := range m.onReload {
		if err := cb(); err != nil {
			return fmt.Errorf("reload callback failed: %w", err)
		}
	}

	
	if err := m.registry.Reload(m.ctx, nil); err != nil {
		return fmt.Errorf("registry reload failed: %w", err)
	}

	log.Println("[Lifecycle] Configuration reloaded successfully")
	return nil
}


func (m *Manager) Context() context.Context {
	return m.ctx
}
func (m *Manager) Events() events.EventBus {
	return m.eventBus
}


func (m *Manager) Registry() registry.Registry {
	return m.registry
}
func (m *Manager) HealthCheck() map[string]interfaces.HealthStatus {
	return m.registry.HealthCheck()
}


func (m *Manager) IsHealthy() bool {
	status := m.HealthCheck()
	for _, s := range status {
		if !s.Healthy {
			return false
		}
	}
	return true
}


func (m *Manager) OnStart(cb func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStart = append(m.onStart, cb)
}


func (m *Manager) OnStop(cb func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStop = append(m.onStop, cb)
}


func (m *Manager) OnReload(cb func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onReload = append(m.onReload, cb)
}


func (m *Manager) OnShutdown(cb func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onShutdown = append(m.onShutdown, cb)
}


func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}


func (m *Manager) WaitForShutdown() {
	<-m.ctx.Done()
}
func (m *Manager) HealthEndpoint() func() map[string]interface{} {
	return func() map[string]interface{} {
		status := m.HealthCheck()
		healthy := true
		modules := make(map[string]interface{})

		for name, s := range status {
			if !s.Healthy {
				healthy = false
			}
			modules[name] = map[string]interface{}{
				"healthy":      s.Healthy,
				"message":      s.Message,
				"last_checked": s.LastChecked,
				"details":      s.Details,
			}
		}

		return map[string]interface{}{
			"healthy": healthy,
			"modules": modules,
		}
	}
}


func (m *Manager) GracefulShutdown() {
	m.cancel()
}
type Builder struct {
	config  Config
	modules []func() (interfaces.Module, error)
	onStart []func() error
	onStop  []func() error
}


func NewBuilder() *Builder {
	return &Builder{
		config:  DefaultConfig(),
		modules: make([]func() (interfaces.Module, error), 0),
		onStart: make([]func() error, 0),
		onStop:  make([]func() error, 0),
	}
}


func (b *Builder) WithShutdownTimeout(timeout time.Duration) *Builder {
	b.config.ShutdownTimeout = timeout
	return b
}


func (b *Builder) WithGracefulStop(graceful bool) *Builder {
	b.config.GracefulStop = graceful
	return b
}


func (b *Builder) WithModule(createFn func() (interfaces.Module, error)) *Builder {
	b.modules = append(b.modules, createFn)
	return b
}


func (b *Builder) OnStart(cb func() error) *Builder {
	b.onStart = append(b.onStart, cb)
	return b
}


func (b *Builder) OnStop(cb func() error) *Builder {
	b.onStop = append(b.onStop, cb)
	return b
}


func (b *Builder) Build() (*Manager, error) {
	m := NewManager(b.config)

	
	for _, cb := range b.onStart {
		m.OnStart(cb)
	}
	for _, cb := range b.onStop {
		m.OnStop(cb)
	}

	
	for _, createFn := range b.modules {
		module, err := createFn()
		if err != nil {
			return nil, err
		}
		if err := m.Register(module); err != nil {
			return nil, err
		}
	}

	return m, nil
}


func (b *Builder) Run() error {
	m, err := b.Build()
	if err != nil {
		return err
	}
	return m.Run()
}
