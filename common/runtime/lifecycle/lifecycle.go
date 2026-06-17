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
	"whispera/common/runtime/events"
	"whispera/common/runtime/interfaces"
	"whispera/common/runtime/registry"
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

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("lifecycle manager already running")
	}

	for _, cb := range m.onStart {
		if err := cb(); err != nil {
			return fmt.Errorf("pre-start callback failed: %w", err)
		}
	}

	if err := m.registry.StartAll(m.ctx); err != nil {
		return fmt.Errorf("failed to start modules: %w", err)
	}

	m.running = true
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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), m.shutdownTimeout)
	defer shutdownCancel()

	const cbTimeout = 5 * time.Second

	for i, cb := range m.onStop {
		done := make(chan error, 1)
		go func(c func() error) { done <- c() }(cb)
		select {
		case err := <-done:
			if err != nil {
				log.Printf("[Lifecycle] Pre-stop callback error: %v", err)
			}
		case <-time.After(cbTimeout):
			log.Printf("[Lifecycle] Pre-stop callback[%d] timeout %s — продолжаем", i, cbTimeout)
		}
	}

	if err := m.registry.StopAll(shutdownCtx); err != nil {
		log.Printf("[Lifecycle] Error stopping modules: %v", err)
	}

	m.cancel()

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
				if err := m.Reload(); err != nil {
					log.Printf("[Lifecycle] Reload error: %v", err)
				}
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("[Lifecycle] Received %v, initiating shutdown...", sig)
				done := make(chan error, 1)
				go func() { done <- m.Stop() }()
				select {
				case err := <-done:
					return err
				case <-time.After(m.shutdownTimeout + 15*time.Second):
					os.Exit(0)
					return nil
				}
			}
		case <-m.ctx.Done():
			return m.Stop()
		}
	}
}

func (m *Manager) Reload() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cb := range m.onReload {
		if err := cb(); err != nil {
			return fmt.Errorf("reload callback failed: %w", err)
		}
	}

	if err := m.registry.Reload(m.ctx, nil); err != nil {
		return fmt.Errorf("registry reload failed: %w", err)
	}

	return nil
}

func (m *Manager) Context() context.Context {
	return m.ctx
}

func (m *Manager) Registry() registry.Registry {
	return m.registry
}

func (m *Manager) OnStop(cb func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStop = append(m.onStop, cb)
}

func (m *Manager) OnShutdown(cb func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onShutdown = append(m.onShutdown, cb)
}
