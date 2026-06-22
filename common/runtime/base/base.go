package base

import (
	"context"
	"sync"
	"time"
	"whispera/common/runtime/events"
	"whispera/common/runtime/interfaces"
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
