package registry

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

type Registry interface {
	Register(module interfaces.Module) error

	Get(name string) (interfaces.Module, bool)

	GetTyped(name string, target interface{}) error

	GetAll() []interfaces.Module

	StartAll(ctx context.Context) error

	StopAll(ctx context.Context) error

	Reload(ctx context.Context, cfg interface{}) error

	HealthCheck() map[string]interfaces.HealthStatus

	SetEventBus(bus events.EventBus)

	Events() events.EventBus
}

type ModuleState int

const (
	ModuleStateUninitialized ModuleState = iota
	ModuleStateInitialized
	ModuleStateStarting
	ModuleStateRunning
	ModuleStateStopping
	ModuleStateStopped
	ModuleStateError
)

func (s ModuleState) String() string {
	switch s {
	case ModuleStateUninitialized:
		return "uninitialized"
	case ModuleStateInitialized:
		return "initialized"
	case ModuleStateStarting:
		return "starting"
	case ModuleStateRunning:
		return "running"
	case ModuleStateStopping:
		return "stopping"
	case ModuleStateStopped:
		return "stopped"
	case ModuleStateError:
		return "error"
	default:
		return "unknown"
	}
}

type moduleEntry struct {
	module interfaces.Module
	state  ModuleState
	err    error
}

type registry struct {
	mu       sync.RWMutex
	modules  map[string]*moduleEntry
	order    []string
	eventBus events.EventBus
}

func NewRegistry() Registry {
	return &registry{
		modules:  make(map[string]*moduleEntry),
		order:    make([]string, 0),
		eventBus: events.NewEventBus(100),
	}
}

func (r *registry) Register(module interfaces.Module) error {
	if module == nil {
		return fmt.Errorf("cannot register nil module")
	}

	name := module.Name()
	if name == "" {
		return fmt.Errorf("module name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.modules[name]; exists {
		return fmt.Errorf("module %q already registered", name)
	}

	r.modules[name] = &moduleEntry{
		module: module,
		state:  ModuleStateUninitialized,
	}

	return nil
}

func (r *registry) Get(name string) (interfaces.Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.modules[name]
	if !exists {
		return nil, false
	}
	return entry.module, true
}

func (r *registry) GetTyped(name string, target interface{}) error {
	module, exists := r.Get(name)
	if !exists {
		return fmt.Errorf("module %q not found", name)
	}

	switch t := target.(type) {
	case *interfaces.Transport:
		if m, ok := module.(interfaces.Transport); ok {
			*t = m
			return nil
		}
	case *interfaces.SessionManager:
		if m, ok := module.(interfaces.SessionManager); ok {
			*t = m
			return nil
		}
	case *interfaces.Router:
		if m, ok := module.(interfaces.Router); ok {
			*t = m
			return nil
		}
	case *interfaces.Obfuscator:
		if m, ok := module.(interfaces.Obfuscator); ok {
			*t = m
			return nil
		}
	}

	return fmt.Errorf("module %q is not of the expected type", name)
}

func (r *registry) GetAll() []interfaces.Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	modules := make([]interfaces.Module, 0, len(r.modules))
	for _, entry := range r.modules {
		modules = append(modules, entry.module)
	}
	return modules
}

func (r *registry) StartAll(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	order, err := r.computeStartOrder()
	if err != nil {
		return fmt.Errorf("failed to compute start order: %w", err)
	}
	r.order = order

	for _, name := range order {
		entry := r.modules[name]
		if entry.state == ModuleStateRunning {
			continue
		}

		if entry.state == ModuleStateUninitialized {
			if err := entry.module.Init(ctx, nil); err != nil {
				return fmt.Errorf("failed to init module %q: %w", name, err)
			}
			entry.state = ModuleStateInitialized
		}

		entry.state = ModuleStateStarting

		if err := entry.module.Start(); err != nil {
			entry.state = ModuleStateError
			entry.err = err
			r.publishEvent(events.EventTypeModuleError, name, map[string]interface{}{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to start module %q: %w", name, err)
		}

		entry.state = ModuleStateRunning
		r.publishEvent(events.EventTypeModuleStarted, name, nil)
		log.Printf("[Registry] Module started: %s", name)
	}

	return nil
}

func (r *registry) StopAll(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	stopOrder := make([]string, len(r.order))
	for i, name := range r.order {
		stopOrder[len(r.order)-1-i] = name
	}

	var lastErr error
	for _, name := range stopOrder {
		entry := r.modules[name]
		if entry.state != ModuleStateRunning {
			continue
		}

		entry.state = ModuleStateStopping

		if err := entry.module.Stop(); err != nil {
			entry.state = ModuleStateError
			entry.err = err
			lastErr = err
			continue
		}

		entry.state = ModuleStateStopped
		r.publishEvent(events.EventTypeModuleStopped, name, nil)
	}

	if lastErr != nil {
		return fmt.Errorf("errors occurred while stopping modules: %w", lastErr)
	}

	return nil
}

func (r *registry) Reload(ctx context.Context, cfg interface{}) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.publishEvent(events.EventTypeConfigReloaded, "registry", cfg)
	return nil
}

func (r *registry) HealthCheck() map[string]interfaces.HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status := make(map[string]interfaces.HealthStatus, len(r.modules))
	for name, entry := range r.modules {
		if entry.state == ModuleStateRunning {
			status[name] = entry.module.HealthCheck()
		} else {
			status[name] = interfaces.HealthStatus{
				Healthy:     false,
				Message:     fmt.Sprintf("module is in state: %s", entry.state),
				LastChecked: time.Now(),
			}
		}
	}
	return status
}

func (r *registry) SetEventBus(bus events.EventBus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventBus = bus
}

func (r *registry) Events() events.EventBus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.eventBus
}

func (r *registry) computeStartOrder() ([]string, error) {
	inDegree := make(map[string]int)
	deps := make(map[string][]string)

	for name := range r.modules {
		inDegree[name] = 0
		deps[name] = make([]string, 0)
	}

	for name, entry := range r.modules {
		for _, dep := range entry.module.Dependencies() {
			if _, exists := r.modules[dep]; !exists {
				return nil, fmt.Errorf("module %q depends on unregistered module %q", name, dep)
			}
			deps[dep] = append(deps[dep], name)
			inDegree[name]++
		}
	}

	queue := make([]string, 0)
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}

	sort.Strings(queue)

	order := make([]string, 0, len(r.modules))
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		order = append(order, name)

		dependents := deps[name]
		sort.Strings(dependents)
		for _, dependent := range dependents {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	if len(order) != len(r.modules) {
		return nil, fmt.Errorf("circular dependency detected in modules")
	}

	return order, nil
}

func (r *registry) publishEvent(eventType, source string, data interface{}) {
	if r.eventBus != nil {
		r.eventBus.PublishAsync(events.NewEvent(eventType, source, data))
	}
}

type ModuleFactory func(cfg interface{}) (interfaces.Module, error)

type FactoryRegistry struct {
	mu        sync.RWMutex
	factories map[string]ModuleFactory
}

func NewFactoryRegistry() *FactoryRegistry {
	return &FactoryRegistry{
		factories: make(map[string]ModuleFactory),
	}
}

func (fr *FactoryRegistry) RegisterFactory(moduleType string, factory ModuleFactory) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.factories[moduleType] = factory
}

var GlobalFactoryRegistry = NewFactoryRegistry()
