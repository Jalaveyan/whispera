package base

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/interfaces"
)

// Container supervises a single Module: catches panics, enforces restart
// policy with exponential backoff, tracks restart counts, and exposes a
// unified health view. It is a light-weight in-process "container" — each
// module can fail independently without taking the server down.
type Container struct {
	mod interfaces.Module

	policy RestartPolicy

	mu            sync.RWMutex
	state         ContainerState
	restarts      int64
	lastPanic     string
	lastPanicTime time.Time
	ctx           context.Context
	cancel        context.CancelFunc
}

type ContainerState int

const (
	ContainerIdle ContainerState = iota
	ContainerRunning
	ContainerFailed
	ContainerStopped
)

func (s ContainerState) String() string {
	switch s {
	case ContainerIdle:
		return "idle"
	case ContainerRunning:
		return "running"
	case ContainerFailed:
		return "failed"
	case ContainerStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// RestartPolicy describes how the Container reacts to failures.
type RestartPolicy struct {
	// MaxRestarts caps automatic restarts; 0 disables auto-restart.
	MaxRestarts int
	// InitialBackoff is the wait after the first failure.
	InitialBackoff time.Duration
	// MaxBackoff caps the exponential backoff.
	MaxBackoff time.Duration
	// ResetAfter: if the module stays healthy for this long, the restart
	// counter is reset to 0.
	ResetAfter time.Duration
}

func DefaultRestartPolicy() RestartPolicy {
	return RestartPolicy{
		MaxRestarts:    5,
		InitialBackoff: 500 * time.Millisecond,
		MaxBackoff:     30 * time.Second,
		ResetAfter:     5 * time.Minute,
	}
}

func NewContainer(mod interfaces.Module, policy RestartPolicy) *Container {
	return &Container{
		mod:    mod,
		policy: policy,
		state:  ContainerIdle,
	}
}

// Start initialises the module (if it has not been initialised) and runs
// its Start method inside a panic-recovering goroutine. Returns immediately
// after the first successful Start; supervision continues in the
// background.
func (c *Container) Start(ctx context.Context, cfg interfaces.ModuleConfig) error {
	c.mu.Lock()
	if c.state == ContainerRunning {
		c.mu.Unlock()
		return fmt.Errorf("container %q already running", c.mod.Name())
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.state = ContainerRunning
	c.mu.Unlock()

	if err := c.mod.Init(c.ctx, cfg); err != nil {
		c.setFailed(fmt.Sprintf("init: %v", err))
		return err
	}
	if err := c.safeStart(); err != nil {
		c.setFailed(fmt.Sprintf("start: %v", err))
		go c.supervise(cfg)
		return err
	}
	go c.superviseHealth()
	return nil
}

func (c *Container) safeStart() (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.recordPanic(r)
			err = fmt.Errorf("panic during Start: %v", r)
		}
	}()
	return c.mod.Start()
}

func (c *Container) safeStop() (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.recordPanic(r)
			err = fmt.Errorf("panic during Stop: %v", r)
		}
	}()
	return c.mod.Stop()
}

// Stop cancels supervision and stops the wrapped module.
func (c *Container) Stop() error {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.state = ContainerStopped
	c.mu.Unlock()
	return c.safeStop()
}

// superviseHealth periodically reads the module's HealthCheck and resets
// the restart counter if the module stays healthy long enough. Runs for
// the lifetime of the Container.
func (c *Container) superviseHealth() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	var healthySince time.Time
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			hs := c.healthCheckSafe()
			if hs.Healthy {
				if healthySince.IsZero() {
					healthySince = time.Now()
				} else if c.policy.ResetAfter > 0 && time.Since(healthySince) >= c.policy.ResetAfter {
					atomic.StoreInt64(&c.restarts, 0)
					healthySince = time.Now()
				}
			} else {
				healthySince = time.Time{}
			}
		}
	}
}

func (c *Container) healthCheckSafe() (hs interfaces.HealthStatus) {
	defer func() {
		if r := recover(); r != nil {
			c.recordPanic(r)
			hs = interfaces.HealthStatus{Healthy: false, Message: fmt.Sprintf("panic in HealthCheck: %v", r), LastChecked: time.Now()}
		}
	}()
	return c.mod.HealthCheck()
}

// supervise retries Start with exponential backoff after a failure, up to
// policy.MaxRestarts attempts.
func (c *Container) supervise(cfg interfaces.ModuleConfig) {
	backoff := c.policy.InitialBackoff
	if backoff <= 0 {
		backoff = 500 * time.Millisecond
	}
	for {
		if c.policy.MaxRestarts > 0 && atomic.LoadInt64(&c.restarts) >= int64(c.policy.MaxRestarts) {
			return
		}
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backoff):
		}
		atomic.AddInt64(&c.restarts, 1)
		if err := c.safeStart(); err != nil {
			c.setFailed(fmt.Sprintf("restart: %v", err))
			backoff *= 2
			if c.policy.MaxBackoff > 0 && backoff > c.policy.MaxBackoff {
				backoff = c.policy.MaxBackoff
			}
			continue
		}
		c.setRunning()
		go c.superviseHealth()
		return
	}
}

func (c *Container) setFailed(msg string) {
	c.mu.Lock()
	c.state = ContainerFailed
	c.lastPanic = msg
	c.lastPanicTime = time.Now()
	c.mu.Unlock()
}

func (c *Container) setRunning() {
	c.mu.Lock()
	c.state = ContainerRunning
	c.mu.Unlock()
}

func (c *Container) recordPanic(r interface{}) {
	c.mu.Lock()
	c.lastPanic = fmt.Sprintf("%v\n%s", r, debug.Stack())
	c.lastPanicTime = time.Now()
	c.mu.Unlock()
}

func (c *Container) State() ContainerState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

func (c *Container) Restarts() int64 { return atomic.LoadInt64(&c.restarts) }

func (c *Container) LastPanic() (string, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastPanic, c.lastPanicTime
}

// Name returns the wrapped module's name.
func (c *Container) Name() string { return c.mod.Name() }

// HealthCheck returns the module's health annotated with container state.
func (c *Container) HealthCheck() interfaces.HealthStatus {
	hs := c.healthCheckSafe()
	if hs.Details == nil {
		hs.Details = map[string]interface{}{}
	}
	c.mu.RLock()
	hs.Details["container_state"] = c.state.String()
	hs.Details["restarts"] = atomic.LoadInt64(&c.restarts)
	if !c.lastPanicTime.IsZero() {
		hs.Details["last_panic"] = c.lastPanic
		hs.Details["last_panic_at"] = c.lastPanicTime
	}
	c.mu.RUnlock()
	return hs
}
