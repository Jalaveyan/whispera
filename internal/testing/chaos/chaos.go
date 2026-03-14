package chaos

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

type FaultType string

const (
	FaultBridgeDown     FaultType = "bridge_down"
	FaultNetworkLatency FaultType = "network_latency"
	FaultPacketLoss     FaultType = "packet_loss"
	FaultCPUSpike       FaultType = "cpu_spike"
	FaultMemoryPressure FaultType = "memory_pressure"
	FaultDNSFailure     FaultType = "dns_failure"
	FaultConnectionDrop FaultType = "connection_drop"
)

type Fault struct {
	Type     FaultType
	Target   string
	Duration time.Duration
	Params   map[string]interface{}
}

type FaultResult struct {
	Fault     Fault
	StartedAt time.Time
	EndedAt   time.Time
	Error     error
	Recovered bool
	RecoveryTime time.Duration
}

type FaultInjector interface {
	Inject(ctx context.Context, fault Fault) error
	Rollback(ctx context.Context, fault Fault) error
}

type Engine struct {
	mu        sync.Mutex
	injectors map[FaultType]FaultInjector
	active    map[string]*activeFault
	results   []FaultResult
	stopCh    chan struct{}
}

type activeFault struct {
	fault   Fault
	started time.Time
	cancel  context.CancelFunc
}

func NewEngine() *Engine {
	return &Engine{
		injectors: make(map[FaultType]FaultInjector),
		active:    make(map[string]*activeFault),
		stopCh:    make(chan struct{}),
	}
}

func (e *Engine) RegisterInjector(faultType FaultType, injector FaultInjector) {
	e.mu.Lock()
	e.injectors[faultType] = injector
	e.mu.Unlock()
}

func (e *Engine) InjectFault(ctx context.Context, fault Fault) (*FaultResult, error) {
	e.mu.Lock()
	injector, ok := e.injectors[fault.Type]
	if !ok {
		e.mu.Unlock()
		return nil, fmt.Errorf("no injector for fault type: %s", fault.Type)
	}

	faultID := fmt.Sprintf("%s-%s-%d", fault.Type, fault.Target, time.Now().UnixNano())
	faultCtx, cancel := context.WithCancel(ctx)

	af := &activeFault{
		fault:   fault,
		started: time.Now(),
		cancel:  cancel,
	}
	e.active[faultID] = af
	e.mu.Unlock()

	result := &FaultResult{
		Fault:     fault,
		StartedAt: af.started,
	}

	if err := injector.Inject(faultCtx, fault); err != nil {
		result.Error = err
		result.EndedAt = time.Now()
		e.removeFault(faultID)
		return result, err
	}

	go func() {
		select {
		case <-time.After(fault.Duration):
		case <-faultCtx.Done():
		case <-e.stopCh:
		}

		rollbackStart := time.Now()
		injector.Rollback(context.Background(), fault)
		result.EndedAt = time.Now()
		result.Recovered = true
		result.RecoveryTime = time.Since(rollbackStart)

		e.mu.Lock()
		e.results = append(e.results, *result)
		delete(e.active, faultID)
		e.mu.Unlock()
	}()

	return result, nil
}

func (e *Engine) removeFault(id string) {
	e.mu.Lock()
	if af, ok := e.active[id]; ok {
		af.cancel()
		delete(e.active, id)
	}
	e.mu.Unlock()
}

func (e *Engine) StopAllFaults() {
	e.mu.Lock()
	for id, af := range e.active {
		af.cancel()
		if injector, ok := e.injectors[af.fault.Type]; ok {
			injector.Rollback(context.Background(), af.fault)
		}
		delete(e.active, id)
	}
	e.mu.Unlock()
}

func (e *Engine) ActiveFaults() []Fault {
	e.mu.Lock()
	defer e.mu.Unlock()
	faults := make([]Fault, 0, len(e.active))
	for _, af := range e.active {
		faults = append(faults, af.fault)
	}
	return faults
}

func (e *Engine) Results() []FaultResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]FaultResult, len(e.results))
	copy(out, e.results)
	return out
}

func (e *Engine) Stop() {
	e.StopAllFaults()
	close(e.stopCh)
}

type RandomChaos struct {
	engine   *Engine
	faults   []Fault
	interval time.Duration
	stopCh   chan struct{}
}

func NewRandomChaos(engine *Engine, faults []Fault, interval time.Duration) *RandomChaos {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	return &RandomChaos{
		engine:   engine,
		faults:   faults,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (rc *RandomChaos) Start() {
	go func() {
		ticker := time.NewTicker(rc.interval)
		defer ticker.Stop()
		for {
			select {
			case <-rc.stopCh:
				return
			case <-ticker.C:
				if len(rc.faults) == 0 {
					continue
				}
				idx := randN(len(rc.faults))
				fault := rc.faults[idx]
				rc.engine.InjectFault(context.Background(), fault)
			}
		}
	}()
}

func (rc *RandomChaos) Stop() {
	close(rc.stopCh)
}

type BridgeDownInjector struct {
	onDown func(bridgeID string) error
	onUp   func(bridgeID string) error
}

func NewBridgeDownInjector(onDown, onUp func(string) error) *BridgeDownInjector {
	return &BridgeDownInjector{onDown: onDown, onUp: onUp}
}

func (b *BridgeDownInjector) Inject(_ context.Context, fault Fault) error {
	if b.onDown != nil {
		return b.onDown(fault.Target)
	}
	return nil
}

func (b *BridgeDownInjector) Rollback(_ context.Context, fault Fault) error {
	if b.onUp != nil {
		return b.onUp(fault.Target)
	}
	return nil
}

type LatencyInjector struct {
	mu      sync.Mutex
	delays  map[string]time.Duration
	onSet   func(target string, delay time.Duration)
	onClear func(target string)
}

func NewLatencyInjector(onSet func(string, time.Duration), onClear func(string)) *LatencyInjector {
	return &LatencyInjector{
		delays:  make(map[string]time.Duration),
		onSet:   onSet,
		onClear: onClear,
	}
}

func (l *LatencyInjector) Inject(_ context.Context, fault Fault) error {
	delay := fault.Duration / 2
	if d, ok := fault.Params["delay"].(time.Duration); ok {
		delay = d
	}
	l.mu.Lock()
	l.delays[fault.Target] = delay
	l.mu.Unlock()
	if l.onSet != nil {
		l.onSet(fault.Target, delay)
	}
	return nil
}

func (l *LatencyInjector) Rollback(_ context.Context, fault Fault) error {
	l.mu.Lock()
	delete(l.delays, fault.Target)
	l.mu.Unlock()
	if l.onClear != nil {
		l.onClear(fault.Target)
	}
	return nil
}

func (l *LatencyInjector) GetDelay(target string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.delays[target]
}

func randN(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(binary.BigEndian.Uint32(b)) % n
}
