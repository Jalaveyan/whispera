package evasion

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)

var (
	enableCoreEvasion = os.Getenv("WHISPERA_CORE_EVASION") == "1"
)

const (
	CircuitStateClosed   = "closed"
	CircuitStateOpen     = "open"
	CircuitStateHalfOpen = "half-open"
)

type CircuitBreaker struct {
	FailureCount    int
	LastFailureTime time.Time
	State           string
	Threshold       int
	Timeout         time.Duration
}

type PacketJob struct {
	Data      []byte
	Direction string
	Result    chan *PacketResult
	Error     chan error
	Timeout   time.Duration
	Timestamp time.Time
}

type PacketResult struct {
	Data  []byte
	Delay time.Duration
}

type ruleCacheKey struct {
	Size      int
	Direction string
	RuleCount int
}

type EvasionSystemMetrics struct {
	PacketsProcessed    int64
	MLPredictions       int64
	MLFailures          int64
	AverageLatency      int64
	MemoryUsage         int64
	LastCleanup         int64
	CircuitBreakerTrips int64
}

type EvasionEffectivenessMetrics struct {
	TotalPackets      int64
	SuccessfulEvasion int64
	FailedEvasion     int64
	LastUpdate        time.Time
}

type Marionette struct {
	Rules            []types.ObfuscationRule
	State            *types.TrafficState
	Profiles         map[string]*types.TrafficProfile
	Active           string
	Mutex            sync.RWMutex
	MlSystem         types.UnifiedMLSystemInterface
	AdaptiveLearning types.AdaptiveLearning
	Effectiveness    types.EffectivenessMetrics
	CoverTraffic     []byte
	DynamicManager   types.DynamicProfileManagerInterface
	RealAPI          types.RealAPIIntegrationInterface
	AdaptiveManager  types.AdaptiveProfileManager

	CircuitBreaker *CircuitBreaker
	Metrics        *EvasionSystemMetrics
	FallbackMode   bool

	Adversarial *AdversarialEngine

	EvasionWorkerPool types.EvasionWorkerPoolInterface
	RuleCache         sync.Map
	ProcessingQueue   chan *PacketJob
	Ctx               context.Context
	Cancel            context.CancelFunc
	Wg                sync.WaitGroup
}

func NewMarionette() *Marionette {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Marionette{
		Rules: make([]types.ObfuscationRule, 0),
		State: &types.TrafficState{
			MaxHistorySize:  1000,
			LastCleanup:     util.GetGlobalTimeCache().Now(),
			CleanupInterval: 30 * time.Second,
		},
		Profiles:         make(map[string]*types.TrafficProfile),
		MlSystem:         NewUnifiedMLSystem(),
		AdaptiveLearning: &AdaptiveLearningImpl{},
		Effectiveness:    NewEffectivenessMetrics(),
		AdaptiveManager:  &AdaptiveProfileManagerImpl{},
		RealAPI:          NewRealAPIIntegration(),

		CircuitBreaker: &CircuitBreaker{
			State:     CircuitStateClosed,
			Threshold: 5,
			Timeout:   30 * time.Second,
		},
		Metrics: &EvasionSystemMetrics{
			LastCleanup: util.GetGlobalTimeCache().Now().UnixNano(),
		},
		FallbackMode: false,
		Adversarial:  NewAdversarialEngine(),

		Ctx:             ctx,
		Cancel:          cancel,
		ProcessingQueue: make(chan *PacketJob, 4096),
	}

	m.EvasionWorkerPool = NewEvasionWorkerPool()

	m.initDefaultProfiles()
	m.initDefaultRules()
	m.initRussianServiceProfiles()
	m.initMobileDeviceProfiles()
	m.initDynamicProfileManager()
	m.loadRealTrafficData("fixed_traffic_data.csv")

	return m
}

func NewEffectivenessMetrics() *EvasionEffectivenessMetrics {
	timeCache := util.GetGlobalTimeCache()
	return &EvasionEffectivenessMetrics{
		TotalPackets:      0,
		SuccessfulEvasion: 0,
		FailedEvasion:     0,
		LastUpdate:        timeCache.Now(),
	}
}

func (m *Marionette) updateState(data []byte, direction string) {
	now := util.GetGlobalTimeCache().Now()

	packetInfo := types.PacketInfo{
		Size:      len(data),
		Direction: direction,
		Timestamp: now,
		Protocol:  m.State.Protocol,
		Processed: true,
		Evasion:   false,
		MLUsed:    m.MlSystem != nil,
	}

	if len(m.State.PacketHistory) < m.State.MaxHistorySize {
		m.State.PacketHistory = append(m.State.PacketHistory, packetInfo)
	} else {
		m.State.PacketHistory[m.State.PacketHistoryIdx] = packetInfo
		m.State.PacketHistoryIdx = (m.State.PacketHistoryIdx + 1) % m.State.MaxHistorySize
	}

	atomic.AddInt64(&m.State.TotalPackets, 1)
	atomic.AddInt64(&m.State.TotalBytes, int64(len(data)))
	m.State.PacketCount++
	m.State.ByteCount += int64(len(data))

	if direction == "outbound" {
		atomic.AddInt64(&m.State.OutboundPackets, 1)
		atomic.AddInt64(&m.State.OutboundBytes, int64(len(data)))
	} else {
		atomic.AddInt64(&m.State.InboundPackets, 1)
		atomic.AddInt64(&m.State.InboundBytes, int64(len(data)))
	}

	if !m.State.LastPacket.IsZero() {
		interval := now.Sub(m.State.LastPacket)
		const maxIntervals = 100
		if len(m.State.Intervals) < maxIntervals {
			m.State.Intervals = append(m.State.Intervals, interval)
			m.State.IntervalsSum += interval
		} else {
			m.State.IntervalsSum -= m.State.Intervals[m.State.IntervalsIdx]
			m.State.Intervals[m.State.IntervalsIdx] = interval
			m.State.IntervalsSum += interval
			m.State.IntervalsIdx = (m.State.IntervalsIdx + 1) % maxIntervals
		}
		m.State.AverageInterval = m.State.IntervalsSum / time.Duration(len(m.State.Intervals))
	}

	const maxPacketSizes = 1000
	if len(m.State.PacketSizes) < maxPacketSizes {
		m.State.PacketSizes = append(m.State.PacketSizes, len(data))
	} else {
		m.State.PacketSizes[m.State.PacketCount%maxPacketSizes] = len(data)
	}

	const maxRecentSizes = 50
	if len(m.State.RecentPacketSizes) < maxRecentSizes {
		m.State.RecentPacketSizes = append(m.State.RecentPacketSizes, len(data))
		m.State.RecentPacketSizesSum += len(data)
	} else {
		m.State.RecentPacketSizesSum -= m.State.RecentPacketSizes[m.State.RecentPacketSizesIdx]
		m.State.RecentPacketSizes[m.State.RecentPacketSizesIdx] = len(data)
		m.State.RecentPacketSizesSum += len(data)
		m.State.RecentPacketSizesIdx = (m.State.RecentPacketSizesIdx + 1) % maxRecentSizes
	}
	m.State.AveragePacketSize = float64(m.State.RecentPacketSizesSum) / float64(len(m.State.RecentPacketSizes))

	m.State.LastPacket = now
}

func (m *Marionette) checkCircuitBreaker() bool {
	return m.CircuitBreaker.State == CircuitStateClosed
}

func (m *Marionette) isFallbackMode() bool {
	return m.FallbackMode
}

func (m *Marionette) recordMLFailure() {
	atomic.AddInt64(&m.Metrics.MLFailures, 1)
	m.CircuitBreaker.FailureCount++
	m.CircuitBreaker.LastFailureTime = time.Now()
	if m.CircuitBreaker.FailureCount >= m.CircuitBreaker.Threshold {
		m.CircuitBreaker.State = CircuitStateOpen
		m.FallbackMode = true
	}
}

func (m *Marionette) recordMLSuccess() {
	m.CircuitBreaker.FailureCount = 0
	switch m.CircuitBreaker.State {
	case CircuitStateOpen:
		m.CircuitBreaker.State = CircuitStateHalfOpen
	case CircuitStateHalfOpen:
		m.CircuitBreaker.State = CircuitStateClosed
		m.FallbackMode = false
	}
}

func (m *Marionette) enableFallbackMode() {
	m.FallbackMode = true
}

func (m *Marionette) evaluateConditionFast(condition types.Condition) bool {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	return m.evaluateCondition(condition)
}

var (
	resultChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan []byte, 1)
		},
	}
	errorChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan error, 1)
		},
	}
)

func (m *Marionette) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	m.Mutex.RLock()
	inFallback := m.isFallbackMode()
	circuitBreakerOK := m.checkCircuitBreaker()
	hasML := m.MlSystem != nil
	hasAdaptive := m.AdaptiveManager != nil
	m.Mutex.RUnlock()

	if len(data) >= 512 {
		data = m.applyMetadataProtection(data)
	}

	if hasML && circuitBreakerOK && !inFallback && len(data) > 2048 {
		mlResult := resultChanPool.Get().(chan []byte)
		mlError := errorChanPool.Get().(chan error)
		defer func() {
			resultChanPool.Put(mlResult)
			errorChanPool.Put(mlError)
		}()

		go func() {
			context := &types.UnifiedTrafficContext{
				Direction: direction,
				Protocol:  "Marionette",
				Size:      len(data),
				Timestamp: util.GetGlobalTimeCache().Now(),
			}
			result, err := m.MlSystem.ProcessTraffic(data, context)
			select {
			case mlResult <- result:
			default:
			}
			select {
			case mlError <- err:
			default:
			}
		}()

		select {
		case result := <-mlResult:
			err := <-mlError
			m.Mutex.Lock()
			if err != nil {
				m.recordMLFailure()
				m.enableFallbackMode()
				if m.Adversarial != nil {
					features := m.Adversarial.extractFeatures(data)
					m.Adversarial.RecordFeedback(true, m.Adversarial.bestVector.strategy, m.Adversarial.intensity, features)
				}
			} else {
				m.recordMLSuccess()
				if len(result) > 0 && !bytes.Equal(result, data) {
					data = result
				}
				if m.Adversarial != nil {
					features := m.Adversarial.extractFeatures(data)
					m.Adversarial.RecordFeedback(false, m.Adversarial.bestVector.strategy, m.Adversarial.intensity, features)
				}
			}
			m.Mutex.Unlock()
		case <-time.After(50 * time.Millisecond):
			m.Mutex.Lock()
			m.recordMLFailure()
			m.Mutex.Unlock()
		}
	}

	if m.Adversarial != nil && direction == "outbound" {
		data = m.Adversarial.Apply(data)
	}

	if hasAdaptive && !inFallback {
		m.Mutex.RLock()
		_ = m.analyzeTrafficSuccess(data, direction)
		m.Mutex.RUnlock()
	}

	m.Mutex.Lock()
	m.updateState(data, direction)
	rules := m.Rules
	m.Mutex.Unlock()

	processed := data
	delay := time.Duration(0)
	atomic.AddInt64(&m.Metrics.PacketsProcessed, 1)

	if len(processed) < 512 {
		for _, rule := range rules {
			if !rule.Enabled || rule.Priority < 5 {
				continue
			}
		}
	} else {
		cacheKey := ruleCacheKey{
			Size:      len(processed),
			Direction: direction,
			RuleCount: len(rules),
		}
		if cached, ok := m.RuleCache.Load(cacheKey); ok {
			if cachedResult, ok := cached.(*PacketResult); ok {
				processed = make([]byte, len(cachedResult.Data))
				copy(processed, cachedResult.Data)
				delay = cachedResult.Delay
			}
		} else {
			for _, rule := range rules {
				if !rule.Enabled {
					continue
				}
			}
			if len(processed) > 0 {
				resultCopy := make([]byte, len(processed))
				copy(resultCopy, processed)
				m.RuleCache.Store(cacheKey, &PacketResult{
					Data:  resultCopy,
					Delay: delay,
				})
				if atomic.LoadInt64(&m.Metrics.PacketsProcessed)%1000 == 0 {
					m.cleanupRuleCache()
				}
			}
		}
	}

	if delay > 0 {
		for {
			oldLatency := atomic.LoadInt64(&m.Metrics.AverageLatency)
			newLatency := (oldLatency + delay.Nanoseconds()) / 2
			if atomic.CompareAndSwapInt64(&m.Metrics.AverageLatency, oldLatency, newLatency) {
				break
			}
		}
	}

	return processed, delay, nil
}

type EvasionWorkerPool struct {
	workers    int
	jobQueue   chan *EvasionJob
	workerPool chan chan *EvasionJob
	quit       chan struct{}
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

type EvasionJob struct {
	Data      []byte
	Params    map[string]interface{}
	Result    chan []byte
	Error     chan error
	Timeout   time.Duration
	Timestamp time.Time
}

func NewEvasionWorkerPool() *EvasionWorkerPool {
	workers := runtime.NumCPU()
	if workers > 16 {
		workers = 16
	}
	if workers < 2 {
		workers = 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := &EvasionWorkerPool{
		workers:    workers,
		jobQueue:   make(chan *EvasionJob, 2048),
		workerPool: make(chan chan *EvasionJob, workers),
		quit:       make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}
	pool.start()
	return pool
}

func (p *EvasionWorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	go p.dispatcher()
}

func (p *EvasionWorkerPool) dispatcher() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case job := <-p.jobQueue:
			if time.Since(job.Timestamp) > job.Timeout {
				continue
			}
			go func(j *EvasionJob) {
				j.Result <- j.Data
			}(job)
		}
	}
}

func (p *EvasionWorkerPool) worker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		}
	}
}

func (p *EvasionWorkerPool) SubmitJob(data []byte, params map[string]interface{}, timeout time.Duration) ([]byte, error) {
	return data, nil
}

func (p *EvasionWorkerPool) Stop() {
	close(p.quit)
	p.cancel()
	p.wg.Wait()
}
