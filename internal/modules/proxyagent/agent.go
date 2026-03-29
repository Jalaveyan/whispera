package proxyagent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
)

var log = logger.Module("proxy-agent")

type ProbeResult struct {
	Transport  string
	Server     string
	Latency    time.Duration
	Success    bool
	Error      string
	Timestamp  time.Time
	BytesUp    int64
	BytesDown  int64
}

type TransportCandidate struct {
	Name       string
	Server     string
	Priority   float64
	Enabled    bool
	Config     map[string]interface{}
}

type AgentState int

const (
	AgentIdle AgentState = iota
	AgentProbing
	AgentRotating
	AgentConnected
	AgentBlocked
)

type AgentConfig struct {
	Candidates      []TransportCandidate
	ProbeInterval   time.Duration
	RotateInterval  time.Duration
	FailThreshold   int
	LearnRate       float64
	ExploreRate     float64
	DecayRate       float64
	MaxHistory      int
	ParallelProbes  int
}

func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		ProbeInterval:  60 * time.Second,
		RotateInterval: 30 * time.Minute,
		FailThreshold:  3,
		LearnRate:      0.1,
		ExploreRate:    0.15,
		DecayRate:      0.01,
		MaxHistory:     100,
		ParallelProbes: 3,
	}
}

type armStats struct {
	mu        sync.Mutex
	name      string
	attempts  int
	successes int
	totalMs   float64
	qValue    float64
	lastUsed  time.Time
	lastOk    bool
	streak    int
}

type ProxyAgent struct {
	mu     sync.RWMutex
	config *AgentConfig

	state       AgentState
	arms        []*armStats
	armIndex    map[string]int
	history     []ProbeResult
	currentArm  int
	consecutiveFails int

	onSwitch func(transport string, server string)

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	totalProbes    uint64
	totalRotations uint64
	totalBlocks    uint64
}

func NewProxyAgent(cfg *AgentConfig) *ProxyAgent {
	if cfg == nil {
		cfg = DefaultAgentConfig()
	}

	pa := &ProxyAgent{
		config:   cfg,
		state:    AgentIdle,
		armIndex: make(map[string]int),
		stopCh:   make(chan struct{}),
	}

	for i, c := range cfg.Candidates {
		pa.arms = append(pa.arms, &armStats{
			name:   c.Name,
			qValue: c.Priority,
		})
		pa.armIndex[c.Name] = i
	}

	return pa
}

func (pa *ProxyAgent) SetSwitchCallback(fn func(string, string)) {
	pa.mu.Lock()
	pa.onSwitch = fn
	pa.mu.Unlock()
}

func (pa *ProxyAgent) Start() {
	pa.wg.Add(2)
	go pa.probeLoop()
	go pa.rotateLoop()
	log.Info("Proxy agent started (%d candidates, explore=%.0f%%)", len(pa.arms), pa.config.ExploreRate*100)
}

func (pa *ProxyAgent) Stop() {
	pa.stopOnce.Do(func() { close(pa.stopCh) })
	pa.wg.Wait()
}

func (pa *ProxyAgent) ReportResult(result ProbeResult) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	idx, ok := pa.armIndex[result.Transport]
	if !ok {
		return
	}

	arm := pa.arms[idx]
	arm.mu.Lock()
	arm.attempts++
	arm.lastUsed = result.Timestamp
	arm.lastOk = result.Success

	if result.Success {
		arm.successes++
		arm.totalMs += float64(result.Latency.Milliseconds())
		arm.streak++
		if arm.streak < 0 {
			arm.streak = 1
		}

		reward := pa.computeReward(result)
		arm.qValue += pa.config.LearnRate * (reward - arm.qValue)
	} else {
		if arm.streak > 0 {
			arm.streak = -1
		} else {
			arm.streak--
		}

		arm.qValue *= (1 - pa.config.DecayRate)
	}
	arm.mu.Unlock()

	pa.history = append(pa.history, result)
	if len(pa.history) > pa.config.MaxHistory {
		pa.history = pa.history[len(pa.history)-pa.config.MaxHistory:]
	}

	if !result.Success {
		pa.consecutiveFails++
		if pa.consecutiveFails >= pa.config.FailThreshold {
			pa.state = AgentBlocked
			atomic.AddUint64(&pa.totalBlocks, 1)
			log.Warn("Agent detected block (fails=%d), triggering rotation", pa.consecutiveFails)
			go pa.emergencyRotate()
		}
	} else {
		pa.consecutiveFails = 0
		pa.state = AgentConnected
	}
}

func (pa *ProxyAgent) computeReward(r ProbeResult) float64 {
	latencyScore := 1.0 - math.Min(float64(r.Latency.Milliseconds())/5000.0, 1.0)
	throughputScore := 0.5
	if r.BytesDown > 0 {
		mbps := float64(r.BytesDown) / float64(r.Latency.Seconds()+0.001) / 1024 / 1024
		throughputScore = math.Min(mbps/10.0, 1.0)
	}
	return latencyScore*0.6 + throughputScore*0.4
}

func (pa *ProxyAgent) SelectTransport() (string, string) {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	if len(pa.arms) == 0 {
		return "", ""
	}

	if shouldExplore(pa.config.ExploreRate) {
		idx := cryptoRandN(len(pa.arms))
		candidate := pa.config.Candidates[idx]
		return candidate.Name, candidate.Server
	}

	totalAttempts := 0
	for _, a := range pa.arms {
		a.mu.Lock()
		totalAttempts += a.attempts
		a.mu.Unlock()
	}

	bestIdx := 0
	bestQ := -1.0
	for i, arm := range pa.arms {
		arm.mu.Lock()
		q := arm.qValue
		if !pa.config.Candidates[i].Enabled {
			arm.mu.Unlock()
			continue
		}
		if arm.streak < -2 {
			q *= 0.5
		}
		ucb := q
		if arm.attempts > 0 && totalAttempts > 0 {
			ucb += math.Sqrt(2 * math.Log(float64(totalAttempts)) / float64(arm.attempts))
		} else if arm.attempts == 0 {
			ucb = 100
		}
		arm.mu.Unlock()

		if ucb > bestQ {
			bestQ = ucb
			bestIdx = i
		}
	}

	pa.mu.RUnlock()
	pa.mu.Lock()
	pa.currentArm = bestIdx
	pa.mu.Unlock()
	pa.mu.RLock()

	candidate := pa.config.Candidates[bestIdx]
	return candidate.Name, candidate.Server
}

func (pa *ProxyAgent) probeLoop() {
	defer pa.wg.Done()

	ticker := time.NewTicker(pa.config.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pa.stopCh:
			return
		case <-ticker.C:
			pa.probeAll()
		}
	}
}

func (pa *ProxyAgent) probeAll() {
	pa.mu.RLock()
	state := pa.state
	pa.mu.RUnlock()

	if state == AgentRotating {
		return
	}

	pa.mu.Lock()
	pa.state = AgentProbing
	pa.mu.Unlock()

	atomic.AddUint64(&pa.totalProbes, 1)

	sem := make(chan struct{}, pa.config.ParallelProbes)
	var wg sync.WaitGroup

	for _, c := range pa.config.Candidates {
		if !c.Enabled {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(candidate TransportCandidate) {
			defer func() {
				<-sem
				wg.Done()
			}()
			result := pa.probeCandidate(candidate)
			pa.ReportResult(result)
		}(c)
	}

	wg.Wait()

	pa.mu.Lock()
	if pa.state == AgentProbing {
		pa.state = AgentConnected
	}
	pa.mu.Unlock()
}

func (pa *ProxyAgent) probeCandidate(c TransportCandidate) ProbeResult {
	result := ProbeResult{
		Transport: c.Name,
		Server:    c.Server,
		Timestamp: time.Now(),
	}

	if c.Server == "" {
		result.Error = "no server"
		return result
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.Server)
	if err != nil {
		result.Error = err.Error()
		result.Latency = time.Since(start)
		return result
	}
	defer conn.Close()

	result.Latency = time.Since(start)
	result.Success = true

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	testData := make([]byte, 64)
	rand.Read(testData)
	n, err := conn.Write(testData)
	if err == nil {
		result.BytesUp = int64(n)
	}

	buf := make([]byte, 1024)
	n, _ = conn.Read(buf)
	result.BytesDown = int64(n)

	return result
}

func (pa *ProxyAgent) rotateLoop() {
	defer pa.wg.Done()

	ticker := time.NewTicker(pa.config.RotateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pa.stopCh:
			return
		case <-ticker.C:
			pa.scheduledRotate()
		}
	}
}

func (pa *ProxyAgent) scheduledRotate() {
	transport, server := pa.SelectTransport()
	if transport == "" {
		return
	}

	pa.mu.Lock()
	pa.state = AgentRotating
	pa.mu.Unlock()

	atomic.AddUint64(&pa.totalRotations, 1)
	log.Info("Scheduled rotation: %s @ %s", transport, server)

	pa.mu.RLock()
	cb := pa.onSwitch
	pa.mu.RUnlock()

	if cb != nil {
		cb(transport, server)
	}

	pa.mu.Lock()
	pa.state = AgentConnected
	pa.consecutiveFails = 0
	pa.mu.Unlock()
}

func (pa *ProxyAgent) emergencyRotate() {
	pa.mu.Lock()
	pa.state = AgentRotating
	pa.mu.Unlock()

	transport, server := pa.SelectTransport()
	if transport == "" {
		pa.mu.Lock()
		pa.state = AgentBlocked
		pa.mu.Unlock()
		return
	}

	atomic.AddUint64(&pa.totalRotations, 1)
	log.Warn("Emergency rotation: %s @ %s", transport, server)

	pa.mu.RLock()
	cb := pa.onSwitch
	pa.mu.RUnlock()

	if cb != nil {
		cb(transport, server)
	}

	pa.mu.Lock()
	pa.state = AgentConnected
	pa.consecutiveFails = 0
	pa.mu.Unlock()
}

func (pa *ProxyAgent) GetState() AgentState {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return pa.state
}

func (pa *ProxyAgent) Stats() map[string]interface{} {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	armStats := make([]map[string]interface{}, len(pa.arms))
	for i, arm := range pa.arms {
		arm.mu.Lock()
		avgMs := 0.0
		if arm.successes > 0 {
			avgMs = arm.totalMs / float64(arm.successes)
		}
		armStats[i] = map[string]interface{}{
			"name":      arm.name,
			"attempts":  arm.attempts,
			"successes": arm.successes,
			"q_value":   arm.qValue,
			"avg_ms":    avgMs,
			"streak":    arm.streak,
			"last_ok":   arm.lastOk,
		}
		arm.mu.Unlock()
	}

	return map[string]interface{}{
		"state":           pa.state,
		"current_arm":     pa.currentArm,
		"total_probes":    atomic.LoadUint64(&pa.totalProbes),
		"total_rotations": atomic.LoadUint64(&pa.totalRotations),
		"total_blocks":    atomic.LoadUint64(&pa.totalBlocks),
		"arms":            armStats,
		"history_len":     len(pa.history),
		"consec_fails":    pa.consecutiveFails,
	}
}

func shouldExplore(rate float64) bool {
	b := make([]byte, 8)
	rand.Read(b)
	val := float64(binary.LittleEndian.Uint64(b)) / float64(^uint64(0))
	return val < rate
}

func cryptoRandN(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(binary.LittleEndian.Uint32(b)) % n
}
