package ml

import (
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
	"whispera/internal/obfuscation/ml/gnet"
)

var kaLog = logger.Module("rl-ka")

// KeepaliveIntervals — дискретный набор интервалов keepalive (агент выбирает индекс).
var KeepaliveIntervals = []time.Duration{
	5 * time.Second,
	10 * time.Second,
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

const (
	kaStateSize    = 5
	kaHidden1      = 12
	kaHidden2      = 8
	kaNumActions   = 5 // len(KeepaliveIntervals)
	kaBufferSize   = 600
	kaBatchSize    = 8
	kaGamma        = 0.95
	kaEpsilonStart = 0.40
	kaEpsilonMin   = 0.05
	kaEpsilonDecay = 0.999
	kaTargetSync   = 100
	kaTrainEvery   = 4
)

// KeepaliveView — снимок состояния для агента keepalive.
type KeepaliveView struct {
	RTTMs     float64
	MissedKAs int
	ErrorRate float64
}

// RLKeepaliveAgent выбирает оптимальный интервал keepalive через DQN.
//
// State (5): rtt_norm, missed_ka_norm, error_rate, hour_sin, hour_cos
// Actions: 5s / 10s / 15s / 30s / 60s
// Reward: качество пинга − штраф за длинный интервал
type RLKeepaliveAgent struct {
	mu sync.RWMutex

	qNet   *gnet.GorgoniaNet
	target *gnet.GorgoniaNet
	adam   *AdamState

	buffer  []Experience
	bufIdx  int
	bufFull bool

	epsilon    float64
	stepCount  int64
	trainCount int64

	pendingState  []float64
	pendingAction int
}

func NewRLKeepaliveAgent() *RLKeepaliveAgent {
	a := &RLKeepaliveAgent{
		buffer:        make([]Experience, kaBufferSize),
		epsilon:       kaEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{kaStateSize, kaHidden1, kaHidden2, kaNumActions})
	a.target = gnet.Clone(a.qNet)
	a.adam = NewAdamState(a.qNet)
	return a
}

func (a *RLKeepaliveAgent) encodeState(v KeepaliveView) []float64 {
	s := make([]float64, kaStateSize)
	s[0] = math.Min(v.RTTMs/500.0, 1.0)
	s[1] = math.Min(float64(v.MissedKAs)/5.0, 1.0)
	s[2] = math.Min(v.ErrorRate, 1.0)
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[3] = math.Sin(2 * math.Pi * hour / 24.0)
	s[4] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

// Decide выбирает интервал keepalive.
// Пока не накоплено 30 шагов — возвращает безопасный дефолт (15s) не вмешиваясь.
func (a *RLKeepaliveAgent) Decide(v KeepaliveView) time.Duration {
	if atomic.LoadInt64(&a.stepCount) < 30 {
		return KeepaliveIntervals[2] // 15s — безопасный дефолт
	}

	state := a.encodeState(v)
	a.mu.Lock()
	defer a.mu.Unlock()

	var idx int
	if mrand.Float64() < a.epsilon {
		idx = mrand.Intn(kaNumActions)
	} else {
		idx = dqnArgmax(a.qNet, state, kaNumActions)
	}

	a.pendingState = state
	a.pendingAction = idx
	kaLog.Info("interval=%v eps=%.2f rtt=%.0fms missed=%d steps=%d",
		KeepaliveIntervals[idx], a.epsilon, v.RTTMs, v.MissedKAs, atomic.LoadInt64(&a.stepCount))
	return KeepaliveIntervals[idx]
}

// RecordOutcome фиксирует результат. quality=1 — пинг прошёл успешно, 0 — пропущен.
func (a *RLKeepaliveAgent) RecordOutcome(quality float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	// Лёгкий штраф за длинные интервалы (предпочитаем чаще проверять стабильность).
	intervalPenalty := float64(action) * 0.03
	reward := quality - intervalPenalty
	kaLog.Info("outcome: quality=%.2f reward=%.2f interval=%v eps→%.3f",
		quality, reward, KeepaliveIntervals[action], a.epsilon*kaEpsilonDecay)

	a.mu.Lock()
	a.buffer[a.bufIdx] = Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: quality < 0.1,
	}
	a.bufIdx = (a.bufIdx + 1) % kaBufferSize
	if a.bufIdx == 0 {
		a.bufFull = true
	}
	a.epsilon = math.Max(kaEpsilonMin, a.epsilon*kaEpsilonDecay)
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	if step%kaTrainEvery == 0 {
		go a.trainStep()
	}
	if step%kaTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLKeepaliveAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLKeepaliveAgent) trainStep() {
	a.mu.RLock()
	batch, ok := sampleBatch(a.buffer, a.bufIdx, a.bufFull, kaBatchSize)
	a.mu.RUnlock()
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	dqnTrainBatchAdam(a.qNet, a.target, a.adam, batch, kaNumActions, kaGamma, 0.001)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	if cnt%10 == 0 {
		kaLog.Debug("train#%d eps=%.3f steps=%d", cnt, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
}
