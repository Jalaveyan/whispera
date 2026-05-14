package ml

import (
	"math"
	mrand "math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
	"whispera/internal/obfuscation/ml/gnet"
)

var tlsLog = logger.Module("rl-tls")

// TLSProfiles — набор JA3/TLS fingerprint профилей.
// Пустая строка = не перекрывать (использовать Go default).
var TLSProfiles = []string{
	"",         // go default
	"chrome",
	"firefox",
	"safari",
	"ios",
}

const (
	tlsStateSize    = 5
	tlsHidden1      = 10
	tlsHidden2      = 6
	tlsNumActions   = 5 // len(TLSProfiles)
	tlsBufferSize   = 400
	tlsBatchSize    = 8
	tlsGamma        = 0.95
	tlsEpsilonStart = 0.50
	tlsEpsilonMin   = 0.05
	tlsEpsilonDecay = 0.97
	tlsTargetSync   = 20
	tlsTrainEvery   = 4
)

// TLSView — контекст для выбора TLS fingerprint.
type TLSView struct {
	ConsecutiveTLSErrors int
	TransportName        string // используется для хэш-кодирования
	IsPhantom            bool
}

// RLTLSAgent выбирает TLS fingerprint профиль через DQN.
//
// State (5): tls_errors_norm, transport_hash_norm, hour_sin, hour_cos, is_phantom
// Actions: go / chrome / firefox / safari / ios
// Reward: +1 handshake успешен, −1 провал
//
// Разные ISP/DPI реагируют по-разному на JA3. Агент учится какой профиль
// лучше всего проходит через конкретные блокировки.
type RLTLSAgent struct {
	mu sync.RWMutex

	qNet   *gnet.GorgoniaNet
	target *gnet.GorgoniaNet

	buffer  []Experience
	bufIdx  int
	bufFull bool

	epsilon    float64
	stepCount  int64
	trainCount int64

	pendingState  []float64
	pendingAction int
}

func NewRLTLSAgent() *RLTLSAgent {
	a := &RLTLSAgent{
		buffer:        make([]Experience, tlsBufferSize),
		epsilon:       tlsEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{tlsStateSize, tlsHidden1, tlsHidden2, tlsNumActions})
	a.target = gnet.Clone(a.qNet)
	return a
}

func (a *RLTLSAgent) encodeState(v TLSView) []float64 {
	s := make([]float64, tlsStateSize)
	s[0] = math.Min(float64(v.ConsecutiveTLSErrors)/5.0, 1.0)
	s[1] = transportHash(v.TransportName)
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[2] = math.Sin(2 * math.Pi * hour / 24.0)
	s[3] = math.Cos(2 * math.Pi * hour / 24.0)
	if v.IsPhantom {
		s[4] = 1.0
	}
	return s
}

// transportHash кодирует имя транспорта в [0,1] детерминированно.
func transportHash(name string) float64 {
	h := 0
	for _, c := range strings.ToLower(name) {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return float64(h%100) / 100.0
}

// Decide возвращает строку TLS fingerprint профиля (пустая = go default).
func (a *RLTLSAgent) Decide(v TLSView) string {
	state := a.encodeState(v)
	a.mu.Lock()
	defer a.mu.Unlock()

	var idx int
	if mrand.Float64() < a.epsilon {
		idx = mrand.Intn(tlsNumActions)
	} else {
		idx = dqnArgmax(a.qNet, state, tlsNumActions)
	}

	a.pendingState = state
	a.pendingAction = idx
	profile := TLSProfiles[idx]
	if profile == "" {
		profile = "go-default"
	}
	tlsLog.Info("profile=%s transport=%s tlsErrs=%d eps=%.2f steps=%d",
		profile, v.TransportName, v.ConsecutiveTLSErrors, a.epsilon, atomic.LoadInt64(&a.stepCount))
	return TLSProfiles[idx]
}

// RecordOutcome фиксирует результат TLS handshake.
func (a *RLTLSAgent) RecordOutcome(success bool) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	reward := -1.0
	if success {
		reward = 1.0
	}
	profile := TLSProfiles[action]
	if profile == "" {
		profile = "go-default"
	}
	tlsLog.Info("outcome: success=%v reward=%.1f profile=%s eps→%.3f",
		success, reward, profile, a.epsilon*tlsEpsilonDecay)

	a.mu.Lock()
	a.buffer[a.bufIdx] = Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: !success,
	}
	a.bufIdx = (a.bufIdx + 1) % tlsBufferSize
	if a.bufIdx == 0 {
		a.bufFull = true
	}
	a.epsilon = math.Max(tlsEpsilonMin, a.epsilon*tlsEpsilonDecay)
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	if step%tlsTrainEvery == 0 {
		go a.trainStep()
	}
	if step%tlsTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLTLSAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLTLSAgent) trainStep() {
	a.mu.RLock()
	batch, ok := sampleBatch(a.buffer, a.bufIdx, a.bufFull, tlsBatchSize)
	a.mu.RUnlock()
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	dqnTrainBatch(a.qNet, a.target, batch, tlsNumActions, tlsGamma, 0.001)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	if cnt%10 == 0 {
		tlsLog.Debug("train#%d eps=%.3f steps=%d", cnt, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
}
