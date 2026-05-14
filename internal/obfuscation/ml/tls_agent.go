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
	"",        // go default
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
	tlsBufferSize   = 800
	tlsBatchSize    = 4
	tlsGamma        = 0.95
	tlsEpsilonStart = 0.50
	tlsEpsilonMin   = 0.05
	tlsEpsilonDecay = 0.97
	tlsTargetSync   = 8
	tlsTrainEvery   = 1
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
type RLTLSAgent struct {
	mu sync.RWMutex

	qNet   *gnet.GorgoniaNet
	target *gnet.GorgoniaNet
	adam   *AdamState

	prb        *PrioritizedReplayBuffer
	thompson   *ThompsonSampler
	sticky     StickyExplorer
	curriculum CurriculumTracker
	diversity  DiversityTracker
	temperature float64

	epsilon    float64
	stepCount  int64
	trainCount int64

	pendingState  []float64
	pendingAction int
}

func NewRLTLSAgent() *RLTLSAgent {
	a := &RLTLSAgent{
		prb:           NewPrioritizedBuffer(tlsBufferSize),
		thompson:      NewThompsonSampler(tlsNumActions),
		sticky:        StickyExplorer{K: 2},
		curriculum:    NewCurriculumTracker(20, 0.0),
		diversity:     NewDiversityTracker(tlsNumActions, 0.05),
		temperature:   InitTemp,
		epsilon:       tlsEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{tlsStateSize, tlsHidden1, tlsHidden2, tlsNumActions})
	a.target = gnet.Clone(a.qNet)
	a.adam = NewAdamState(a.qNet)
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
	if atomic.LoadInt64(&a.stepCount) < 10 {
		return "" // warmup: не менять TLS fingerprint
	}

	state := a.encodeState(v)
	a.mu.Lock()
	defer a.mu.Unlock()

	var idx int
	if action, exploring := a.sticky.Explore(a.epsilon, tlsNumActions); exploring {
		idx = action
	} else {
		qvals := a.qNet.Forward(state)
		if mrand.Float64() < 0.30 {
			idx = a.thompson.Sample(tlsNumActions)
		} else {
			idx = boltzmannSample(qvals, a.temperature)
		}
	}

	a.pendingState = state
	a.pendingAction = idx
	profile := TLSProfiles[idx]
	if profile == "" {
		profile = "go-default"
	}
	tlsLog.Info("profile=%s transport=%s tlsErrs=%d eps=%.2f temp=%.2f steps=%d",
		profile, v.TransportName, v.ConsecutiveTLSErrors, a.epsilon, a.temperature, atomic.LoadInt64(&a.stepCount))
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

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	if a.curriculum.Add(reward) {
		a.epsilon = math.Min(tlsEpsilonStart, a.epsilon*2)
	} else {
		a.epsilon = math.Max(tlsEpsilonMin, a.epsilon*tlsEpsilonDecay)
	}
	a.thompson.Update(action, reward)
	a.prb.Add(Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: !success,
	})
	step := atomic.AddInt64(&a.stepCount, 1)
	eps := a.epsilon
	a.mu.Unlock()

	tlsLog.Info("outcome: success=%v reward=%.1f profile=%s eps=%.3f",
		success, reward, profile, eps)

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
	a.mu.Lock()
	batch, idxs, ok := a.prb.Sample(tlsBatchSize)
	if !ok {
		a.mu.Unlock()
		return
	}
	dqnTrainBatchAdamPER(a.qNet, a.target, a.adam, a.prb, batch, idxs, tlsNumActions, tlsGamma, 0.005, defaultEntropyCoeff)
	a.temperature = math.Max(MinTemp, a.temperature*TempDecay)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	temp := a.temperature
	eps := a.epsilon
	a.mu.Unlock()
	if cnt%10 == 0 {
		tlsLog.Debug("train#%d eps=%.3f temp=%.3f steps=%d", cnt, eps, temp, atomic.LoadInt64(&a.stepCount))
	}
}
