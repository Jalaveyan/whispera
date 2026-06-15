package ml

import (
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/log"
	"whispera/internal/obfuscation/ml/gnet"
)

var jLog = logger.Module("rl-jitter")

// JitterFractions — доля от базового интервала keepalive, добавляемая как ±jitter.
// 0.10 = ±10%, 0.70 = ±70%.
var JitterFractions = []float64{0.10, 0.20, 0.40, 0.70}

const (
	jStateSize    = 5
	jHidden1      = 10
	jHidden2      = 6
	jNumActions   = 4 // len(JitterFractions)
	jBufferSize   = 5000
	jBatchSize    = 8
	jGamma        = 0.95
	jEpsilonStart = 0.40
	jEpsilonMin   = 0.05
	jEpsilonDecay = 0.999
	jTargetSync   = 100
	jTrainEvery   = 4
)

// JitterView — снимок состояния сети для агента джиттера.
type JitterView struct {
	RTTMs     float64
	MissedKAs int
	ErrorRate float64
}

// RLJitterAgent выбирает оптимальный уровень временно́го джиттера для keepalive.
//
// State (5): rtt_norm, missed_ka_norm, error_rate, hour_sin, hour_cos
// Actions: ±10% / ±20% / ±40% / ±70% от базового интервала
// Reward: стабильность соединения − штраф за высокий джиттер
type RLJitterAgent struct {
	mu sync.RWMutex

	modelDir string
	qNet     *gnet.GorgoniaNet
	target   *gnet.GorgoniaNet
	adam     *AdamState

	prb         *PrioritizedReplayBuffer
	thompson    *ThompsonSampler
	sticky      StickyExplorer
	curriculum  CurriculumTracker
	diversity   DiversityTracker
	temperature float64

	epsilon    float64
	stepCount  int64
	trainCount int64

	pendingState  []float64
	pendingAction int
}

func NewRLJitterAgent(modelDir string) *RLJitterAgent {
	a := &RLJitterAgent{
		modelDir:      modelDir,
		prb:           NewPrioritizedBuffer(jBufferSize),
		thompson:      NewThompsonSampler(jNumActions),
		sticky:        StickyExplorer{K: 1},
		curriculum:    NewCurriculumTracker(20, 0.0),
		diversity:     NewDiversityTracker(jNumActions, 0.05),
		temperature:   InitTemp,
		epsilon:       jEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{jStateSize, jHidden1, jHidden2, jNumActions})
	a.target = gnet.Clone(a.qNet)
	a.adam = NewAdamState(a.qNet)
	if layers, eps, steps, ok := loadRLMiniPolicy(modelDir, "rl_jitter.json", jStateSize, jNumActions); ok {
		loaded := &gnet.GorgoniaNet{Layers: layers}
		a.qNet = loaded
		a.target = gnet.Clone(loaded)
		a.epsilon = eps
		atomic.StoreInt64(&a.stepCount, steps)
	}
	return a
}

func (a *RLJitterAgent) encodeState(v JitterView) []float64 {
	s := make([]float64, jStateSize)
	s[0] = math.Min(v.RTTMs/500.0, 1.0)
	s[1] = math.Min(float64(v.MissedKAs)/5.0, 1.0)
	s[2] = math.Min(v.ErrorRate, 1.0)
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[3] = math.Sin(2 * math.Pi * hour / 24.0)
	s[4] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

// Decide возвращает долю джиттера (0.10–0.70).
func (a *RLJitterAgent) Decide(v JitterView) float64 {
	if atomic.LoadInt64(&a.stepCount) < 30 {
		return JitterFractions[2] // 0.40 ≈ ±40% — поведение по умолчанию
	}

	state := a.encodeState(v)
	a.mu.Lock()
	defer a.mu.Unlock()

	var idx int
	if action, exploring := a.sticky.Explore(a.epsilon, jNumActions); exploring {
		idx = action
	} else {
		qvals := a.qNet.Forward(state)
		if mrand.Float64() < 0.30 {
			idx = a.thompson.Sample(jNumActions)
		} else {
			idx = boltzmannSample(qvals, a.temperature)
		}
	}

	a.pendingState = state
	a.pendingAction = idx
	return JitterFractions[idx]
}

// RecordOutcome: quality=1 соединение стабильно, 0 — пропущен keepalive/обрыв.
func (a *RLJitterAgent) RecordOutcome(quality float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	jitterCost := float64(action) * 0.05
	reward := quality - jitterCost + GlobalFlowObserver.KLReward()

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	a.curriculum.Add(reward)
	a.epsilon = math.Max(jEpsilonMin, a.epsilon*jEpsilonDecay)
	a.thompson.Update(action, reward)
	a.prb.Add(Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: true,
	})
	step := atomic.AddInt64(&a.stepCount, 1)
	_ = a.epsilon
	a.mu.Unlock()

	if step%jTrainEvery == 0 {
		go a.trainStep()
	}
	if step%jTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLJitterAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLJitterAgent) trainStep() {
	a.mu.Lock()
	batch, idxs, ok := a.prb.Sample(jBatchSize)
	if !ok {
		a.mu.Unlock()
		return
	}
	dqnTrainBatchAdamPER(a.qNet, a.target, a.adam, a.prb, batch, idxs, jNumActions, jGamma, 0.001, defaultEntropyCoeff)
	a.temperature = math.Max(MinTemp, a.temperature*TempDecay)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	if cnt%100 == 0 {
		saveRLMiniPolicy(a.modelDir, "rl_jitter.json", a.qNet.Layers, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
	a.mu.Unlock()
	if cnt%10 == 0 {
	}
}
