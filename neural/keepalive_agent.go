package neural

import (
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"
	"whispera/neural/gnet"
)

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
	kaNumActions   = 5
	kaBufferSize   = 5000
	kaBatchSize    = 8
	kaGamma        = 0.95
	kaEpsilonStart = 0.40
	kaEpsilonMin   = 0.05
	kaEpsilonDecay = 0.999
	kaTargetSync   = 100
	kaTrainEvery   = 4
)

type KeepaliveView struct {
	RTTMs     float64
	MissedKAs int
	ErrorRate float64
}

type RLKeepaliveAgent struct {
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

func NewRLKeepaliveAgent(modelDir string) *RLKeepaliveAgent {
	a := &RLKeepaliveAgent{
		modelDir:      modelDir,
		prb:           NewPrioritizedBuffer(kaBufferSize),
		thompson:      NewThompsonSampler(kaNumActions),
		sticky:        StickyExplorer{K: 1},
		curriculum:    NewCurriculumTracker(20, 0.0),
		diversity:     NewDiversityTracker(kaNumActions, 0.05),
		temperature:   InitTemp,
		epsilon:       kaEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{kaStateSize, kaHidden1, kaHidden2, kaNumActions})
	a.target = gnet.Clone(a.qNet)
	a.adam = NewAdamState(a.qNet)
	if layers, eps, steps, ok := loadRLMiniPolicy(modelDir, "rl_ka.json", kaStateSize, kaNumActions); ok {
		loaded := &gnet.GorgoniaNet{Layers: layers}
		a.qNet = loaded
		a.target = gnet.Clone(loaded)
		a.epsilon = eps
		atomic.StoreInt64(&a.stepCount, steps)
	}
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

func (a *RLKeepaliveAgent) Decide(v KeepaliveView) time.Duration {
	if atomic.LoadInt64(&a.stepCount) < 30 {
		return KeepaliveIntervals[2]
	}

	state := a.encodeState(v)
	a.mu.Lock()
	defer a.mu.Unlock()

	var idx int
	if action, exploring := a.sticky.Explore(a.epsilon, kaNumActions); exploring {
		idx = action
	} else {
		qvals := a.qNet.Forward(state)
		if mrand.Float64() < 0.30 {
			idx = a.thompson.Sample(kaNumActions)
		} else {
			idx = boltzmannSample(qvals, a.temperature)
		}
	}

	a.pendingState = state
	a.pendingAction = idx
	return KeepaliveIntervals[idx]
}

func (a *RLKeepaliveAgent) RecordOutcome(quality float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	reward := quality + GlobalFlowObserver.KLReward()

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	a.curriculum.Add(reward)
	a.epsilon = math.Max(kaEpsilonMin, a.epsilon*kaEpsilonDecay)
	a.thompson.Update(action, reward)
	a.prb.Add(Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: true,
	})
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
	a.mu.Lock()
	batch, idxs, ok := a.prb.Sample(kaBatchSize)
	if !ok {
		a.mu.Unlock()
		return
	}
	dqnTrainBatchAdamPER(a.qNet, a.target, a.adam, a.prb, batch, idxs, kaNumActions, kaGamma, 0.001, defaultEntropyCoeff)
	a.temperature = math.Max(MinTemp, a.temperature*TempDecay)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	if cnt%100 == 0 {
		saveRLMiniPolicy(a.modelDir, "rl_ka.json", a.qNet.Layers, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
	a.mu.Unlock()
}
