package neural

import (
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"
	"whispera/neural/gnet"
)

var ChunkSizes = []int{8192, 16384, 32768, 65535}

const (
	chunkStateSize    = 5
	chunkHidden1      = 10
	chunkHidden2      = 6
	chunkNumActions   = 4
	chunkBufferSize   = 5000
	chunkBatchSize    = 8
	chunkGamma        = 0.95
	chunkEpsilonStart = 0.40
	chunkEpsilonMin   = 0.05
	chunkEpsilonDecay = 0.999
	chunkTargetSync   = 100
	chunkTrainEvery   = 4
)

type ChunkView struct {
	RTTMs      float64
	BytesUpSec float64
	BytesDnSec float64
}

type RLChunkAgent struct {
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

func NewRLChunkAgent(modelDir string) *RLChunkAgent {
	a := &RLChunkAgent{
		modelDir:      modelDir,
		prb:           NewPrioritizedBuffer(chunkBufferSize),
		thompson:      NewThompsonSampler(chunkNumActions),
		sticky:        StickyExplorer{K: 1},
		curriculum:    NewCurriculumTracker(20, 0.0),
		diversity:     NewDiversityTracker(chunkNumActions, 0.05),
		temperature:   InitTemp,
		epsilon:       chunkEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{chunkStateSize, chunkHidden1, chunkHidden2, chunkNumActions})
	a.target = gnet.Clone(a.qNet)
	a.adam = NewAdamState(a.qNet)
	if layers, eps, steps, ok := loadRLMiniPolicy(modelDir, "rl_chunk.json", chunkStateSize, chunkNumActions); ok {
		loaded := &gnet.GorgoniaNet{Layers: layers}
		a.qNet = loaded
		a.target = gnet.Clone(loaded)
		a.epsilon = eps
		atomic.StoreInt64(&a.stepCount, steps)
	}
	return a
}

func (a *RLChunkAgent) encodeState(v ChunkView) []float64 {
	s := make([]float64, chunkStateSize)
	s[0] = math.Min(v.RTTMs/500.0, 1.0)
	s[1] = math.Min(v.BytesUpSec/1e7, 1.0)
	s[2] = math.Min(v.BytesDnSec/1e7, 1.0)
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[3] = math.Sin(2 * math.Pi * hour / 24.0)
	s[4] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

func (a *RLChunkAgent) Decide(v ChunkView) int {
	if atomic.LoadInt64(&a.stepCount) < 30 {
		return ChunkSizes[3]
	}

	state := a.encodeState(v)
	a.mu.Lock()
	defer a.mu.Unlock()

	var idx int
	if action, exploring := a.sticky.Explore(a.epsilon, chunkNumActions); exploring {
		idx = action
	} else {
		qvals := a.qNet.Forward(state)
		if mrand.Float64() < 0.30 {
			idx = a.thompson.Sample(chunkNumActions)
		} else {
			idx = boltzmannSample(qvals, a.temperature)
		}
	}

	a.pendingState = state
	a.pendingAction = idx
	return ChunkSizes[idx]
}

func (a *RLChunkAgent) RecordOutcome(quality float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	sizePenalty := float64(action) * 0.02
	reward := quality - sizePenalty + GlobalFlowObserver.KLReward()

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	a.curriculum.Add(reward)
	a.epsilon = math.Max(chunkEpsilonMin, a.epsilon*chunkEpsilonDecay)
	a.thompson.Update(action, reward)
	a.prb.Add(Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: true,
	})
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	if step%chunkTrainEvery == 0 {
		go a.trainStep()
	}
	if step%chunkTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLChunkAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLChunkAgent) trainStep() {
	a.mu.Lock()
	batch, idxs, ok := a.prb.Sample(chunkBatchSize)
	if !ok {
		a.mu.Unlock()
		return
	}
	dqnTrainBatchAdamPER(a.qNet, a.target, a.adam, a.prb, batch, idxs, chunkNumActions, chunkGamma, 0.001, defaultEntropyCoeff)
	a.temperature = math.Max(MinTemp, a.temperature*TempDecay)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	if cnt%100 == 0 {
		saveRLMiniPolicy(a.modelDir, "rl_chunk.json", a.qNet.Layers, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
	a.mu.Unlock()
}
