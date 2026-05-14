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

var chunkLog = logger.Module("rl-chunk")

// ChunkSizes — дискретный набор размеров фреймов mux (байт).
var ChunkSizes = []int{8192, 16384, 32768, 65535}

const (
	chunkStateSize    = 5
	chunkHidden1      = 10
	chunkHidden2      = 6
	chunkNumActions   = 4 // len(ChunkSizes)
	chunkBufferSize   = 5000
	chunkBatchSize    = 8
	chunkGamma        = 0.95
	chunkEpsilonStart = 0.40
	chunkEpsilonMin   = 0.05
	chunkEpsilonDecay = 0.999
	chunkTargetSync   = 100
	chunkTrainEvery   = 4
)

// ChunkView — метрики пропускной способности для агента размера чанков.
type ChunkView struct {
	RTTMs      float64
	BytesUpSec float64 // байт/сек исходящий трафик
	BytesDnSec float64 // байт/сек входящий трафик
}

// RLChunkAgent выбирает оптимальный размер фрейма mux через DQN.
//
// State (5): rtt_norm, up_rate_norm, dn_rate_norm, hour_sin, hour_cos
// Actions: 8KB / 16KB / 32KB / 64KB
// Reward: пропускная способность / RTT баланс
type RLChunkAgent struct {
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

func NewRLChunkAgent() *RLChunkAgent {
	a := &RLChunkAgent{
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
	return a
}

func (a *RLChunkAgent) encodeState(v ChunkView) []float64 {
	s := make([]float64, chunkStateSize)
	s[0] = math.Min(v.RTTMs/500.0, 1.0)
	s[1] = math.Min(v.BytesUpSec/1e7, 1.0) // 10 MB/s → 1.0
	s[2] = math.Min(v.BytesDnSec/1e7, 1.0)
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[3] = math.Sin(2 * math.Pi * hour / 24.0)
	s[4] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

// Decide возвращает оптимальный размер фрейма (байт).
func (a *RLChunkAgent) Decide(v ChunkView) int {
	if atomic.LoadInt64(&a.stepCount) < 30 {
		return ChunkSizes[3] // 65535 — дефолт
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
	chunkLog.Info("frame=%dB eps=%.2f temp=%.2f rtt=%.0fms up=%.0fB/s dn=%.0fB/s steps=%d",
		ChunkSizes[idx], a.epsilon, a.temperature, v.RTTMs, v.BytesUpSec, v.BytesDnSec, atomic.LoadInt64(&a.stepCount))
	return ChunkSizes[idx]
}

// RecordOutcome фиксирует результат выбора размера чанка.
// quality — комбинация пропускной способности и задержки (0-1).
func (a *RLChunkAgent) RecordOutcome(quality float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	sizePenalty := float64(action) * 0.02
	reward := quality - sizePenalty

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	if a.curriculum.Add(reward) {
		a.epsilon = math.Min(chunkEpsilonStart, a.epsilon*2)
	} else {
		a.epsilon = math.Max(chunkEpsilonMin, a.epsilon*chunkEpsilonDecay)
	}
	a.thompson.Update(action, reward)
	a.prb.Add(Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: quality < 0.1,
	})
	step := atomic.AddInt64(&a.stepCount, 1)
	eps := a.epsilon
	a.mu.Unlock()

	chunkLog.Info("outcome: quality=%.2f reward=%.2f frame=%dB eps=%.3f",
		quality, reward, ChunkSizes[action], eps)

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
	temp := a.temperature
	eps := a.epsilon
	a.mu.Unlock()
	if cnt%10 == 0 {
		chunkLog.Debug("train#%d eps=%.3f temp=%.3f steps=%d", cnt, eps, temp, atomic.LoadInt64(&a.stepCount))
	}
}
