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

var boLog = logger.Module("rl-backoff")

var BackoffDelays = []time.Duration{
	1 * time.Second,
	3 * time.Second,
	8 * time.Second,
	20 * time.Second,
	60 * time.Second,
}

type BackoffErrType int

const (
	BackoffErrUnknown BackoffErrType = 0
	BackoffErrTimeout BackoffErrType = 1
	BackoffErrTLS     BackoffErrType = 2
	BackoffErrRefused BackoffErrType = 3
)

const (
	boStateSize    = 5
	boHidden1      = 12
	boHidden2      = 8
	boNumActions   = 5
	boBufferSize   = 800
	boBatchSize    = 4
	boGamma        = 0.95
	boEpsilonStart = 0.40
	boEpsilonMin   = 0.05
	boEpsilonDecay = 0.97
	boTargetSync   = 8
	boTrainEvery   = 1
)

type BackoffView struct {
	ConsecutiveFails    int
	LastErrType         BackoffErrType
	TimeSinceSuccessSec float64
}

type RLBackoffAgent struct {
	mu sync.RWMutex

	modelDir string
	qNet     *gnet.GorgoniaNet
	target   *gnet.GorgoniaNet
	adam     *AdamState

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

func NewRLBackoffAgent(modelDir string) *RLBackoffAgent {
	a := &RLBackoffAgent{
		modelDir:      modelDir,
		prb:           NewPrioritizedBuffer(boBufferSize),
		thompson:      NewThompsonSampler(boNumActions),
		sticky:        StickyExplorer{K: 2},
		curriculum:    NewCurriculumTracker(20, 0.0),
		diversity:     NewDiversityTracker(boNumActions, 0.05),
		temperature:   InitTemp,
		epsilon:       boEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{boStateSize, boHidden1, boHidden2, boNumActions})
	a.target = gnet.Clone(a.qNet)
	a.adam = NewAdamState(a.qNet)
	if layers, eps, steps, ok := loadRLMiniPolicy(modelDir, "rl_bo.json"); ok {
		loaded := &gnet.GorgoniaNet{Layers: layers}
		a.qNet = loaded
		a.target = gnet.Clone(loaded)
		a.epsilon = eps
		atomic.StoreInt64(&a.stepCount, steps)
	}
	return a
}

func (a *RLBackoffAgent) encodeState(v BackoffView) []float64 {
	s := make([]float64, boStateSize)
	s[0] = math.Min(float64(v.ConsecutiveFails)/10.0, 1.0)
	s[1] = float64(v.LastErrType) / 3.0
	s[2] = math.Min(v.TimeSinceSuccessSec/600.0, 1.0)
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[3] = math.Sin(2 * math.Pi * hour / 24.0)
	s[4] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

func (a *RLBackoffAgent) Decide(v BackoffView) time.Duration {
	if atomic.LoadInt64(&a.stepCount) < 10 {
		return BackoffDelays[1]
	}

	state := a.encodeState(v)
	a.mu.Lock()
	defer a.mu.Unlock()

	var idx int
	if action, exploring := a.sticky.Explore(a.epsilon, boNumActions); exploring {
		idx = action
	} else {
		qvals := a.qNet.Forward(state)
		if mrand.Float64() < 0.30 {
			idx = a.thompson.Sample(boNumActions)
		} else {
			idx = boltzmannSample(qvals, a.temperature)
		}
	}

	a.pendingState = state
	a.pendingAction = idx
	boLog.Info("delay=%v fails=%d errType=%d eps=%.2f temp=%.2f steps=%d",
		BackoffDelays[idx], v.ConsecutiveFails, v.LastErrType, a.epsilon, a.temperature, atomic.LoadInt64(&a.stepCount))
	return BackoffDelays[idx]
}

func (a *RLBackoffAgent) RecordOutcome(success bool) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	var reward float64
	if success {
		delayCost := float64(action) * 0.05
		reward = 1.0 - delayCost
	} else {
		reward = -0.5
	}

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	if a.curriculum.Add(reward) {
		a.epsilon = math.Min(boEpsilonStart, a.epsilon*2)
	} else {
		a.epsilon = math.Max(boEpsilonMin, a.epsilon*boEpsilonDecay)
	}
	a.thompson.Update(action, reward)
	a.prb.Add(Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: !success,
	})
	step := atomic.AddInt64(&a.stepCount, 1)
	eps := a.epsilon
	a.mu.Unlock()

	boLog.Info("outcome: success=%v reward=%.2f delay=%v eps=%.3f",
		success, reward, BackoffDelays[action], eps)

	if step%boTrainEvery == 0 {
		go a.trainStep()
	}
	if step%boTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func ClassifyBackoffErr(errStr string) BackoffErrType {
	switch {
	case containsAny(errStr, "timeout", "deadline", "i/o timeout"):
		return BackoffErrTimeout
	case containsAny(errStr, "handshake", "certificate", "tls", "x509"):
		return BackoffErrTLS
	case containsAny(errStr, "refused", "no route", "unreachable"):
		return BackoffErrRefused
	default:
		return BackoffErrUnknown
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func (a *RLBackoffAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLBackoffAgent) trainStep() {
	a.mu.Lock()
	batch, idxs, ok := a.prb.Sample(boBatchSize)
	if !ok {
		a.mu.Unlock()
		return
	}
	dqnTrainBatchAdamPER(a.qNet, a.target, a.adam, a.prb, batch, idxs, boNumActions, boGamma, 0.005, defaultEntropyCoeff)
	a.temperature = math.Max(MinTemp, a.temperature*TempDecay)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	temp := a.temperature
	eps := a.epsilon
	if cnt%100 == 0 {
		saveRLMiniPolicy(a.modelDir, "rl_bo.json", a.qNet.Layers, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
	a.mu.Unlock()
	if cnt%10 == 0 {
		boLog.Debug("train#%d eps=%.3f temp=%.3f steps=%d", cnt, eps, temp, atomic.LoadInt64(&a.stepCount))
	}
}
