package ml

import (
	"math"
	mrand "math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
	"whispera/internal/obfuscation/ml/gnet"
)

var srvLog = logger.Module("rl-server")

const (
	srvMaxServers   = 8
	srvStateSize    = 10
	srvHidden1      = 16
	srvHidden2      = 8
	srvNumActions   = srvMaxServers
	srvBufferSize   = 800
	srvBatchSize    = 4
	srvGamma        = 0.95
	srvEpsilonStart = 0.50
	srvEpsilonMin   = 0.05
	srvEpsilonDecay = 0.97
	srvTargetSync   = 8
	srvTrainEvery   = 1
)

type ServerProbe struct {
	Addr    string
	Latency time.Duration
}

type RLServerAgent struct {
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

	lastProbes []ServerProbe
}

func NewRLServerAgent(modelDir string) *RLServerAgent {
	a := &RLServerAgent{
		modelDir:      modelDir,
		prb:           NewPrioritizedBuffer(srvBufferSize),
		thompson:      NewThompsonSampler(srvNumActions),
		sticky:        StickyExplorer{K: 2},
		curriculum:    NewCurriculumTracker(20, 0.0),
		diversity:     NewDiversityTracker(srvNumActions, 0.05),
		temperature:   InitTemp,
		epsilon:       srvEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{srvStateSize, srvHidden1, srvHidden2, srvNumActions})
	a.target = gnet.Clone(a.qNet)
	a.adam = NewAdamState(a.qNet)
	if layers, eps, steps, ok := loadRLMiniPolicy(modelDir, "rl_server.json"); ok {
		loaded := &gnet.GorgoniaNet{Layers: layers}
		a.qNet = loaded
		a.target = gnet.Clone(loaded)
		a.epsilon = eps
		atomic.StoreInt64(&a.stepCount, steps)
	}
	return a
}

func (a *RLServerAgent) encodeState(probes []ServerProbe) []float64 {
	s := make([]float64, srvStateSize)
	const maxRTT = 500.0
	for i := 0; i < srvMaxServers && i < len(probes); i++ {
		ms := float64(probes[i].Latency.Milliseconds())
		if probes[i].Latency == math.MaxInt64 || ms > maxRTT*10 {
			s[i] = 1.0
		} else {
			s[i] = math.Min(ms/maxRTT, 1.0)
		}
	}
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[srvMaxServers] = math.Sin(2 * math.Pi * hour / 24.0)
	s[srvMaxServers+1] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

func (a *RLServerAgent) Decide(probes []ServerProbe) string {
	if len(probes) == 0 {
		return ""
	}
	if atomic.LoadInt64(&a.stepCount) < 10 {
		return ""
	}

	sorted := make([]ServerProbe, len(probes))
	copy(sorted, probes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Latency < sorted[j].Latency
	})

	state := a.encodeState(sorted)

	a.mu.Lock()
	defer a.mu.Unlock()

	a.lastProbes = sorted

	n := len(sorted)
	if n > srvMaxServers {
		n = srvMaxServers
	}

	var idx int
	if action, exploring := a.sticky.Explore(a.epsilon, n); exploring {
		idx = action
	} else {
		qvals := a.qNet.Forward(state)
		if mrand.Float64() < 0.30 {
			idx = a.thompson.Sample(n)
		} else {
			idx = boltzmannSample(qvals[:n], a.temperature)
		}
	}
	if idx >= n {
		idx = 0
	}

	a.pendingState = state
	a.pendingAction = idx
	chosen := sorted[idx]
	srvLog.Info("pick[%d]=%s rtt=%v eps=%.2f temp=%.2f steps=%d (pool=%d servers)",
		idx, chosen.Addr, chosen.Latency, a.epsilon, a.temperature, atomic.LoadInt64(&a.stepCount), n)
	return chosen.Addr
}

func (a *RLServerAgent) RecordOutcome(success bool, latencyMs float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	var reward float64
	if success {
		reward = 1.0 - math.Min(latencyMs/500.0, 1.0)
	} else {
		reward = -1.0
	}

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	if a.curriculum.Add(reward) {
		a.epsilon = math.Min(srvEpsilonStart, a.epsilon*2)
	} else {
		a.epsilon = math.Max(srvEpsilonMin, a.epsilon*srvEpsilonDecay)
	}
	a.thompson.Update(action, reward)
	a.prb.Add(Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: !success,
	})
	step := atomic.AddInt64(&a.stepCount, 1)
	eps := a.epsilon
	a.mu.Unlock()

	srvLog.Info("outcome: success=%v reward=%.2f latency=%.0fms eps=%.3f",
		success, reward, latencyMs, eps)

	if step%srvTrainEvery == 0 {
		go a.trainStep()
	}
	if step%srvTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLServerAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLServerAgent) trainStep() {
	a.mu.Lock()
	batch, idxs, ok := a.prb.Sample(srvBatchSize)
	if !ok {
		a.mu.Unlock()
		return
	}
	dqnTrainBatchAdamPER(a.qNet, a.target, a.adam, a.prb, batch, idxs, srvNumActions, srvGamma, 0.005, defaultEntropyCoeff)
	a.temperature = math.Max(MinTemp, a.temperature*TempDecay)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	temp := a.temperature
	eps := a.epsilon
	if cnt%100 == 0 {
		saveRLMiniPolicy(a.modelDir, "rl_server.json", a.qNet.Layers, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
	a.mu.Unlock()
	if cnt%10 == 0 {
		srvLog.Debug("train#%d eps=%.3f temp=%.3f steps=%d", cnt, eps, temp, atomic.LoadInt64(&a.stepCount))
	}
}
