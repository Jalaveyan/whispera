package ml

import (
	"fmt"
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/log"
	"whispera/internal/obfuscation/ml/gnet"
)

var connLog = logger.Module("rl-conn")

type ConnAction int

const (
	ConnActionKeep       ConnAction = 0
	ConnActionOpen       ConnAction = 1
	ConnActionCloseWorst ConnAction = 2
)

func (a ConnAction) String() string {
	switch a {
	case ConnActionKeep:
		return "KEEP"
	case ConnActionOpen:
		return "OPEN"
	case ConnActionCloseWorst:
		return "CLOSE_WORST"
	default:
		return "UNKNOWN"
	}
}

const (
	connStateSize    = 8
	connHidden1      = 16
	connHidden2      = 8
	connNumActions   = 3
	connBufferSize   = 5000
	connBatchSize    = 8
	connGamma        = 0.95
	connEpsilonStart = 0.30
	connEpsilonMin   = 0.05
	connEpsilonDecay = 0.999
	connTargetSync   = 100
	connTrainEvery   = 4
	connMaxPoolSize  = 16
	// connGoodputScale normalizes goodput (bytes/sec) into [0,1] for state and
	// reward. 1e8 B/s ≈ 800 Mbit/s saturates the signal.
	connGoodputScale = 1e8
)

type ConnPoolView struct {
	Size       int
	RTTMs      float64
	ErrorRate  float64
	MissedKAs  int
	CBFailures int
	// BytesDnSec/BytesUpSec are the measured aggregate goodput across the pool
	// at decision time. They drive the agent toward more parallelism while the
	// path still yields throughput, instead of shrinking on RTT alone.
	BytesDnSec float64
	BytesUpSec float64
}

type RLConnAgent struct {
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
}

type ConnDecision struct {
	state  []float64
	action int
}

func NewRLConnAgent(modelDir string) *RLConnAgent {
	a := &RLConnAgent{
		modelDir:    modelDir,
		prb:         NewPrioritizedBuffer(connBufferSize),
		thompson:    NewThompsonSampler(connNumActions),
		sticky:      StickyExplorer{K: 1},
		curriculum:  NewCurriculumTracker(20, 0.0),
		diversity:   NewDiversityTracker(connNumActions, 0.05),
		temperature: InitTemp,
		epsilon:     connEpsilonStart,
	}
	a.qNet = gnet.New([]int{connStateSize, connHidden1, connHidden2, connNumActions})
	a.target = gnet.Clone(a.qNet)
	a.adam = NewAdamState(a.qNet)
	if layers, eps, steps, ok := loadRLMiniPolicy(modelDir, "rl_conn_v2.json", connStateSize, connNumActions); ok {
		loaded := &gnet.GorgoniaNet{Layers: layers}
		a.qNet = loaded
		a.target = gnet.Clone(loaded)
		a.epsilon = eps
		atomic.StoreInt64(&a.stepCount, steps)
	}
	return a
}

func (a *RLConnAgent) EncodeState(v ConnPoolView) []float64 {
	s := make([]float64, connStateSize)
	s[0] = math.Min(float64(v.Size)/connMaxPoolSize, 1.0)
	s[1] = math.Min(v.RTTMs/500.0, 1.0)
	s[2] = math.Min(v.ErrorRate, 1.0)
	s[3] = math.Min(float64(v.MissedKAs)/5.0, 1.0)
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[4] = math.Sin(2 * math.Pi * hour / 24.0)
	s[5] = math.Cos(2 * math.Pi * hour / 24.0)
	s[6] = math.Min(v.BytesDnSec/connGoodputScale, 1.0)
	s[7] = math.Min(v.BytesUpSec/connGoodputScale, 1.0)
	return s
}

func (a *RLConnAgent) Decide(view ConnPoolView) (ConnAction, *ConnDecision) {
	state := a.EncodeState(view)

	a.mu.Lock()
	defer a.mu.Unlock()

	var actionIdx int
	var mode string

	if idx, exploring := a.sticky.Explore(a.epsilon, connNumActions); exploring {
		actionIdx = idx
		mode = "explore-sticky"
	} else {
		qvals := a.qNet.Forward(state)
		if mrand.Float64() < 0.30 {
			actionIdx = a.thompson.Sample(connNumActions)
			mode = "thompson"
		} else {
			actionIdx = boltzmannSample(qvals, a.temperature)
			mode = fmt.Sprintf("boltzmann Q=%.3f", qvals[actionIdx])
		}
	}

	action := ConnAction(actionIdx)

	if action == ConnActionCloseWorst && view.Size <= 1 {
		action = ConnActionKeep
		mode += " →KEEP(min1)"
	}

	if action == ConnActionOpen && view.Size >= connMaxPoolSize {
		action = ConnActionKeep
		mode += " →KEEP(maxpool)"
	}

	return action, &ConnDecision{state: state, action: actionIdx}
}

func (a *RLConnAgent) RecordOutcome(d *ConnDecision, quality float64) {
	if d == nil || d.state == nil {
		return
	}
	state := d.state
	action := d.action

	connCountNorm := state[0]
	goodputNorm := state[6]
	errNorm := state[2]
	// Throughput dominates: the agent is rewarded for goodput, so it grows the
	// pool while the path keeps yielding more. quality (RTT/keepalive health)
	// keeps it from chasing throughput on a dying link. The connection-count
	// term is a small regularizer to avoid pointless growth when goodput is
	// flat — it must never outweigh a real throughput gain.
	reward := 0.6*goodputNorm + 0.4*quality - 0.02*connCountNorm - 0.4*errNorm + GlobalFlowObserver.KLReward()

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	a.curriculum.Add(reward)
	a.epsilon = math.Max(connEpsilonMin, a.epsilon*connEpsilonDecay)
	a.thompson.Update(action, reward)
	a.prb.Add(Experience{
		State:     state,
		Action:    action,
		Reward:    reward,
		NextState: state,
		Done:      true,
	})
	step := atomic.AddInt64(&a.stepCount, 1)
	_ = a.epsilon
	a.mu.Unlock()

	if step%connTrainEvery == 0 {
		go a.trainStep()
	}
	if step%connTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLConnAgent) trainStep() {
	a.mu.Lock()
	batch, idxs, ok := a.prb.Sample(connBatchSize)
	if !ok {
		a.mu.Unlock()
		return
	}
	dqnTrainBatchAdamPER(a.qNet, a.target, a.adam, a.prb, batch, idxs, connNumActions, connGamma, 0.001, defaultEntropyCoeff)
	a.temperature = math.Max(MinTemp, a.temperature*TempDecay)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	_ = a.temperature
	_ = a.epsilon
	if cnt%100 == 0 {
		saveRLMiniPolicy(a.modelDir, "rl_conn_v2.json", a.qNet.Layers, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
	a.mu.Unlock()
	if cnt%10 == 0 {
	}
}
