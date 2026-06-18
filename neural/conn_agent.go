package neural

import (
	"math"
	"time"
)

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
	connMaxPoolSize  = 16
	connGoodputScale = 1e8
)

var connConfig = dqnConfig{
	stateSize: connStateSize, numActions: 3, hidden1: 16, hidden2: 8,
	bufferSize: 5000, batchSize: 8, gamma: 0.95, lr: 0.001,
	epsilonStart: 0.30, epsilonMin: 0.05, epsilonDecay: 0.999,
	targetSync: 100, trainEvery: 4, stickyK: 1, diversityEps: 0.05,
	policyFile: "rl_conn_v2.json",
}

type ConnPoolView struct {
	Size       int
	RTTMs      float64
	ErrorRate  float64
	MissedKAs  int
	CBFailures int
	BytesDnSec float64
	BytesUpSec float64
}

type RLConnAgent struct {
	core *dqnCore
}

type ConnDecision struct {
	state  []float64
	action int
}

func NewRLConnAgent(modelDir string) *RLConnAgent {
	return &RLConnAgent{core: newDQNCore(modelDir, connConfig)}
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
	actionIdx := a.core.decide(state, connConfig.numActions)

	action := ConnAction(actionIdx)

	if action == ConnActionCloseWorst && view.Size <= 1 {
		action = ConnActionKeep
	}
	if action == ConnActionOpen && view.Size >= connMaxPoolSize {
		action = ConnActionKeep
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
	reward := 0.6*goodputNorm + 0.4*quality - 0.02*connCountNorm - 0.4*errNorm + GlobalFlowObserver.KLReward()

	a.core.finishStep(state, action, reward)
}
