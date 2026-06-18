package neural

import (
	"math"
	"time"
)

var KeepaliveIntervals = []time.Duration{
	5 * time.Second,
	10 * time.Second,
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

const kaStateSize = 5

var kaConfig = dqnConfig{
	stateSize: kaStateSize, numActions: 5, hidden1: 12, hidden2: 8,
	bufferSize: 5000, batchSize: 8, gamma: 0.95, lr: 0.001,
	epsilonStart: 0.40, epsilonMin: 0.05, epsilonDecay: 0.999,
	targetSync: 100, trainEvery: 4, stickyK: 1, diversityEps: 0.05,
	policyFile: "rl_ka.json",
}

type KeepaliveView struct {
	RTTMs     float64
	MissedKAs int
	ErrorRate float64
}

type RLKeepaliveAgent struct {
	core *dqnCore
}

func NewRLKeepaliveAgent(modelDir string) *RLKeepaliveAgent {
	return &RLKeepaliveAgent{core: newDQNCore(modelDir, kaConfig)}
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
	if a.core.stepsTaken() < 30 {
		return KeepaliveIntervals[2]
	}
	state := a.encodeState(v)
	idx := a.core.decide(state, kaConfig.numActions)
	return KeepaliveIntervals[idx]
}

func (a *RLKeepaliveAgent) RecordOutcome(quality float64) {
	state, action, ok := a.core.takePending()
	if !ok {
		return
	}
	reward := quality + GlobalFlowObserver.KLReward()
	a.core.finishStep(state, action, reward)
}

func (a *RLKeepaliveAgent) Epsilon() float64 {
	return a.core.Epsilon()
}
