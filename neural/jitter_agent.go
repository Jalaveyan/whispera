package neural

import (
	"math"
	"time"
)

var JitterFractions = []float64{0.10, 0.20, 0.40, 0.70}

const jStateSize = 5

var jConfig = dqnConfig{
	stateSize: jStateSize, numActions: 4, hidden1: 10, hidden2: 6,
	bufferSize: 5000, batchSize: 8, gamma: 0.95, lr: 0.001,
	epsilonStart: 0.40, epsilonMin: 0.05, epsilonDecay: 0.999,
	targetSync: 100, trainEvery: 4, stickyK: 1, diversityEps: 0.05,
	policyFile: "rl_jitter.json",
}

type JitterView struct {
	RTTMs     float64
	MissedKAs int
	ErrorRate float64
}

type RLJitterAgent struct {
	core *dqnCore
}

func NewRLJitterAgent(modelDir string) *RLJitterAgent {
	return &RLJitterAgent{core: newDQNCore(modelDir, jConfig)}
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

func (a *RLJitterAgent) Decide(v JitterView) float64 {
	if a.core.stepsTaken() < 30 {
		return JitterFractions[2]
	}
	state := a.encodeState(v)
	idx := a.core.decide(state, jConfig.numActions)
	return JitterFractions[idx]
}

func (a *RLJitterAgent) RecordOutcome(quality float64) {
	state, action, ok := a.core.takePending()
	if !ok {
		return
	}
	jitterCost := float64(action) * 0.05
	reward := quality - jitterCost + GlobalFlowObserver.KLReward()
	a.core.finishStep(state, action, reward)
}

func (a *RLJitterAgent) Epsilon() float64 {
	return a.core.Epsilon()
}
