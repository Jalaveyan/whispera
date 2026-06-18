package neural

import (
	"math"
	"time"
)

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

const boStateSize = 5

var boConfig = dqnConfig{
	stateSize: boStateSize, numActions: 5, hidden1: 12, hidden2: 8,
	bufferSize: 800, batchSize: 4, gamma: 0.95, lr: 0.005,
	epsilonStart: 0.40, epsilonMin: 0.05, epsilonDecay: 0.97,
	targetSync: 8, trainEvery: 1, stickyK: 2, diversityEps: 0.05,
	policyFile: "rl_bo.json",
}

type BackoffView struct {
	ConsecutiveFails    int
	LastErrType         BackoffErrType
	TimeSinceSuccessSec float64
}

type RLBackoffAgent struct {
	core *dqnCore
}

func NewRLBackoffAgent(modelDir string) *RLBackoffAgent {
	return &RLBackoffAgent{core: newDQNCore(modelDir, boConfig)}
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
	if a.core.stepsTaken() < 10 {
		return BackoffDelays[1]
	}
	state := a.encodeState(v)
	idx := a.core.decide(state, boConfig.numActions)
	return BackoffDelays[idx]
}

func (a *RLBackoffAgent) RecordOutcome(success bool) {
	state, action, ok := a.core.takePending()
	if !ok {
		return
	}

	var reward float64
	if success {
		reward = 1.0
	} else {
		reward = -0.5
	}
	reward += GlobalFlowObserver.KLReward()

	a.core.finishStep(state, action, reward)
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
	return a.core.Epsilon()
}
