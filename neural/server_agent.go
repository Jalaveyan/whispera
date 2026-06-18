package neural

import (
	"math"
	"sort"
	"time"
)

const (
	srvMaxServers = 8
	srvStateSize  = 10
)

var srvConfig = dqnConfig{
	stateSize: srvStateSize, numActions: srvMaxServers, hidden1: 16, hidden2: 8,
	bufferSize: 800, batchSize: 4, gamma: 0.95, lr: 0.005,
	epsilonStart: 0.50, epsilonMin: 0.05, epsilonDecay: 0.97,
	targetSync: 8, trainEvery: 1, stickyK: 2, diversityEps: 0.05,
	policyFile: "rl_server.json",
}

type ServerProbe struct {
	Addr    string
	Latency time.Duration
}

type RLServerAgent struct {
	core       *dqnCore
	lastProbes []ServerProbe
}

func NewRLServerAgent(modelDir string) *RLServerAgent {
	return &RLServerAgent{core: newDQNCore(modelDir, srvConfig)}
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
	if a.core.stepsTaken() < 10 {
		return ""
	}

	sorted := make([]ServerProbe, len(probes))
	copy(sorted, probes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Latency < sorted[j].Latency
	})

	state := a.encodeState(sorted)
	a.lastProbes = sorted

	n := len(sorted)
	if n > srvMaxServers {
		n = srvMaxServers
	}

	idx := a.core.decide(state, n)
	return sorted[idx].Addr
}

func (a *RLServerAgent) RecordOutcome(success bool, latencyMs float64) {
	state, action, ok := a.core.takePending()
	if !ok {
		return
	}

	var reward float64
	if success {
		reward = 1.0 - math.Min(latencyMs/500.0, 1.0)
	} else {
		reward = -1.0
	}
	reward += GlobalFlowObserver.KLReward()

	a.core.finishStep(state, action, reward)
}

func (a *RLServerAgent) Epsilon() float64 {
	return a.core.Epsilon()
}
