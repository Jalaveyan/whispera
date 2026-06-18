package neural

import (
	"math"
	"time"
)

var ChunkSizes = []int{8192, 16384, 32768, 65535}

const chunkStateSize = 5

var chunkConfig = dqnConfig{
	stateSize: chunkStateSize, numActions: 4, hidden1: 10, hidden2: 6,
	bufferSize: 5000, batchSize: 8, gamma: 0.95, lr: 0.001,
	epsilonStart: 0.40, epsilonMin: 0.05, epsilonDecay: 0.999,
	targetSync: 100, trainEvery: 4, stickyK: 1, diversityEps: 0.05,
	policyFile: "rl_chunk.json",
}

type ChunkView struct {
	RTTMs      float64
	BytesUpSec float64
	BytesDnSec float64
}

type RLChunkAgent struct {
	core *dqnCore
}

func NewRLChunkAgent(modelDir string) *RLChunkAgent {
	return &RLChunkAgent{core: newDQNCore(modelDir, chunkConfig)}
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
	if a.core.stepsTaken() < 30 {
		return ChunkSizes[3]
	}
	state := a.encodeState(v)
	idx := a.core.decide(state, chunkConfig.numActions)
	return ChunkSizes[idx]
}

func (a *RLChunkAgent) RecordOutcome(quality float64) {
	state, action, ok := a.core.takePending()
	if !ok {
		return
	}
	sizePenalty := float64(action) * 0.02
	reward := quality - sizePenalty + GlobalFlowObserver.KLReward()
	a.core.finishStep(state, action, reward)
}

func (a *RLChunkAgent) Epsilon() float64 {
	return a.core.Epsilon()
}
