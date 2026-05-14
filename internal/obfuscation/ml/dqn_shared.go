package ml

import (
	"math"
	mrand "math/rand"

	"whispera/internal/obfuscation/ml/gnet"
)

const (
	adamBeta1 = 0.9
	adamBeta2 = 0.999
	adamEps   = 1e-8
	gradClip  = 1.0
)

// AdamState holds per-layer first and second moment estimates for Adam optimizer.
type AdamState struct {
	MW [][]float64 // first moment, weights
	VW [][]float64 // second moment, weights
	MB [][]float64 // first moment, biases
	VB [][]float64 // second moment, biases
	T  int64
}

// NewAdamState allocates zero-initialized Adam state matching net's architecture.
func NewAdamState(net *gnet.GorgoniaNet) *AdamState {
	s := &AdamState{
		MW: make([][]float64, len(net.Layers)),
		VW: make([][]float64, len(net.Layers)),
		MB: make([][]float64, len(net.Layers)),
		VB: make([][]float64, len(net.Layers)),
	}
	for i, ld := range net.Layers {
		s.MW[i] = make([]float64, len(ld.W))
		s.VW[i] = make([]float64, len(ld.W))
		s.MB[i] = make([]float64, ld.OutSize)
		s.VB[i] = make([]float64, ld.OutSize)
	}
	return s
}

// dqnBackpropAdam runs one backward pass through net using Adam optimizer.
// acts must come from net.ForwardActivations(). dOut is ∂L/∂output.
func dqnBackpropAdam(net *gnet.GorgoniaNet, s *AdamState, acts [][]float64, dOut []float64, lr float64) {
	s.T++
	t := float64(s.T)
	bc1 := 1 - math.Pow(adamBeta1, t)
	bc2 := 1 - math.Pow(adamBeta2, t)

	delta := dOut
	for i := len(net.Layers) - 1; i >= 0; i-- {
		ld := &net.Layers[i]
		input := acts[i]
		output := acts[i+1]

		// ReLU gate on hidden layers
		if i < len(net.Layers)-1 {
			for j := range delta {
				if output[j] <= 0 {
					delta[j] = 0
				}
			}
		}

		// Propagate delta to previous layer
		var prev []float64
		if i > 0 {
			prev = make([]float64, ld.InSize)
			for k := 0; k < ld.InSize; k++ {
				for j := 0; j < ld.OutSize; j++ {
					prev[k] += ld.W[k*ld.OutSize+j] * delta[j]
				}
			}
		}

		// Adam update for weights
		for k := 0; k < ld.InSize && k < len(input); k++ {
			for j := 0; j < ld.OutSize; j++ {
				g := delta[j] * input[k]
				if g > gradClip {
					g = gradClip
				} else if g < -gradClip {
					g = -gradClip
				}
				idx := k*ld.OutSize + j
				s.MW[i][idx] = adamBeta1*s.MW[i][idx] + (1-adamBeta1)*g
				s.VW[i][idx] = adamBeta2*s.VW[i][idx] + (1-adamBeta2)*g*g
				mhat := s.MW[i][idx] / bc1
				vhat := s.VW[i][idx] / bc2
				ld.W[idx] -= lr * mhat / (math.Sqrt(vhat) + adamEps)
			}
		}

		// Adam update for biases
		for j := 0; j < ld.OutSize; j++ {
			g := delta[j]
			if g > gradClip {
				g = gradClip
			} else if g < -gradClip {
				g = -gradClip
			}
			s.MB[i][j] = adamBeta1*s.MB[i][j] + (1-adamBeta1)*g
			s.VB[i][j] = adamBeta2*s.VB[i][j] + (1-adamBeta2)*g*g
			mhat := s.MB[i][j] / bc1
			vhat := s.VB[i][j] / bc2
			ld.B[j] -= lr * mhat / (math.Sqrt(vhat) + adamEps)
		}

		delta = prev
	}
}

// dqnTrainBatchAdam performs one minibatch DQN update using Adam optimizer.
func dqnTrainBatchAdam(q, target *gnet.GorgoniaNet, adam *AdamState, batch []Experience, numActions int, gamma, lr float64) {
	for _, exp := range batch {
		if exp.Action >= numActions {
			continue
		}
		acts := q.ForwardActivations(exp.State)
		qvals := acts[len(acts)-1]

		var targetQ float64
		if exp.Done {
			targetQ = exp.Reward
		} else {
			nextQ := target.Forward(exp.NextState)
			maxQ := nextQ[0]
			for _, v := range nextQ[1:] {
				if v > maxQ {
					maxQ = v
				}
			}
			targetQ = exp.Reward + gamma*maxQ
		}

		dOut := make([]float64, numActions)
		dOut[exp.Action] = -(targetQ - qvals[exp.Action])
		dqnBackpropAdam(q, adam, acts, dOut, lr)
	}
}

// dqnArgmax returns the action index with the highest Q-value.
func dqnArgmax(q *gnet.GorgoniaNet, state []float64, n int) int {
	qvals := q.Forward(state)
	best := 0
	for i := 1; i < n; i++ {
		if i < len(qvals) && qvals[i] > qvals[best] {
			best = i
		}
	}
	return best
}

// sampleBatch draws a random minibatch from the replay buffer.
// Returns (batch, ok); ok=false if buffer is too small.
func sampleBatch(buffer []Experience, bufIdx int, bufFull bool, batchSize int) ([]Experience, bool) {
	size := bufIdx
	if bufFull {
		size = len(buffer)
	}
	if size < batchSize*2 {
		return nil, false
	}
	batch := make([]Experience, batchSize)
	for i := range batch {
		batch[i] = buffer[mrand.Intn(size)]
	}
	return batch, true
}
