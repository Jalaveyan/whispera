package ml

import (
	"math"
	mrand "math/rand"

	"whispera/internal/obfuscation/ml/gnet"
)

// ── Adam optimizer constants ───────────────────────────────────────────────────

const (
	adamBeta1 = 0.9
	adamBeta2 = 0.999
	adamEps   = 1e-8
	gradClip  = 1.0

	// Prioritized Experience Replay
	perAlpha = 0.6 // priority exponent: 0=uniform, 1=fully prioritized

	// Entropy regularization coefficient added to the Bellman target.
	defaultEntropyCoeff = 0.01

	// Boltzmann temperature decay per training step.
	TempDecay = 0.9998
	MinTemp   = 0.1
	InitTemp  = 2.0
)

// ── Adam State ─────────────────────────────────────────────────────────────────

// AdamState holds per-layer first and second moment estimates for Adam optimizer.
type AdamState struct {
	MW [][]float64
	VW [][]float64
	MB [][]float64
	VB [][]float64
	T  int64
}

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
func dqnBackpropAdam(net *gnet.GorgoniaNet, s *AdamState, acts [][]float64, dOut []float64, lr float64) []float64 {
	s.T++
	t := float64(s.T)
	bc1 := 1 - math.Pow(adamBeta1, t)
	bc2 := 1 - math.Pow(adamBeta2, t)

	delta := dOut
	for i := len(net.Layers) - 1; i >= 0; i-- {
		ld := &net.Layers[i]
		input := acts[i]
		output := acts[i+1]

		if i < len(net.Layers)-1 {
			for j := range delta {
				if output[j] <= 0 {
					delta[j] = 0
				}
			}
		}

		prev := make([]float64, ld.InSize)
		for k := 0; k < ld.InSize; k++ {
			for j := 0; j < ld.OutSize; j++ {
				prev[k] += ld.W[k*ld.OutSize+j] * delta[j]
			}
		}

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
	return delta
}

// ── Prioritized Experience Replay ─────────────────────────────────────────────

// PrioritizedReplayBuffer samples experiences proportional to |TD error|^alpha.
// Uses a sum-tree for O(log n) add and sample operations.
type PrioritizedReplayBuffer struct {
	data    []Experience
	tree    []float64 // sum-tree: tree[1]=total; leaves at [cap..2*cap-1]
	cap     int       // always a power of 2
	size    int
	head    int
	maxPrio float64
}

func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func NewPrioritizedBuffer(capacity int) *PrioritizedReplayBuffer {
	c := nextPow2(capacity)
	return &PrioritizedReplayBuffer{
		data:    make([]Experience, c),
		tree:    make([]float64, 2*c),
		cap:     c,
		maxPrio: 1.0,
	}
}

func (b *PrioritizedReplayBuffer) Add(exp Experience) {
	b.data[b.head] = exp
	b.setTree(b.head, math.Pow(b.maxPrio, perAlpha))
	b.head = (b.head + 1) % b.cap
	if b.size < b.cap {
		b.size++
	}
}

func (b *PrioritizedReplayBuffer) setTree(idx int, p float64) {
	pos := idx + b.cap
	b.tree[pos] = p
	for pos >>= 1; pos >= 1; pos >>= 1 {
		b.tree[pos] = b.tree[pos<<1] + b.tree[pos<<1|1]
	}
}

func (b *PrioritizedReplayBuffer) UpdatePriority(idx int, tdError float64) {
	prio := math.Abs(tdError) + 1e-6
	if prio > b.maxPrio {
		b.maxPrio = prio
	}
	b.setTree(idx, math.Pow(prio, perAlpha))
}

// Sample draws n stratified samples proportional to priority.
// Returns (batch, indices, ok); ok=false if buffer is too small.
func (b *PrioritizedReplayBuffer) Sample(n int) ([]Experience, []int, bool) {
	if b.size < n*2 {
		return nil, nil, false
	}
	total := b.tree[1]
	if total <= 0 {
		return nil, nil, false
	}
	batch := make([]Experience, n)
	idxs := make([]int, n)
	seg := total / float64(n)
	for i := range batch {
		val := (float64(i) + mrand.Float64()) * seg
		leaf := b.findLeaf(val)
		idxs[i] = leaf
		batch[i] = b.data[leaf]
	}
	return batch, idxs, true
}

func (b *PrioritizedReplayBuffer) findLeaf(val float64) int {
	pos := 1
	for pos < b.cap {
		l := pos << 1
		if b.tree[l] >= val {
			pos = l
		} else {
			val -= b.tree[l]
			pos = l | 1
		}
	}
	idx := pos - b.cap
	if idx < 0 {
		idx = 0
	}
	if idx >= b.cap {
		idx = b.cap - 1
	}
	return idx
}

func (b *PrioritizedReplayBuffer) Size() int { return b.size }

// ── Training ───────────────────────────────────────────────────────────────────

// dqnTrainBatchAdamPER performs one minibatch DQN update with:
//   - Prioritized replay (updates buffer priorities with TD errors)
//   - Adam optimizer
//   - Entropy regularization bonus on the Bellman target
func dqnTrainBatchAdamPER(
	q, target *gnet.GorgoniaNet,
	adam *AdamState,
	prb *PrioritizedReplayBuffer,
	batch []Experience, idxs []int,
	numActions int,
	gamma, lr, entropyCoeff float64,
) {
	for i, exp := range batch {
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
			bonus := 0.0
			if entropyCoeff > 0 {
				bonus = entropyCoeff * entropy(softmaxVec(nextQ))
			}
			targetQ = exp.Reward + gamma*(maxQ+bonus)
		}

		tdErr := targetQ - qvals[exp.Action]
		if i < len(idxs) && prb != nil {
			prb.UpdatePriority(idxs[i], tdErr)
		}

		dOut := make([]float64, numActions)
		dOut[exp.Action] = -tdErr
		dqnBackpropAdam(q, adam, acts, dOut, lr)
	}
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func softmaxVec(v []float64) []float64 {
	if len(v) == 0 {
		return nil
	}
	maxV := v[0]
	for _, x := range v[1:] {
		if x > maxV {
			maxV = x
		}
	}
	out := make([]float64, len(v))
	sum := 0.0
	for i, x := range v {
		out[i] = math.Exp(x - maxV)
		sum += out[i]
	}
	if sum > 0 {
		for i := range out {
			out[i] /= sum
		}
	}
	return out
}

func entropy(probs []float64) float64 {
	h := 0.0
	for _, p := range probs {
		if p > 1e-10 {
			h -= p * math.Log(p)
		}
	}
	return h
}

