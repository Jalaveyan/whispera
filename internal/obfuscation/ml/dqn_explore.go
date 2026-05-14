package ml

import (
	"math"
	mrand "math/rand"
)

// ── Sticky Exploration ────────────────────────────────────────────────────────

// StickyExplorer holds a random action for K steps before re-rolling.
// Critical for slow agents (transport, SNI, TLS) where a single connection
// attempt takes seconds — without it the reward signal gets diluted across
// many random actions before any feedback arrives.
type StickyExplorer struct {
	K         int // steps to hold the chosen action
	remaining int
	held      int
}

// Explore returns (action, true) if currently in exploration mode.
// Returns (-1, false) to signal the caller should exploit instead.
func (s *StickyExplorer) Explore(epsilon float64, n int) (int, bool) {
	if s.remaining > 0 {
		s.remaining--
		return s.held, true
	}
	if mrand.Float64() < epsilon {
		s.held = mrand.Intn(n)
		s.remaining = s.K - 1
		return s.held, true
	}
	return -1, false
}

// ── Thompson Sampling ─────────────────────────────────────────────────────────

// ThompsonSampler maintains Beta(α, β) per action for Bayesian exploration.
// α accumulates successes, β accumulates failures.
// Best for binary-outcome decisions (connect success/failure, TLS handshake).
type ThompsonSampler struct {
	alpha []float64
	beta  []float64
}

func NewThompsonSampler(n int) *ThompsonSampler {
	s := &ThompsonSampler{
		alpha: make([]float64, n),
		beta:  make([]float64, n),
	}
	for i := range s.alpha {
		s.alpha[i] = 1.0 // uniform Beta(1,1) prior
		s.beta[i] = 1.0
	}
	return s
}

// Update adjusts Beta posterior for the given action based on observed reward.
func (s *ThompsonSampler) Update(action int, reward float64) {
	if action < 0 || action >= len(s.alpha) {
		return
	}
	if reward > 0 {
		s.alpha[action] += reward
	} else {
		s.beta[action] += math.Abs(reward) + 0.5
	}
}

// Sample returns the action with the highest Thompson sample (argmax of Beta samples).
func (s *ThompsonSampler) Sample(n int) int {
	if n <= 0 {
		return 0
	}
	best, bestVal := 0, -math.MaxFloat64
	for i := 0; i < n && i < len(s.alpha); i++ {
		theta := betaSample(s.alpha[i], s.beta[i])
		if theta > bestVal {
			bestVal = theta
			best = i
		}
	}
	return best
}

// betaSample samples from Beta(a, b) via the gamma ratio method.
func betaSample(a, b float64) float64 {
	x := gammaRand(a)
	y := gammaRand(b)
	if x+y < 1e-12 {
		return 0.5
	}
	return x / (x + y)
}

// gammaRand samples from Gamma(shape, 1) using Marsaglia–Tsang's method.
func gammaRand(shape float64) float64 {
	if shape < 1 {
		return gammaRand(1+shape) * math.Pow(mrand.Float64()+1e-12, 1/shape)
	}
	d := shape - 1.0/3.0
	c := 1.0 / math.Sqrt(9*d)
	for {
		x := mrand.NormFloat64()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := mrand.Float64()
		x2 := x * x
		if u < 1-0.0331*x2*x2 {
			return d * v
		}
		if math.Log(u) < 0.5*x2+d*(1-v+math.Log(v)) {
			return d * v
		}
	}
}

// ── Boltzmann (Temperature Scaling) ───────────────────────────────────────────

// boltzmannSample picks an action proportional to exp(Q/temp).
// temp→0 approaches argmax; temp→∞ approaches uniform random.
func boltzmannSample(qvals []float64, temp float64) int {
	n := len(qvals)
	if n == 0 {
		return 0
	}
	if temp < 1e-6 {
		best := 0
		for i := 1; i < n; i++ {
			if qvals[i] > qvals[best] {
				best = i
			}
		}
		return best
	}
	maxQ := qvals[0]
	for _, q := range qvals[1:] {
		if q > maxQ {
			maxQ = q
		}
	}
	probs := make([]float64, n)
	sum := 0.0
	for i, q := range qvals {
		probs[i] = math.Exp((q - maxQ) / temp)
		sum += probs[i]
	}
	r := mrand.Float64() * sum
	for i, p := range probs {
		r -= p
		if r <= 0 {
			return i
		}
	}
	return n - 1
}

// ── Curriculum Tracker ────────────────────────────────────────────────────────

// CurriculumTracker detects performance regression (e.g. censor tightened)
// and signals that epsilon should be bumped back up for re-exploration.
type CurriculumTracker struct {
	window    []float64
	idx       int
	filled    bool
	threshold float64
}

func NewCurriculumTracker(windowSize int, threshold float64) CurriculumTracker {
	return CurriculumTracker{
		window:    make([]float64, windowSize),
		threshold: threshold,
	}
}

// Add records a reward. Returns true if a performance regression is detected.
func (c *CurriculumTracker) Add(reward float64) bool {
	c.window[c.idx%len(c.window)] = reward
	c.idx++
	if !c.filled && c.idx >= len(c.window) {
		c.filled = true
	}
	if !c.filled {
		return false
	}
	sum := 0.0
	for _, r := range c.window {
		sum += r
	}
	return sum/float64(len(c.window)) < c.threshold
}

// ── Diversity Tracker ─────────────────────────────────────────────────────────

// DiversityTracker rewards underrepresented actions to prevent the policy
// from collapsing to a single action prematurely.
type DiversityTracker struct {
	counts []int64
	total  int64
	coeff  float64
}

func NewDiversityTracker(n int, coeff float64) DiversityTracker {
	return DiversityTracker{
		counts: make([]int64, n),
		coeff:  coeff,
	}
}

// Record increments the counter for action and returns a diversity bonus.
// Rare actions get a larger bonus: -coeff * log(freq).
func (d *DiversityTracker) Record(action int) float64 {
	if action < 0 || action >= len(d.counts) {
		return 0
	}
	d.counts[action]++
	d.total++
	freq := float64(d.counts[action]) / float64(d.total)
	return -d.coeff * math.Log(freq+1e-8)
}
