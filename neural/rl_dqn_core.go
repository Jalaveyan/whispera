package neural

import (
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"whispera/neural/gnet"
)

type dqnConfig struct {
	stateSize  int
	numActions int
	hidden1    int
	hidden2    int

	bufferSize int
	batchSize  int
	gamma      float64
	lr         float64

	epsilonStart float64
	epsilonMin   float64
	epsilonDecay float64

	targetSync int64
	trainEvery int64

	stickyK      int
	diversityEps float64

	policyFile string
}

type dqnCore struct {
	mu  sync.RWMutex
	cfg dqnConfig

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

	pendingState  []float64
	pendingAction int
}

func newDQNCore(modelDir string, cfg dqnConfig) *dqnCore {
	c := &dqnCore{
		modelDir:      modelDir,
		cfg:           cfg,
		prb:           NewPrioritizedBuffer(cfg.bufferSize),
		thompson:      NewThompsonSampler(cfg.numActions),
		sticky:        StickyExplorer{K: cfg.stickyK},
		curriculum:    NewCurriculumTracker(20, 0.0),
		diversity:     NewDiversityTracker(cfg.numActions, cfg.diversityEps),
		temperature:   InitTemp,
		epsilon:       cfg.epsilonStart,
		pendingAction: -1,
	}
	c.qNet = gnet.New([]int{cfg.stateSize, cfg.hidden1, cfg.hidden2, cfg.numActions})
	c.target = gnet.Clone(c.qNet)
	c.adam = NewAdamState(c.qNet)
	if layers, eps, steps, ok := loadRLMiniPolicy(modelDir, cfg.policyFile, cfg.stateSize, cfg.numActions); ok {
		loaded := &gnet.GorgoniaNet{Layers: layers}
		c.qNet = loaded
		c.target = gnet.Clone(loaded)
		c.epsilon = eps
		atomic.StoreInt64(&c.stepCount, steps)
	}
	return c
}

func (c *dqnCore) Epsilon() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.epsilon
}

func (c *dqnCore) ExportWeights() []gnet.LayerDef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return copyLayers(c.qNet)
}

func (c *dqnCore) ImportWeights(layers []gnet.LayerDef) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.qNet.LoadWeights(layers)
	c.target = gnet.Clone(c.qNet)
}

func (c *dqnCore) stepsTaken() int64 {
	return atomic.LoadInt64(&c.stepCount)
}

func (c *dqnCore) selectAction(state []float64, n int) int {
	if action, exploring := c.sticky.Explore(c.epsilon, n); exploring {
		return action
	}
	qvals := c.qNet.Forward(state)
	if mrand.Float64() < 0.30 {
		return c.thompson.Sample(n)
	}
	if n < len(qvals) {
		qvals = qvals[:n]
	}
	return boltzmannSample(qvals, c.temperature)
}

func (c *dqnCore) decide(state []float64, n int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := c.selectAction(state, n)
	if idx >= n {
		idx = 0
	}
	c.pendingState = state
	c.pendingAction = idx
	return idx
}

func (c *dqnCore) takePending() (state []float64, action int, ok bool) {
	c.mu.Lock()
	state, action = c.pendingState, c.pendingAction
	c.mu.Unlock()
	return state, action, state != nil && action >= 0
}

func (c *dqnCore) finishStep(state []float64, action int, reward float64) int64 {
	c.mu.Lock()
	reward += c.diversity.Record(action)
	c.curriculum.Add(reward)
	c.epsilon = math.Max(c.cfg.epsilonMin, c.epsilon*c.cfg.epsilonDecay)
	c.thompson.Update(action, reward)
	c.prb.Add(Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: true,
	})
	step := atomic.AddInt64(&c.stepCount, 1)
	c.mu.Unlock()

	if step%c.cfg.trainEvery == 0 {
		go c.trainStep()
	}
	if step%c.cfg.targetSync == 0 {
		c.mu.Lock()
		c.target = gnet.Clone(c.qNet)
		c.mu.Unlock()
	}
	return step
}

func (c *dqnCore) trainStep() {
	c.mu.Lock()
	batch, idxs, ok := c.prb.Sample(c.cfg.batchSize)
	if !ok {
		c.mu.Unlock()
		return
	}
	dqnTrainBatchAdamPER(c.qNet, c.target, c.adam, c.prb, batch, idxs, c.cfg.numActions, c.cfg.gamma, c.cfg.lr, defaultEntropyCoeff)
	c.temperature = math.Max(MinTemp, c.temperature*TempDecay)
	cnt := atomic.AddInt64(&c.trainCount, 1)
	if cnt%100 == 0 {
		saveRLMiniPolicy(c.modelDir, c.cfg.policyFile, c.qNet.Layers, c.epsilon, atomic.LoadInt64(&c.stepCount))
	}
	c.mu.Unlock()
}
