package ml

import (
	"encoding/json"
	"math"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"whispera/internal/log"
	"whispera/internal/obfuscation/ml/gnet"
)

var trLog = logger.Module("rl-transport")

const (
	RLStateSize    = 16
	RLActionSize   = 26
	RLHidden1      = 64
	RLHidden2      = 32
	RLBufferSize   = 1000
	RLBatchSize    = 4
	RLGamma        = 0.95
	RLEpsilonStart = 0.3
	RLEpsilonMin   = 0.05
	RLEpsilonDecay = 0.97
	RLTargetSync   = 8
	RLTrainEvery   = 1
)

type Experience struct {
	State     []float64
	Action    int
	Reward    float64
	NextState []float64
	Done      bool
}

type RLTransportAgent struct {
	mu sync.RWMutex

	qNet      *gnet.GorgoniaNet
	target    *gnet.GorgoniaNet
	worldNet  *gnet.GorgoniaNet
	adam      *AdamState
	worldAdam *AdamState

	prb         *PrioritizedReplayBuffer
	thompson    *ThompsonSampler
	sticky      StickyExplorer
	curriculum  CurriculumTracker
	diversity   DiversityTracker
	temperature float64

	epsilon    float64
	stepCount  int64
	trainCount int64

	transportNames []string
	transportIndex map[string]int

	activePool []string

	pendingState     []float64
	pendingAction    int
	consecutiveFails int32
	rotateSignal     int32

	outcomes map[string]*[2]int64

	modelDir string
}

func NewRLTransportAgent(modelDir string, _ []string) *RLTransportAgent {
	agent := &RLTransportAgent{
		prb:         NewPrioritizedBuffer(RLBufferSize),
		thompson:    NewThompsonSampler(RLActionSize),
		sticky:      StickyExplorer{K: 3},
		curriculum:  NewCurriculumTracker(20, 0.0),
		diversity:   NewDiversityTracker(RLActionSize, 0.03),
		temperature: InitTemp,
		epsilon:     RLEpsilonStart,
		modelDir:    modelDir,
		transportNames: []string{
			"tcp", "h2c", "quic", "tuic", "websocket", "grpc",
			"httpupgrade", "splithttp", "shadowtls", "shadowsocks",
			"obfs4", "meek", "snowflake", "torsocks", "domainfront",
			"mtproto", "mirage", "asn_bypass", "vkwebrtc", "okwebrtc",
			"yatelemost", "yadisk", "yacloud", "vkbot", "tgbot", "cdnworker",
		},
		transportIndex: make(map[string]int),
		outcomes:       make(map[string]*[2]int64),
	}
	for i, name := range agent.transportNames {
		agent.transportIndex[name] = i
	}
	agent.qNet = gnet.New([]int{RLStateSize, RLHidden1, RLHidden2, RLActionSize})
	agent.target = gnet.Clone(agent.qNet)
	agent.worldNet = gnet.New([]int{RLStateSize, RLHidden1, RLHidden2, RLActionSize})
	agent.adam = NewAdamState(agent.qNet)
	agent.worldAdam = NewAdamState(agent.worldNet)
	agent.activePool = agent.transportNames
	if !agent.loadPolicy() {
		agent.PreSeed()
	}
	return agent
}

func (a *RLTransportAgent) SetActivePool(names []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(names) == 0 {
		a.activePool = a.transportNames
		return
	}
	a.activePool = names
}

func (a *RLTransportAgent) Select(state []float64) (transport string, actionIdx int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pool := a.activePool
	if len(pool) == 0 {
		return "", -1
	}
	known := make([]string, 0, len(pool))
	for _, name := range pool {
		if _, ok := a.transportIndex[name]; ok {
			known = append(known, name)
		}
	}
	if len(known) == 0 {
		return "", -1
	}
	pool = known
	if atomic.LoadInt64(&a.stepCount) < 10 {
		return "", -1
	}

	var idx int

	if stickyIdx, exploring := a.sticky.Explore(a.epsilon, RLActionSize); exploring {
		found := false
		for _, name := range pool {
			if a.transportIndex[name] == stickyIdx {
				idx = stickyIdx
				found = true
				break
			}
		}
		if !found {
			pidx := mrand.Intn(len(pool))
			idx = a.transportIndex[pool[pidx]]
		}
	} else {
		qvals := a.qNet.Forward(state)
		wvals := a.worldNet.Forward(state)
		if mrand.Float64() < 0.30 {
			bestTheta := -1e9
			idx = a.transportIndex[pool[0]]
			for _, name := range pool {
				i, ok := a.transportIndex[name]
				if !ok || i >= len(a.thompson.alpha) {
					continue
				}
				theta := betaSample(a.thompson.alpha[i], a.thompson.beta[i])
				if theta > bestTheta {
					bestTheta = theta
					idx = i
				}
			}
		} else {
			scores := make([]float64, len(pool))
			pIdxs := make([]int, len(pool))
			for j, name := range pool {
				i := a.transportIndex[name]
				pIdxs[j] = i
				if i < len(qvals) && i < len(wvals) {
					scores[j] = 0.6*qvals[i] + 0.4*wvals[i]
				}
			}
			best := boltzmannSample(scores, a.temperature)
			idx = pIdxs[best]
		}
	}

	name := ""
	for _, n := range pool {
		if a.transportIndex[n] == idx {
			name = n
			break
		}
	}
	if name == "" {
		name = pool[0]
		idx = a.transportIndex[name]
	}

	a.pendingState = state
	a.pendingAction = idx
	return name, idx
}

func (a *RLTransportAgent) RecordOutcome(success bool, latencyMs float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()

	if state == nil || action < 0 {
		return
	}

	reward := ComputeReward(success, latencyMs)

	if success {
		atomic.StoreInt32(&a.consecutiveFails, 0)
	} else {
		fails := atomic.AddInt32(&a.consecutiveFails, 1)
		if fails >= 3 {
			atomic.StoreInt32(&a.rotateSignal, 1)
		}
	}

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	a.curriculum.Add(reward)
	a.thompson.Update(action, reward)
	if action >= 0 && action < len(a.transportNames) {
		c := a.outcomes[a.transportNames[action]]
		if c == nil {
			c = &[2]int64{}
			a.outcomes[a.transportNames[action]] = c
		}
		if success {
			c[0]++
		} else {
			c[1]++
		}
	}
	a.mu.Unlock()

	nextState := make([]float64, len(state))
	copy(nextState, state)
	a.RecordExperience(state, action, reward, nextState, true)
}

func (a *RLTransportAgent) ShouldRotate() bool {
	return atomic.CompareAndSwapInt32(&a.rotateSignal, 1, 0)
}

func (a *RLTransportAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLTransportAgent) EncodeState(
	rttMs [4]float64,
	recentSuccessRate float64,
	recentFailRate float64,
	dpiDetected bool,
	anomalyScore float64,
	hourOfDay int,
	blockRisk float64,
) []float64 {
	s := make([]float64, RLStateSize)
	for i := 0; i < 4 && i < len(rttMs); i++ {
		s[i] = math.Min(rttMs[i]/500.0, 1.0)
	}
	s[4] = recentSuccessRate
	s[5] = recentFailRate
	if dpiDetected {
		s[6] = 1.0
	}
	s[7] = math.Min(anomalyScore, 1.0)
	s[8] = math.Sin(2 * math.Pi * float64(hourOfDay) / 24.0)
	s[9] = math.Cos(2 * math.Pi * float64(hourOfDay) / 24.0)
	s[10] = blockRisk
	return s
}

func (a *RLTransportAgent) SelectTransport(state []float64) (transport string, actionIdx int, explored bool) {
	a.mu.RLock()
	eps := a.epsilon
	temp := a.temperature
	qvals := a.qNet.Forward(state)
	a.mu.RUnlock()

	if mrand.Float64() < eps {
		idx := mrand.Intn(len(a.transportNames))
		return a.transportNames[idx], idx, true
	}

	best := boltzmannSample(qvals, temp)
	if best < len(a.transportNames) {
		return a.transportNames[best], best, false
	}
	return a.transportNames[0], 0, false
}

func ComputeReward(success bool, latencyMs float64) float64 {
	if !success {
		return -1.0
	}
	latencyBonus := math.Max(0, 1.0-latencyMs/2000.0)
	return 0.5 + 0.5*latencyBonus
}

func (a *RLTransportAgent) RecordExperience(state []float64, action int, reward float64, nextState []float64, done bool) {
	a.mu.Lock()
	a.prb.Add(Experience{
		State:     state,
		Action:    action,
		Reward:    reward,
		NextState: nextState,
		Done:      done,
	})
	step := atomic.AddInt64(&a.stepCount, 1)
	a.epsilon = math.Max(RLEpsilonMin, a.epsilon*RLEpsilonDecay)
	a.mu.Unlock()

	if step%RLTrainEvery == 0 {
		go a.trainStep()
	}

	if step%RLTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLTransportAgent) trainStep() {
	a.mu.Lock()
	batch, idxs, ok := a.prb.Sample(RLBatchSize)
	if !ok {
		a.mu.Unlock()
		return
	}

	const lr = 0.005
	for i, exp := range batch {
		if exp.Action >= RLActionSize {
			continue
		}
		acts := a.qNet.ForwardActivations(exp.State)
		qvals := acts[len(acts)-1]

		var targetQ float64
		if exp.Done {
			targetQ = exp.Reward
		} else {
			nextQ := a.target.Forward(exp.NextState)
			maxNextQ := nextQ[0]
			for _, q := range nextQ[1:] {
				if q > maxNextQ {
					maxNextQ = q
				}
			}
			bonus := defaultEntropyCoeff * entropy(softmaxVec(nextQ))
			targetQ = exp.Reward + RLGamma*(maxNextQ+bonus)
		}

		tdErr := targetQ - qvals[exp.Action]
		a.prb.UpdatePriority(idxs[i], tdErr)

		dOutput := make([]float64, RLActionSize)
		dOutput[exp.Action] = -tdErr
		dqnBackpropAdam(a.qNet, a.adam, acts, dOutput, lr)

		if a.worldNet != nil && exp.Action < len(a.worldNet.Layers[len(a.worldNet.Layers)-1].B) {
			wActs := a.worldNet.ForwardActivations(exp.State)
			wvals := wActs[len(wActs)-1]
			dW := make([]float64, len(wvals))
			dW[exp.Action] = wvals[exp.Action] - exp.Reward
			dqnBackpropAdam(a.worldNet, a.worldAdam, wActs, dW, lr)
		}
	}

	a.temperature = math.Max(MinTemp, a.temperature*TempDecay)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	a.mu.Unlock()

	if cnt%100 == 0 {
		a.mu.Lock()
		a.savePolicyLocked()
		a.mu.Unlock()
	} else if cnt%20 == 0 {
	}
}

func (a *RLTransportAgent) PreSeed() {
	a.mu.Lock()
	defer a.mu.Unlock()

	priors := map[string]float64{
		"tcp": 0.3, "h2c": 0.5, "quic": 0.4, "tuic": 0.55, "websocket": 0.6, "grpc": 0.6,
		"httpupgrade": 0.55, "splithttp": 0.6, "shadowtls": 0.7, "shadowsocks": 0.55,
		"obfs4": 0.7, "meek": 0.55, "snowflake": 0.6, "torsocks": 0.4, "domainfront": 0.75,
		"mtproto": 0.6, "mirage": 0.6, "asn_bypass": 0.7, "vkwebrtc": 0.8, "okwebrtc": 0.75,
		"yatelemost": 0.7, "yadisk": 0.7, "yacloud": 0.65, "vkbot": 0.5, "tgbot": 0.5, "cdnworker": 0.75,
	}

	conditions := [][4]float64{
		{50, 30, 40, 60},
		{200, 150, 300, 400},
		{9999, 100, 80, 90},
		{9999, 9999, 9999, 9999},
	}

	for _, rtt := range conditions {
		dpiDetected := rtt[0] > 5000 && rtt[1] < 1000
		blockRisk := 0.0
		if dpiDetected {
			blockRisk = 0.7
		}

		state := make([]float64, RLStateSize)
		for i := 0; i < 4; i++ {
			state[i] = math.Min(rtt[i]/500.0, 1.0)
		}
		state[4] = 0.5
		state[5] = 0.5
		if dpiDetected {
			state[6] = 1.0
		}
		state[10] = blockRisk

		for name, baseReward := range priors {
			idx, ok := a.transportIndex[name]
			if !ok {
				continue
			}
			reward := baseReward
			if dpiDetected {
				switch name {
				case "shadowtls", "vkwebrtc", "okwebrtc", "domainfront", "cdnworker", "asn_bypass":
					reward = math.Min(reward+0.2, 1.0)
				case "tcp", "quic", "h2c":
					reward = math.Max(reward-0.4, -1.0)
				}
			}
			if rtt[0] > 5000 && rtt[1] > 5000 {
				reward = -0.8
			}

			reward += (mrand.Float64() - 0.5) * 0.1

			nextState := make([]float64, RLStateSize)
			copy(nextState, state)

			a.prb.Add(Experience{
				State:     state,
				Action:    idx,
				Reward:    reward,
				NextState: nextState,
				Done:      true,
			})
			atomic.AddInt64(&a.stepCount, 1)
		}
	}

	for i := 0; i < 20; i++ {
		batch, idxs, ok := a.prb.Sample(RLBatchSize)
		if !ok {
			break
		}
		for j, exp := range batch {
			acts := a.qNet.ForwardActivations(exp.State)
			qvals := acts[len(acts)-1]

			var targetQ float64
			if exp.Done {
				targetQ = exp.Reward
			} else {
				nextQ := a.target.Forward(exp.NextState)
				maxNextQ := nextQ[0]
				for _, q := range nextQ[1:] {
					if q > maxNextQ {
						maxNextQ = q
					}
				}
				targetQ = exp.Reward + RLGamma*maxNextQ
			}
			tdErr := targetQ - qvals[exp.Action]
			a.prb.UpdatePriority(idxs[j], tdErr)
			dOut := make([]float64, RLActionSize)
			dOut[exp.Action] = -tdErr
			dqnBackpropAdam(a.qNet, a.adam, acts, dOut, 0.001)
		}
	}

	a.target = gnet.Clone(a.qNet)
}

func (a *RLTransportAgent) TransportIndex(name string) int {
	if idx, ok := a.transportIndex[name]; ok {
		return idx
	}
	return -1
}

func (a *RLTransportAgent) Stats() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return map[string]interface{}{
		"epsilon":     a.epsilon,
		"step_count":  atomic.LoadInt64(&a.stepCount),
		"train_count": atomic.LoadInt64(&a.trainCount),
		"buffer_size": a.prb.Size(),
	}
}

type rlPolicyState struct {
	Version int             `json:"v"`
	Layers  []gnet.LayerDef `json:"layers"`
	Epsilon float64         `json:"epsilon"`
	Steps   int64           `json:"steps"`
}

func (a *RLTransportAgent) savePolicyLocked() {
	if a.modelDir == "" {
		return
	}
	state := rlPolicyState{
		Version: rlPolicyVersion,
		Layers:  a.qNet.Layers,
		Epsilon: a.epsilon,
		Steps:   atomic.LoadInt64(&a.stepCount),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	os.MkdirAll(a.modelDir, 0700)
	os.WriteFile(filepath.Join(a.modelDir, "rl_policy.json"), data, 0600)
}

func (a *RLTransportAgent) loadPolicy() bool {
	if a.modelDir == "" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(a.modelDir, "rl_policy.json"))
	if err != nil {
		return false
	}
	var state rlPolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		return false
	}
	if state.Version == rlPolicyVersion && validLayers(state.Layers, RLStateSize, RLActionSize) {
		loaded := &gnet.GorgoniaNet{Layers: state.Layers}
		a.mu.Lock()
		a.qNet = loaded
		a.target = gnet.Clone(loaded)
		a.epsilon = state.Epsilon
		atomic.StoreInt64(&a.stepCount, state.Steps)
		a.mu.Unlock()
		return true
	}
	return false
}
