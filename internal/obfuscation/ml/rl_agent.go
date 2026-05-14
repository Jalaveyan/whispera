package ml

import (
	"encoding/json"
	"math"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"whispera/internal/logger"
	"whispera/internal/obfuscation/ml/gnet"
)

var trLog = logger.Module("rl-transport")


const (
	RLStateSize    = 16
	RLActionSize   = 28
	RLHidden1      = 64
	RLHidden2      = 32
	RLBufferSize   = 200
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
	worldNet  *gnet.GorgoniaNet // world model: прямое предсказание reward
	adam      *AdamState
	worldAdam *AdamState
	buffer    []Experience
	bufIdx    int
	bufFull   bool

	epsilon    float64
	stepCount  int64
	trainCount int64

	transportNames []string
	transportIndex map[string]int

	// активный пул: подмножество transportNames, реально доступных в данный момент
	activePool []string

	// для RecordOutcome / ShouldRotate
	pendingState     []float64
	pendingAction    int
	consecutiveFails int32
	rotateSignal     int32

	modelDir string
}

func NewRLTransportAgent(modelDir string, _ []string) *RLTransportAgent {
	agent := &RLTransportAgent{
		qNet:       gnet.New([]int{RLStateSize, RLHidden1, RLHidden2, RLActionSize}),
		buffer:     make([]Experience, RLBufferSize),
		epsilon:    RLEpsilonStart,
		modelDir:   modelDir,
		transportNames: []string{
			"tcp", "udp", "h2c", "shadowtls", "ws", "wss",
			"grpc", "quic", "kcp", "obfs4", "meek",
			"utls", "reality", "vless", "vmess", "trojan",
			"hysteria", "hysteria2", "tuic", "ssh", "wireguard",
			"cdn-ws", "cdn-grpc", "fragment", "tlsfrag",
			"vkvideo", "okhttp", "doh",
		},
		transportIndex: make(map[string]int),
	}
	for i, name := range agent.transportNames {
		agent.transportIndex[name] = i
	}
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

// SetActivePool ограничивает выбор транспортов реально доступными в данном соединении.
// Вызывается из buildCandidates после фильтрации по конфигу.
func (a *RLTransportAgent) SetActivePool(names []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(names) == 0 {
		a.activePool = a.transportNames
		return
	}
	a.activePool = names
}

// Select выбирает транспорт из activePool (epsilon-greedy + world model thinking).
// Возвращает ("", -1) если агент ещё не обучен (< 20 шагов) — tunnel использует дефолт.
func (a *RLTransportAgent) Select(state []float64) (transport string, actionIdx int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pool := a.activePool
	if len(pool) == 0 {
		return "", -1
	}
	if atomic.LoadInt64(&a.stepCount) < 10 {
		return "", -1
	}

	var idx int
	var mode string
	if mrand.Float64() < a.epsilon {
		name := pool[mrand.Intn(len(pool))]
		idx = a.transportIndex[name]
		mode = "explore"
	} else {
		qvals := a.qNet.Forward(state)
		wvals := a.worldNet.Forward(state)
		bestName := pool[0]
		bestScore := -1e9
		for _, name := range pool {
			i, ok := a.transportIndex[name]
			if !ok || i >= len(qvals) {
				continue
			}
			score := 0.6*qvals[i] + 0.4*wvals[i]
			if score > bestScore {
				bestScore = score
				bestName = name
				idx = i
			}
		}
		_ = bestName
		mode = "think"
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

	trLog.Info("%s → %s (eps=%.2f steps=%d)", mode, name, a.epsilon, atomic.LoadInt64(&a.stepCount))

	a.pendingState = state
	a.pendingAction = idx
	return name, idx
}

// RecordOutcome записывает результат последнего Select и обучает сеть.
func (a *RLTransportAgent) RecordOutcome(success bool, latencyMs float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()

	if state == nil || action < 0 {
		return
	}

	reward := ComputeReward(success, latencyMs)
	trLog.Info("outcome: success=%v reward=%.2f latency=%.0fms eps→%.3f",
		success, reward, latencyMs, a.epsilon*RLEpsilonDecay)

	if success {
		atomic.StoreInt32(&a.consecutiveFails, 0)
	} else {
		fails := atomic.AddInt32(&a.consecutiveFails, 1)
		if fails >= 3 {
			atomic.StoreInt32(&a.rotateSignal, 1)
			trLog.Warn("rotate signal: %d consecutive transport failures — switching transport", fails)
		}
	}

	nextState := make([]float64, len(state))
	copy(nextState, state)
	a.RecordExperience(state, action, reward, nextState, !success)
}

// ShouldRotate возвращает true и сбрасывает флаг если нужно сменить транспорт.
func (a *RLTransportAgent) ShouldRotate() bool {
	return atomic.CompareAndSwapInt32(&a.rotateSignal, 1, 0)
}

// Epsilon возвращает текущий epsilon для диагностики.
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
	a.mu.RUnlock()

	if mrand.Float64() < eps {
		idx := mrand.Intn(len(a.transportNames))
		return a.transportNames[idx], idx, true
	}

	a.mu.RLock()
	qvals := a.qNet.Forward(state)
	a.mu.RUnlock()

	best := 0
	for i := 1; i < len(qvals); i++ {
		if qvals[i] > qvals[best] {
			best = i
		}
	}
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
	a.buffer[a.bufIdx] = Experience{
		State:     state,
		Action:    action,
		Reward:    reward,
		NextState: nextState,
		Done:      done,
	}
	a.bufIdx = (a.bufIdx + 1) % RLBufferSize
	if a.bufIdx == 0 {
		a.bufFull = true
	}
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	a.mu.Lock()
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
	a.mu.RLock()
	size := a.bufIdx
	if a.bufFull {
		size = RLBufferSize
	}
	if size < RLBatchSize*2 {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	batch := make([]Experience, RLBatchSize)
	a.mu.RLock()
	for i := 0; i < RLBatchSize; i++ {
		idx := mrand.Intn(size)
		batch[i] = a.buffer[idx]
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()

	const lr = 0.005

	for _, exp := range batch {
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

		dOutput := make([]float64, RLActionSize)
		dOutput[exp.Action] = -(targetQ - qvals[exp.Action])
		dqnBackpropAdam(a.qNet, a.adam, acts, dOutput, lr)

		// World model: MSE на наблюдаемый reward
		if a.worldNet != nil && exp.Action < len(a.worldNet.Layers[len(a.worldNet.Layers)-1].B) {
			wActs := a.worldNet.ForwardActivations(exp.State)
			wvals := wActs[len(wActs)-1]
			dW := make([]float64, len(wvals))
			dW[exp.Action] = wvals[exp.Action] - exp.Reward
			dqnBackpropAdam(a.worldNet, a.worldAdam, wActs, dW, lr)
		}
	}

	cnt := atomic.AddInt64(&a.trainCount, 1)

	if cnt%100 == 0 {
		trLog.Info("train#%d eps=%.3f steps=%d (saving policy)", cnt, a.epsilon, atomic.LoadInt64(&a.stepCount))
		a.savePolicyLocked()
	} else if cnt%20 == 0 {
		trLog.Debug("train#%d eps=%.3f steps=%d", cnt, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
}

func (a *RLTransportAgent) PreSeed() {
	a.mu.Lock()
	defer a.mu.Unlock()

	priors := map[string]float64{
		"tcp": 0.3, "udp": 0.2, "h2c": 0.5, "shadowtls": 0.7, "ws": 0.6, "wss": 0.65,
		"grpc": 0.6, "quic": 0.4, "kcp": 0.3, "obfs4": 0.7, "meek": 0.5,
		"utls": 0.6, "reality": 0.8, "vless": 0.7, "vmess": 0.65, "trojan": 0.7,
		"hysteria": 0.6, "hysteria2": 0.65, "tuic": 0.55, "ssh": 0.5, "wireguard": 0.4,
		"cdn-ws": 0.75, "cdn-grpc": 0.75, "fragment": 0.6, "tlsfrag": 0.6,
		"vkvideo": 0.8, "okhttp": 0.5, "doh": 0.6,
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
				case "reality", "shadowtls", "vkvideo", "cdn-ws", "cdn-grpc", "trojan":
					reward = math.Min(reward+0.2, 1.0)
				case "tcp", "udp", "quic":
					reward = math.Max(reward-0.4, -1.0)
				}
			}
			if rtt[0] > 5000 && rtt[1] > 5000 {
				reward = -0.8
			}

			reward += (mrand.Float64() - 0.5) * 0.1

			nextState := make([]float64, RLStateSize)
			copy(nextState, state)

			a.buffer[a.bufIdx] = Experience{
				State:     state,
				Action:    idx,
				Reward:    reward,
				NextState: nextState,
				Done:      reward < 0,
			}
			a.bufIdx = (a.bufIdx + 1) % RLBufferSize
			if a.bufIdx == 0 {
				a.bufFull = true
			}
			atomic.AddInt64(&a.stepCount, 1)
		}
	}

	for i := 0; i < 20; i++ {
		size := a.bufIdx
		if a.bufFull {
			size = RLBufferSize
		}
		if size < RLBatchSize*2 {
			break
		}
		batch := make([]Experience, RLBatchSize)
		for j := 0; j < RLBatchSize; j++ {
			batch[j] = a.buffer[mrand.Intn(size)]
		}
		for _, exp := range batch {
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
			dOut := make([]float64, RLActionSize)
			dOut[exp.Action] = -(targetQ - qvals[exp.Action])
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
	size := a.bufIdx
	if a.bufFull {
		size = RLBufferSize
	}
	return map[string]interface{}{
		"epsilon":     a.epsilon,
		"step_count":  atomic.LoadInt64(&a.stepCount),
		"train_count": atomic.LoadInt64(&a.trainCount),
		"buffer_size": size,
	}
}

type rlPolicyState struct {
	Layers  []gnet.LayerDef `json:"layers"`
	Epsilon float64         `json:"epsilon"`
	Steps   int64           `json:"steps"`
}

func (a *RLTransportAgent) savePolicyLocked() {
	if a.modelDir == "" {
		return
	}
	state := rlPolicyState{
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
	if len(state.Layers) > 0 {
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
