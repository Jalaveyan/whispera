package ml

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
	"whispera/internal/obfuscation/ml/gnet"
)

var sniLog = logger.Module("rl-sni")

const (
	sniStateSize    = 7
	sniHidden1      = 32
	sniHidden2      = 16
	sniBufferSize   = 1000
	sniBatchSize    = 4
	sniGamma        = 0.95
	sniEpsilonStart = 0.40
	sniEpsilonMin   = 0.05
	sniEpsilonDecay = 0.97
	sniTargetSync   = 8
	sniTrainEvery   = 1
	maxSNIPoolSize  = 256 // максимальный размер пула доменов

	sniQWeight     = 0.6
	sniWorldWeight = 0.4
)

// RLSNIAgent выбирает SNI-домены через DQN + world model.
//
// State (7 признаков): rtt_norm, success_rate, fail_rate, dpi_flag,
//
//	hour_sin, hour_cos, block_risk
//
// Actions: индексы в текущем пуле доменов.
// Сохраняется в <modelDir>/rl_sni_policy.json.
type RLSNIAgent struct {
	mu sync.RWMutex

	pool      []string
	qNet      *gnet.GorgoniaNet
	target    *gnet.GorgoniaNet
	worldNet  *gnet.GorgoniaNet
	adam      *AdamState
	worldAdam *AdamState

	prb        *PrioritizedReplayBuffer
	thompson   *ThompsonSampler
	sticky     StickyExplorer
	curriculum CurriculumTracker
	diversity  DiversityTracker
	temperature float64

	epsilon    float64
	stepCount  int64
	trainCount int64
	modelDir   string

	pendingState  []float64
	pendingAction int

	consecutiveFails int32
	rotateSignal     int32
}

type sniPolicyState struct {
	Layers      []gnet.LayerDef `json:"layers"`
	WorldLayers []gnet.LayerDef `json:"world_layers,omitempty"`
	Pool        []string        `json:"pool"`
	Epsilon     float64         `json:"epsilon"`
	Steps       int64           `json:"steps"`
}

func NewRLSNIAgent(modelDir string, pool []string) *RLSNIAgent {
	if len(pool) == 0 {
		pool = sniDefaultPool()
	}
	n := len(pool)
	if n > maxSNIPoolSize {
		n = maxSNIPoolSize
		pool = pool[:n]
	}
	a := &RLSNIAgent{
		pool:          pool,
		prb:           NewPrioritizedBuffer(sniBufferSize),
		thompson:      NewThompsonSampler(maxSNIPoolSize),
		sticky:        StickyExplorer{K: 3},
		curriculum:    NewCurriculumTracker(20, 0.0),
		diversity:     NewDiversityTracker(maxSNIPoolSize, 0.03),
		temperature:   InitTemp,
		epsilon:       sniEpsilonStart,
		modelDir:      modelDir,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{sniStateSize, sniHidden1, sniHidden2, n})
	a.target = gnet.Clone(a.qNet)
	a.worldNet = gnet.New([]int{sniStateSize, sniHidden1, sniHidden2, n})
	a.adam = NewAdamState(a.qNet)
	a.worldAdam = NewAdamState(a.worldNet)
	a.load(pool)
	return a
}

// SetPool обновляет список доменов. Если размер пула изменился — сети пересоздаются.
// Максимум maxSNIPoolSize доменов.
func (a *RLSNIAgent) SetPool(pool []string) {
	if len(pool) == 0 {
		return
	}
	if len(pool) > maxSNIPoolSize {
		pool = pool[:maxSNIPoolSize]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(pool) == len(a.pool) {
		a.pool = pool
		return
	}
	// Сохраняем веса скрытых слоёв, добавляем нули для новых действий.
	oldQLayers := a.qNet.Layers
	oldWLayers := a.worldNet.Layers
	newQ := gnet.New([]int{sniStateSize, sniHidden1, sniHidden2, len(pool)})
	newW := gnet.New([]int{sniStateSize, sniHidden1, sniHidden2, len(pool)})
	for i := 0; i < len(oldQLayers)-1 && i < len(newQ.Layers)-1; i++ {
		if len(oldQLayers[i].W) == len(newQ.Layers[i].W) {
			copy(newQ.Layers[i].W, oldQLayers[i].W)
			copy(newQ.Layers[i].B, oldQLayers[i].B)
		}
		if len(oldWLayers[i].W) == len(newW.Layers[i].W) {
			copy(newW.Layers[i].W, oldWLayers[i].W)
			copy(newW.Layers[i].B, oldWLayers[i].B)
		}
	}
	a.pool = pool
	a.qNet = newQ
	a.target = gnet.Clone(newQ)
	a.worldNet = newW
	a.adam = NewAdamState(newQ)
	a.worldAdam = NewAdamState(newW)
}

// StartAutoFetch запускает фоновую горутину, которая каждые 24ч скачивает
// список доменов (plain-text, один домен на строку) и добавляет их в пул.
func (a *RLSNIAgent) StartAutoFetch(domainsURL string) {
	go func() {
		a.fetchAndUpdatePool(domainsURL)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			a.fetchAndUpdatePool(domainsURL)
		}
	}()
}

func (a *RLSNIAgent) fetchAndUpdatePool(url string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		sniLog.Warn("auto-fetch domains failed: %v", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var fetched []string
	for _, line := range strings.Split(string(body), "\n") {
		d := strings.TrimSpace(line)
		if d != "" && !strings.HasPrefix(d, "#") {
			fetched = append(fetched, d)
		}
	}
	if len(fetched) == 0 {
		return
	}

	a.mu.Lock()
	existing := make(map[string]bool, len(a.pool))
	for _, d := range a.pool {
		existing[d] = true
	}
	oldLen := len(a.pool)
	newPool := append([]string{}, a.pool...)
	for _, d := range fetched {
		if !existing[d] && len(newPool) < maxSNIPoolSize {
			newPool = append(newPool, d)
		}
	}
	a.mu.Unlock()

	if len(newPool) > oldLen {
		a.SetPool(newPool)
		sniLog.Info("auto-fetch: pool updated %d → %d domains", oldLen, len(newPool))
	}
}

// EncodeState строит вектор состояния из доступных метрик.
func (a *RLSNIAgent) EncodeState(rttMs float64, successRate, failRate float64, dpiDetected bool, blockRisk float64) []float64 {
	s := make([]float64, sniStateSize)
	s[0] = math.Min(rttMs/500.0, 1.0)
	s[1] = successRate
	s[2] = failRate
	if dpiDetected {
		s[3] = 1.0
	}
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[4] = math.Sin(2 * math.Pi * hour / 24.0)
	s[5] = math.Cos(2 * math.Pi * hour / 24.0)
	s[6] = math.Min(blockRisk, 1.0)
	return s
}

// Select выбирает SNI-домен.
func (a *RLSNIAgent) Select(state []float64) (domain string, actionIdx int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pool := a.pool
	if len(pool) == 0 {
		return "", -1
	}
	if atomic.LoadInt64(&a.stepCount) < 10 {
		a.pendingState = nil
		a.pendingAction = -1
		idx := mrand.Intn(len(pool))
		sniLog.Info("warmup → %s (pool=%d)", pool[idx], len(pool))
		return pool[idx], idx
	}

	n := len(pool)
	var idx int
	var mode string

	if stickyIdx, exploring := a.sticky.Explore(a.epsilon, n); exploring {
		idx = stickyIdx
		if idx >= n {
			idx = mrand.Intn(n)
		}
		mode = "explore-sticky"
	} else {
		qvals := a.qNet.Forward(state)
		wvals := a.worldNet.Forward(state)
		if mrand.Float64() < 0.30 {
			// Thompson restricted to current pool.
			bestTheta := -1e9
			idx = 0
			for i := 0; i < n && i < len(a.thompson.alpha); i++ {
				theta := betaSample(a.thompson.alpha[i], a.thompson.beta[i])
				if theta > bestTheta {
					bestTheta = theta
					idx = i
				}
			}
			mode = "thompson"
		} else {
			// Boltzmann over combined Q+W scores.
			scores := make([]float64, n)
			for i := 0; i < n && i < len(qvals) && i < len(wvals); i++ {
				scores[i] = sniQWeight*qvals[i] + sniWorldWeight*wvals[i]
			}
			idx = boltzmannSample(scores, a.temperature)
			mode = fmt.Sprintf("boltzmann Q=%.3f W=%.3f", qvals[idx], wvals[idx])
		}
	}

	sniLog.Info("%s → %s (eps=%.2f temp=%.2f pool=%d steps=%d train=%d)",
		mode, pool[idx], a.epsilon, a.temperature, n,
		atomic.LoadInt64(&a.stepCount), atomic.LoadInt64(&a.trainCount))

	a.pendingState = state
	a.pendingAction = idx
	return pool[idx], idx
}

// RecordOutcome записывает результат последнего Select и запускает обучение.
func (a *RLSNIAgent) RecordOutcome(success bool, latencyMs float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()

	if state == nil || action < 0 {
		return
	}

	reward := ComputeReward(success, latencyMs)
	sniLog.Info("outcome: success=%v reward=%.2f latency=%.0fms", success, reward, latencyMs)

	if success {
		atomic.StoreInt32(&a.consecutiveFails, 0)
	} else {
		fails := atomic.AddInt32(&a.consecutiveFails, 1)
		if fails >= 3 {
			atomic.StoreInt32(&a.rotateSignal, 1)
			sniLog.Warn("rotate signal: %d consecutive failures — triggering SNI rotation", fails)
		}
	}

	a.mu.Lock()
	divBonus := a.diversity.Record(action)
	reward += divBonus
	if a.curriculum.Add(reward) {
		a.epsilon = math.Min(sniEpsilonStart, a.epsilon*2)
	} else {
		a.epsilon = math.Max(sniEpsilonMin, a.epsilon*sniEpsilonDecay)
	}
	a.thompson.Update(action, reward)
	a.prb.Add(Experience{
		State:     state,
		Action:    action,
		Reward:    reward,
		NextState: state,
		Done:      !success,
	})
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	if step%sniTrainEvery == 0 {
		go a.trainStep()
	}
	if step%sniTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

// Epsilon возвращает текущее значение epsilon.
func (a *RLSNIAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

// ShouldRotate возвращает true и сбрасывает флаг, если агент решил что нужна ротация SNI.
func (a *RLSNIAgent) ShouldRotate() bool {
	return atomic.CompareAndSwapInt32(&a.rotateSignal, 1, 0)
}

func (a *RLSNIAgent) trainStep() {
	a.mu.Lock()
	batch, idxs, ok := a.prb.Sample(sniBatchSize)
	if !ok {
		a.mu.Unlock()
		return
	}

	const lr = 0.005
	outSize := len(a.qNet.Layers[len(a.qNet.Layers)-1].B)
	wOutSize := len(a.worldNet.Layers[len(a.worldNet.Layers)-1].B)

	for i, exp := range batch {
		if exp.Action >= outSize {
			continue
		}

		// Q-сеть: Bellman update с энтропийным бонусом.
		qActs := a.qNet.ForwardActivations(exp.State)
		qvals := qActs[len(qActs)-1]

		var targetQ float64
		if exp.Done {
			targetQ = exp.Reward
		} else {
			nextQ := a.target.Forward(exp.NextState)
			maxQ := nextQ[0]
			for _, q := range nextQ[1:] {
				if q > maxQ {
					maxQ = q
				}
			}
			bonus := defaultEntropyCoeff * entropy(softmaxVec(nextQ))
			targetQ = exp.Reward + sniGamma*(maxQ+bonus)
		}

		tdErr := targetQ - qvals[exp.Action]
		a.prb.UpdatePriority(idxs[i], tdErr)

		dQ := make([]float64, outSize)
		dQ[exp.Action] = -tdErr
		dqnBackpropAdam(a.qNet, a.adam, qActs, dQ, lr)

		// World model: прямой MSE на наблюдаемый reward.
		if exp.Action >= wOutSize {
			continue
		}
		wActs := a.worldNet.ForwardActivations(exp.State)
		wvals := wActs[len(wActs)-1]

		dW := make([]float64, wOutSize)
		dW[exp.Action] = wvals[exp.Action] - exp.Reward
		dqnBackpropAdam(a.worldNet, a.worldAdam, wActs, dW, lr)
	}

	a.temperature = math.Max(MinTemp, a.temperature*TempDecay)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	temp := a.temperature
	eps := a.epsilon
	a.mu.Unlock()

	if cnt%50 == 0 {
		sniLog.Info("train#%d eps=%.3f temp=%.3f steps=%d (saving policy)", cnt, eps, temp, atomic.LoadInt64(&a.stepCount))
		a.mu.Lock()
		a.saveLocked()
		a.mu.Unlock()
	} else if cnt%10 == 0 {
		sniLog.Debug("train#%d eps=%.3f temp=%.3f steps=%d", cnt, eps, temp, atomic.LoadInt64(&a.stepCount))
	}
}

func (a *RLSNIAgent) load(pool []string) {
	if a.modelDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(a.modelDir, "rl_sni_policy.json"))
	if err != nil {
		return
	}
	var st sniPolicyState
	if json.Unmarshal(data, &st) != nil || len(st.Layers) == 0 {
		return
	}
	if st.Layers[len(st.Layers)-1].OutSize != len(pool) {
		return
	}
	a.mu.Lock()
	a.qNet = &gnet.GorgoniaNet{Layers: st.Layers}
	a.target = gnet.Clone(a.qNet)
	if len(st.WorldLayers) > 0 && st.WorldLayers[len(st.WorldLayers)-1].OutSize == len(pool) {
		a.worldNet = &gnet.GorgoniaNet{Layers: st.WorldLayers}
	}
	a.adam = NewAdamState(a.qNet)
	a.worldAdam = NewAdamState(a.worldNet)
	a.epsilon = st.Epsilon
	atomic.StoreInt64(&a.stepCount, st.Steps)
	a.mu.Unlock()
	sniLog.Info("loaded policy (steps=%d eps=%.3f world=%v)", st.Steps, st.Epsilon, len(st.WorldLayers) > 0)
}

func (a *RLSNIAgent) saveLocked() {
	if a.modelDir == "" {
		return
	}
	st := sniPolicyState{
		Layers:      a.qNet.Layers,
		WorldLayers: a.worldNet.Layers,
		Pool:        a.pool,
		Epsilon:     a.epsilon,
		Steps:       atomic.LoadInt64(&a.stepCount),
	}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = os.MkdirAll(a.modelDir, 0700)
	_ = os.WriteFile(filepath.Join(a.modelDir, "rl_sni_policy.json"), data, 0600)
}

func sniDefaultPool() []string {
	return []string{
		"kion.ru", "rutube.ru", "vk.com", "ok.ru", "dzen.ru",
		"music.yandex.ru", "cloud.mail.ru", "premier.one",
		"wink.ru", "ivi.ru", "start.ru", "more.tv",
	}
}
