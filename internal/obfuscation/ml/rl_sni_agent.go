package ml

import (
	"encoding/json"
	"fmt"
	"math"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/ml/gnet"
)

var sniLog = func(format string, args ...interface{}) {
	fmt.Printf("[RL-SNI] "+format+"\n", args...)
}

const (
	sniStateSize    = 7
	sniHidden1      = 32
	sniHidden2      = 16
	sniBufferSize   = 1000
	sniBatchSize    = 16
	sniGamma        = 0.95
	sniEpsilonStart = 0.40
	sniEpsilonMin   = 0.05
	sniEpsilonDecay = 0.990
	sniTargetSync   = 30
	sniTrainEvery   = 5
)

// RLSNIAgent выбирает SNI-домены через DQN вместо crypto/rand.
// State (7 признаков): rtt_norm, success_rate, fail_rate, dpi_flag,
//
//	hour_sin, hour_cos, block_risk
//
// Actions: индексы в текущем пуле доменов.
// Сохраняется в <modelDir>/rl_sni_policy.json.
type RLSNIAgent struct {
	mu sync.RWMutex

	pool   []string
	qNet   *gnet.GorgoniaNet
	target *gnet.GorgoniaNet

	buffer  []Experience
	bufIdx  int
	bufFull bool

	epsilon    float64
	stepCount  int64
	trainCount int64
	modelDir   string

	// последнее действие для RecordOutcome
	pendingState  []float64
	pendingAction int

	// agent-driven rotation signal
	consecutiveFails int32 // atomic
	rotateSignal     int32 // atomic: 1 = rotate now
}

type sniPolicyState struct {
	Layers  []gnet.LayerDef `json:"layers"`
	Pool    []string        `json:"pool"`
	Epsilon float64         `json:"epsilon"`
	Steps   int64           `json:"steps"`
}

func NewRLSNIAgent(modelDir string, pool []string) *RLSNIAgent {
	if len(pool) == 0 {
		pool = sniDefaultPool()
	}
	a := &RLSNIAgent{
		pool:     pool,
		buffer:   make([]Experience, sniBufferSize),
		epsilon:  sniEpsilonStart,
		modelDir: modelDir,
	}
	a.qNet = gnet.New([]int{sniStateSize, sniHidden1, sniHidden2, len(pool)})
	a.target = gnet.Clone(a.qNet)
	a.load(pool)
	return a
}

// SetPool обновляет список доменов. Вызывается когда SNI prober добавляет новые домены.
// Если размер пула изменился — сеть пересоздаётся (веса старых действий сохраняются).
func (a *RLSNIAgent) SetPool(pool []string) {
	if len(pool) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(pool) == len(a.pool) {
		a.pool = pool
		return
	}
	// Пул вырос — сохраняем старые веса, добавляем нули для новых действий.
	oldLayers := a.qNet.Layers
	newNet := gnet.New([]int{sniStateSize, sniHidden1, sniHidden2, len(pool)})
	// Копируем веса старых слоёв (кроме выходного) как есть.
	for i := 0; i < len(oldLayers)-1 && i < len(newNet.Layers)-1; i++ {
		if len(oldLayers[i].W) == len(newNet.Layers[i].W) {
			copy(newNet.Layers[i].W, oldLayers[i].W)
			copy(newNet.Layers[i].B, oldLayers[i].B)
		}
	}
	a.pool = pool
	a.qNet = newNet
	a.target = gnet.Clone(newNet)
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

// Select выбирает SNI-домен (epsilon-greedy). Запоминает выбор для RecordOutcome.
func (a *RLSNIAgent) Select(state []float64) (domain string, actionIdx int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pool := a.pool
	if len(pool) == 0 {
		return "", -1
	}

	var idx int
	var mode string
	if mrand.Float64() < a.epsilon {
		idx = mrand.Intn(len(pool))
		mode = "explore"
	} else {
		qvals := a.qNet.Forward(state)
		best := 0
		for i := 1; i < len(qvals) && i < len(pool); i++ {
			if qvals[i] > qvals[best] {
				best = i
			}
		}
		idx = best
		mode = fmt.Sprintf("exploit Q=%.3f", qvals[idx])
	}

	sniLog("%s → %s (eps=%.2f, pool=%d, steps=%d)",
		mode, pool[idx], a.epsilon, len(pool), atomic.LoadInt64(&a.stepCount))

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
	sniLog("outcome: success=%v reward=%.2f latency=%.0fms eps→%.3f",
		success, reward, latencyMs, a.epsilon*sniEpsilonDecay)

	if success {
		atomic.StoreInt32(&a.consecutiveFails, 0)
	} else {
		fails := atomic.AddInt32(&a.consecutiveFails, 1)
		if fails >= 3 {
			atomic.StoreInt32(&a.rotateSignal, 1)
			sniLog("rotate signal: %d consecutive failures — triggering rotation", fails)
		}
	}

	a.mu.Lock()
	a.buffer[a.bufIdx] = Experience{
		State:     state,
		Action:    action,
		Reward:    reward,
		NextState: state,
		Done:      !success,
	}
	a.bufIdx = (a.bufIdx + 1) % sniBufferSize
	if a.bufIdx == 0 {
		a.bufFull = true
	}
	a.epsilon = math.Max(sniEpsilonMin, a.epsilon*sniEpsilonDecay)
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

// Epsilon возвращает текущее значение epsilon (для логов/диагностики).
func (a *RLSNIAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

// ShouldRotate возвращает true и сбрасывает флаг, если агент решил что нужна ротация SNI.
// Вызывается из tunnel.go после каждого неудачного RecordOutcome.
func (a *RLSNIAgent) ShouldRotate() bool {
	return atomic.CompareAndSwapInt32(&a.rotateSignal, 1, 0)
}

func (a *RLSNIAgent) trainStep() {
	a.mu.RLock()
	size := a.bufIdx
	if a.bufFull {
		size = sniBufferSize
	}
	if size < sniBatchSize*2 {
		a.mu.RUnlock()
		return
	}
	batch := make([]Experience, sniBatchSize)
	for i := range batch {
		batch[i] = a.buffer[mrand.Intn(size)]
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()

	const lr = 0.001
	for _, exp := range batch {
		if exp.Action >= len(a.qNet.Layers[len(a.qNet.Layers)-1].B) {
			continue
		}
		layerOut := a.fullForward(exp.State)
		qvals := layerOut[len(layerOut)-1]

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
			targetQ = exp.Reward + sniGamma*maxQ
		}

		dOut := make([]float64, len(qvals))
		dOut[exp.Action] = -(targetQ - qvals[exp.Action])
		a.fullBackprop(layerOut, dOut, lr)
	}

	cnt := atomic.AddInt64(&a.trainCount, 1)
	if cnt%50 == 0 {
		a.saveLocked()
	}
}

func (a *RLSNIAgent) fullForward(input []float64) [][]float64 {
	acts := make([][]float64, len(a.qNet.Layers)+1)
	acts[0] = input
	cur := input
	for i, ld := range a.qNet.Layers {
		out := make([]float64, ld.OutSize)
		for j := 0; j < ld.OutSize; j++ {
			sum := ld.B[j]
			for k := 0; k < ld.InSize && k < len(cur); k++ {
				sum += cur[k] * ld.W[k*ld.OutSize+j]
			}
			if i < len(a.qNet.Layers)-1 && sum < 0 {
				sum = 0
			}
			out[j] = sum
		}
		acts[i+1] = out
		cur = out
	}
	return acts
}

func (a *RLSNIAgent) fullBackprop(acts [][]float64, dOut []float64, lr float64) {
	delta := dOut
	for i := len(a.qNet.Layers) - 1; i >= 0; i-- {
		ld := &a.qNet.Layers[i]
		input := acts[i]
		output := acts[i+1]
		if i < len(a.qNet.Layers)-1 {
			for j := range delta {
				if output[j] <= 0 {
					delta[j] = 0
				}
			}
		}
		var prev []float64
		if i > 0 {
			prev = make([]float64, ld.InSize)
			for k := 0; k < ld.InSize; k++ {
				for j := 0; j < ld.OutSize; j++ {
					prev[k] += ld.W[k*ld.OutSize+j] * delta[j]
				}
			}
		}
		for k := 0; k < ld.InSize && k < len(input); k++ {
			for j := 0; j < ld.OutSize; j++ {
				ld.W[k*ld.OutSize+j] -= lr * delta[j] * input[k]
			}
		}
		for j := 0; j < ld.OutSize; j++ {
			ld.B[j] -= lr * delta[j]
		}
		delta = prev
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
	// Принимаем только если размер выхода совпадает с пулом.
	if st.Layers[len(st.Layers)-1].OutSize != len(pool) {
		return
	}
	a.mu.Lock()
	a.qNet = &gnet.GorgoniaNet{Layers: st.Layers}
	a.target = gnet.Clone(a.qNet)
	a.epsilon = st.Epsilon
	atomic.StoreInt64(&a.stepCount, st.Steps)
	a.mu.Unlock()
}

func (a *RLSNIAgent) saveLocked() {
	if a.modelDir == "" {
		return
	}
	st := sniPolicyState{
		Layers:  a.qNet.Layers,
		Pool:    a.pool,
		Epsilon: a.epsilon,
		Steps:   atomic.LoadInt64(&a.stepCount),
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
