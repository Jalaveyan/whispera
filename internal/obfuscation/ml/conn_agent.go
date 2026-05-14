package ml

import (
	"fmt"
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
	"whispera/internal/obfuscation/ml/gnet"
)

var connLog = logger.Module("rl-conn")

// ConnAction — действие агента управления пулом соединений.
type ConnAction int

const (
	ConnActionKeep      ConnAction = 0 // ничего не делать
	ConnActionOpen      ConnAction = 1 // открыть новое соединение
	ConnActionCloseWorst ConnAction = 2 // закрыть худшее соединение (только если pool > 1)
)

func (a ConnAction) String() string {
	switch a {
	case ConnActionKeep:
		return "KEEP"
	case ConnActionOpen:
		return "OPEN"
	case ConnActionCloseWorst:
		return "CLOSE_WORST"
	default:
		return "UNKNOWN"
	}
}

const (
	connStateSize    = 6
	connHidden1      = 16
	connHidden2      = 8
	connNumActions   = 3
	connBufferSize   = 500
	connBatchSize    = 8
	connGamma        = 0.95
	connEpsilonStart = 0.30
	connEpsilonMin   = 0.05
	connEpsilonDecay = 0.999
	connTargetSync   = 100
	connTrainEvery   = 4
	connMaxPoolSize  = 5 // нормировочная константа для pool_size_norm
)

// ConnPoolView — снимок состояния пула соединений, передаётся агенту.
type ConnPoolView struct {
	Size       int     // текущий размер пула
	RTTMs      float64 // средний RTT по пулу (мс)
	ErrorRate  float64 // доля ошибочных соединений (0-1)
	MissedKAs  int     // пропущенных keepalive подряд
	CBFailures int     // сбоев circuit breaker
}

// RLConnAgent управляет пулом соединений через DQN.
//
// State (6 признаков):
//
//	pool_size_norm, rtt_norm, error_rate, missedka_norm, hour_sin, hour_cos
//
// Actions: KEEP(0) / OPEN(1) / CLOSE_WORST(2)
// CLOSE_WORST игнорируется если pool.Size <= 1 (constraint: ≥1 соединение).
// Агент не действует если вызывающая сторона сигнализирует disconnected.
type RLConnAgent struct {
	mu sync.RWMutex

	qNet   *gnet.GorgoniaNet
	target *gnet.GorgoniaNet
	adam   *AdamState

	buffer  []Experience
	bufIdx  int
	bufFull bool

	epsilon    float64
	stepCount  int64
	trainCount int64

	pendingState  []float64
	pendingAction int
}

func NewRLConnAgent() *RLConnAgent {
	a := &RLConnAgent{
		buffer:  make([]Experience, connBufferSize),
		epsilon: connEpsilonStart,
	}
	a.qNet = gnet.New([]int{connStateSize, connHidden1, connHidden2, connNumActions})
	a.target = gnet.Clone(a.qNet)
	a.adam = NewAdamState(a.qNet)
	return a
}

// EncodeState строит вектор состояния из снимка пула.
func (a *RLConnAgent) EncodeState(v ConnPoolView) []float64 {
	s := make([]float64, connStateSize)
	s[0] = math.Min(float64(v.Size)/connMaxPoolSize, 1.0)
	s[1] = math.Min(v.RTTMs/500.0, 1.0)
	s[2] = math.Min(v.ErrorRate, 1.0)
	s[3] = math.Min(float64(v.MissedKAs)/5.0, 1.0)
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[4] = math.Sin(2 * math.Pi * hour / 24.0)
	s[5] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

// Decide выбирает действие для пула. poolSize передаётся отдельно для проверки constraint.
func (a *RLConnAgent) Decide(view ConnPoolView) ConnAction {
	state := a.EncodeState(view)

	a.mu.Lock()
	defer a.mu.Unlock()

	var actionIdx int
	var mode string

	if mrand.Float64() < a.epsilon {
		actionIdx = mrand.Intn(connNumActions)
		mode = "explore"
	} else {
		qvals := a.qNet.Forward(state)
		best := 0
		for i := 1; i < connNumActions; i++ {
			if qvals[i] > qvals[best] {
				best = i
			}
		}
		actionIdx = best
		mode = fmt.Sprintf("exploit Q=%.3f", qvals[actionIdx])
	}

	action := ConnAction(actionIdx)

	// Constraint: нельзя закрывать последнее соединение.
	if action == ConnActionCloseWorst && view.Size <= 1 {
		action = ConnActionKeep
		mode += " →KEEP(min1)"
	}

	// Constraint: нет смысла открывать если пул уже максимален.
	if action == ConnActionOpen && view.Size >= connMaxPoolSize {
		action = ConnActionKeep
		mode += " →KEEP(maxpool)"
	}

	connLog.Info("%s → %s (pool=%d eps=%.2f steps=%d train=%d)",
		mode, action, view.Size, a.epsilon,
		atomic.LoadInt64(&a.stepCount), atomic.LoadInt64(&a.trainCount))

	a.pendingState = state
	a.pendingAction = actionIdx
	return action
}

// RecordOutcome записывает результат действия и запускает обучение.
// quality — оценка качества пула после действия (0-1).
func (a *RLConnAgent) RecordOutcome(quality float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()

	if state == nil {
		return
	}

	// Reward: качество пула − штраф за излишние соединения.
	connCountNorm := state[0]
	reward := quality - 0.05*connCountNorm // лёгкий штраф за избыточность
	connLog.Info("outcome: quality=%.3f reward=%.3f eps→%.3f", quality, reward, a.epsilon*connEpsilonDecay)

	a.mu.Lock()
	a.buffer[a.bufIdx] = Experience{
		State:     state,
		Action:    action,
		Reward:    reward,
		NextState: state,
		Done:      quality < 0.1,
	}
	a.bufIdx = (a.bufIdx + 1) % connBufferSize
	if a.bufIdx == 0 {
		a.bufFull = true
	}
	a.epsilon = math.Max(connEpsilonMin, a.epsilon*connEpsilonDecay)
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	if step%connTrainEvery == 0 {
		go a.trainStep()
	}
	if step%connTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLConnAgent) trainStep() {
	a.mu.RLock()
	size := a.bufIdx
	if a.bufFull {
		size = connBufferSize
	}
	if size < connBatchSize*2 {
		a.mu.RUnlock()
		return
	}
	batch := make([]Experience, connBatchSize)
	for i := range batch {
		batch[i] = a.buffer[mrand.Intn(size)]
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()

	dqnTrainBatchAdam(a.qNet, a.target, a.adam, batch, connNumActions, connGamma, 0.001)

	cnt := atomic.AddInt64(&a.trainCount, 1)
	if cnt%10 == 0 {
		connLog.Debug("train#%d eps=%.3f steps=%d", cnt, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
}
