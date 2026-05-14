package ml

import (
	"math"
	mrand "math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
	"whispera/internal/obfuscation/ml/gnet"
)

var srvLog = logger.Module("rl-server")

const (
	srvMaxServers  = 8  // максимальный размер пула серверов
	srvStateSize   = 10 // rtt[0..7]_norm + hour_sin + hour_cos
	srvHidden1     = 16
	srvHidden2     = 8
	srvNumActions  = srvMaxServers
	srvBufferSize  = 400
	srvBatchSize   = 8
	srvGamma       = 0.95
	srvEpsilonStart = 0.50
	srvEpsilonMin  = 0.05
	srvEpsilonDecay = 0.97
	srvTargetSync  = 20
	srvTrainEvery  = 4
)

// ServerProbe — результат одного измерения задержки до сервера.
type ServerProbe struct {
	Addr    string
	Latency time.Duration // math.MaxInt64 если недостижим
}

// RLServerAgent выбирает сервер из пула на основе исторических данных.
//
// State (10): нормированные RTT для 8 слотов (0 если слот пуст) + hour_sin + hour_cos
// Actions: выбор слота 0..7 (ограничено реальным числом серверов)
// Reward: −rtt_norm (чем быстрее, тем лучше) или −1 при отказе
//
// Агент учится, что «самый быстрый пинг» не всегда лучший (если сервер нестабилен).
type RLServerAgent struct {
	mu sync.RWMutex

	qNet   *gnet.GorgoniaNet
	target *gnet.GorgoniaNet

	buffer  []Experience
	bufIdx  int
	bufFull bool

	epsilon    float64
	stepCount  int64
	trainCount int64

	pendingState  []float64
	pendingAction int

	// последние зонды (обновляются при каждом Connect)
	lastProbes []ServerProbe
}

func NewRLServerAgent() *RLServerAgent {
	a := &RLServerAgent{
		buffer:        make([]Experience, srvBufferSize),
		epsilon:       srvEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{srvStateSize, srvHidden1, srvHidden2, srvNumActions})
	a.target = gnet.Clone(a.qNet)
	return a
}

func (a *RLServerAgent) encodeState(probes []ServerProbe) []float64 {
	s := make([]float64, srvStateSize)
	const maxRTT = 500.0 // мс
	for i := 0; i < srvMaxServers && i < len(probes); i++ {
		ms := float64(probes[i].Latency.Milliseconds())
		if probes[i].Latency == math.MaxInt64 || ms > maxRTT*10 {
			s[i] = 1.0 // недостижим
		} else {
			s[i] = math.Min(ms/maxRTT, 1.0)
		}
	}
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[srvMaxServers] = math.Sin(2 * math.Pi * hour / 24.0)
	s[srvMaxServers+1] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

// Decide выбирает индекс сервера из отсортированного по RTT списка probes.
// Возвращает "" если список пуст.
func (a *RLServerAgent) Decide(probes []ServerProbe) string {
	if len(probes) == 0 {
		return ""
	}

	// Сортируем по RTT (недостижимые — в конец).
	sorted := make([]ServerProbe, len(probes))
	copy(sorted, probes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Latency < sorted[j].Latency
	})

	state := a.encodeState(sorted)

	a.mu.Lock()
	defer a.mu.Unlock()

	a.lastProbes = sorted

	n := len(sorted)
	if n > srvMaxServers {
		n = srvMaxServers
	}

	var idx int
	if mrand.Float64() < a.epsilon {
		idx = mrand.Intn(n)
	} else {
		idx = dqnArgmax(a.qNet, state, n)
	}
	if idx >= n {
		idx = 0
	}

	a.pendingState = state
	a.pendingAction = idx
	chosen := sorted[idx]
	srvLog.Info("pick[%d]=%s rtt=%v eps=%.2f steps=%d (pool=%d servers)",
		idx, chosen.Addr, chosen.Latency, a.epsilon, atomic.LoadInt64(&a.stepCount), n)
	return chosen.Addr
}

// RecordOutcome фиксирует результат подключения к выбранному серверу.
// success=true + latencyMs — успешное соединение; false — отказ.
func (a *RLServerAgent) RecordOutcome(success bool, latencyMs float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	var reward float64
	if success {
		reward = 1.0 - math.Min(latencyMs/500.0, 1.0)
	} else {
		reward = -1.0
	}
	srvLog.Info("outcome: success=%v reward=%.2f latency=%.0fms eps→%.3f",
		success, reward, latencyMs, a.epsilon*srvEpsilonDecay)

	a.mu.Lock()
	a.buffer[a.bufIdx] = Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: !success,
	}
	a.bufIdx = (a.bufIdx + 1) % srvBufferSize
	if a.bufIdx == 0 {
		a.bufFull = true
	}
	a.epsilon = math.Max(srvEpsilonMin, a.epsilon*srvEpsilonDecay)
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	if step%srvTrainEvery == 0 {
		go a.trainStep()
	}
	if step%srvTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLServerAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLServerAgent) trainStep() {
	a.mu.RLock()
	batch, ok := sampleBatch(a.buffer, a.bufIdx, a.bufFull, srvBatchSize)
	a.mu.RUnlock()
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	dqnTrainBatch(a.qNet, a.target, batch, srvNumActions, srvGamma, 0.001)
	cnt := atomic.AddInt64(&a.trainCount, 1)
	if cnt%10 == 0 {
		srvLog.Debug("train#%d eps=%.3f steps=%d", cnt, a.epsilon, atomic.LoadInt64(&a.stepCount))
	}
}
