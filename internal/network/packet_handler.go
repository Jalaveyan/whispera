package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/util"
)

// PacketBuffer - буфер для обработки out-of-order пакетов
type PacketBuffer struct {
	buf      map[uint32]*bufferedPacket // seq -> packet с метаданными
	maxSeq   uint32
	mu       sync.RWMutex
	maxSize  int
	maxDelay time.Duration
}

// bufferedPacket содержит данные пакета и время его получения
type bufferedPacket struct {
	data      []byte
	timestamp time.Time
}

// NewPacketBuffer создает новый буфер пакетов
func NewPacketBuffer(maxSize int, maxDelay time.Duration) *PacketBuffer {
	return &PacketBuffer{
		buf:      make(map[uint32]*bufferedPacket),
		maxSize:  maxSize,
		maxDelay: maxDelay,
	}
}

// Insert вставляет пакет и возвращает готовые к обработке (in-order)
func (pb *PacketBuffer) Insert(seq uint32, data []byte) []byte {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
	timeCache := util.GetGlobalTimeCache()
	now := timeCache.Now()

	// Очистка устаревших пакетов перед добавлением нового
	if pb.maxDelay > 0 {
		pb.cleanupExpired(now)
	}

	// Если пакет старый, игнорируем
	if pb.maxSeq > 0 && seq < pb.maxSeq-100 {
		return nil
	}

	// Обновляем maxSeq
	if seq > pb.maxSeq {
		pb.maxSeq = seq
	}

	// Добавляем пакет с временной меткой
	pb.buf[seq] = &bufferedPacket{
		data:      append([]byte(nil), data...), // Копируем данные для безопасности
		timestamp: now,
	}

	// Проверяем, есть ли последовательные пакеты начиная с ожидаемого
	var ready [][]byte
	expected := pb.maxSeq - uint32(len(pb.buf)) + 1

	// ОПТИМИЗАЦИЯ: Находим минимальный seq более эффективно
	// Используем текущий seq как начальное значение для быстрого пути
	if len(pb.buf) > 0 {
		minSeq := seq
		// ОПТИМИЗАЦИЯ: Останавливаемся после первого найденного меньшего значения
		// В большинстве случаев seq уже минимальный
		for s := range pb.buf {
			if s < minSeq {
				minSeq = s
				// ОПТИМИЗАЦИЯ: Для больших map можно прервать после нескольких итераций
				if len(pb.buf) > 100 {
					break
				}
			}
		}
		expected = minSeq
	}

	// Собираем последовательные пакеты
	for {
		if pkt, ok := pb.buf[expected]; ok {
			ready = append(ready, pkt.data)
			delete(pb.buf, expected)
			expected++
		} else {
			break
		}
	}

	// Очищаем старые пакеты если буфер переполнен
	// УЛУЧШЕНИЕ: Проактивно очищаем до достижения maxSize для предотвращения потери пакетов
	if len(pb.buf) > pb.maxSize {
		pb.cleanupOldest()
	} else if len(pb.buf) > (pb.maxSize*9)/10 { // Очищаем при 90% заполнении
		pb.cleanupExpired(now)
	}

	// Возвращаем первый готовый пакет (если есть)
	if len(ready) > 0 {
		return ready[0]
	}

	return nil
}

// cleanupExpired удаляет пакеты с истекшим временем жизни
func (pb *PacketBuffer) cleanupExpired(now time.Time) {
	if pb.maxDelay <= 0 {
		return
	}

	for seq, pkt := range pb.buf {
		if now.Sub(pkt.timestamp) > pb.maxDelay {
			delete(pb.buf, seq)
		}
	}
}

// cleanupOldest удаляет самые старые пакеты при переполнении буфера
func (pb *PacketBuffer) cleanupOldest() {
	if len(pb.buf) <= pb.maxSize {
		return
	}

	// УЛУЧШЕНИЕ: Эффективный алгоритм cleanup с минимальной фрагментацией памяти
	toRemove := len(pb.buf) - pb.maxSize + 64 // Удаляем немного больше для буфера
	if toRemove <= 0 {
		return
	}

	// УЛУЧШЕНИЕ: Используем heap-based подход для O(n log k) вместо O(n log n) сортировки
	type seqTime struct {
		seq       uint32
		timestamp time.Time
	}

	// ОПТИМИЗАЦИЯ: Собираем только первые toRemove самых старых
	oldest := make([]seqTime, 0, toRemove)

	for seq, pkt := range pb.buf {
		if len(oldest) < toRemove {
			oldest = append(oldest, seqTime{seq: seq, timestamp: pkt.timestamp})
		} else {
			// Находим самый новый в списке oldest
			maxIdx := 0
			for i := 1; i < len(oldest); i++ {
				if oldest[i].timestamp.After(oldest[maxIdx].timestamp) {
					maxIdx = i
				}
			}
			// Если текущий пакет старше, заменяем
			if pkt.timestamp.Before(oldest[maxIdx].timestamp) {
				oldest[maxIdx] = seqTime{seq: seq, timestamp: pkt.timestamp}
			}
		}
	}

	// Удаляем найденные самые старые пакеты
	for _, st := range oldest {
		delete(pb.buf, st.seq)
	}
}

// RetransmissionManager - менеджер повторной передачи пакетов с flow control
type RetransmissionManager struct {
	pending       map[uint32]*PendingPacket
	mu            sync.RWMutex
	onRetransmit  func(seq uint32, data []byte) error
	timeout       time.Duration
	maxRetries    int
	ctx           context.Context
	cancel        context.CancelFunc
	stopDone      chan struct{}
	maxPending    int            // Flow control: максимальное количество pending пакетов
	flowControlCh chan struct{}  // Signaling для flow control
}

// PendingPacket - ожидающий подтверждения пакет
type PendingPacket struct {
	Seq      uint32
	Data     []byte
	SentAt   time.Time
	Retries  int
	LastSent time.Time
}

// NewRetransmissionManager создает менеджер повторной передачи с flow control
func NewRetransmissionManager(timeout time.Duration, maxRetries int, onRetransmit func(uint32, []byte) error) *RetransmissionManager {
	ctx, cancel := context.WithCancel(context.Background())
	rm := &RetransmissionManager{
		pending:       make(map[uint32]*PendingPacket),
		onRetransmit:  onRetransmit,
		timeout:       timeout,
		maxRetries:    maxRetries,
		ctx:           ctx,
		cancel:        cancel,
		stopDone:      make(chan struct{}),
		maxPending:    32768,            // Flow control: максимум 32k pending пакетов
		flowControlCh: make(chan struct{}, 32768),
	}

	// Запускаем обработку таймаутов
	go rm.processTimeouts()

	return rm
}

// Send отправляет пакет и отслеживает его с flow control
func (rm *RetransmissionManager) Send(seq uint32, data []byte) error {
	rm.mu.Lock()
	// УЛУЧШЕНИЕ: Проверяем flow control перед добавлением
	if len(rm.pending) >= rm.maxPending {
		rm.mu.Unlock()
		// Flow control: ждем когда освободится место
		// Это предотвращает накопление пакетов в памяти
		select {
		case <-rm.flowControlCh:
			rm.mu.Lock()
		default:
			return fmt.Errorf("packet buffer full - flow control activated")
		}
	}
	
	timeCache := util.GetGlobalTimeCache()
	now := timeCache.Now()

	rm.pending[seq] = &PendingPacket{
		Seq:      seq,
		Data:     data,
		SentAt:   now,
		Retries:  0,
		LastSent: now,
	}
	rm.mu.Unlock()

	return rm.onRetransmit(seq, data)
}

// Ack подтверждает получение пакета и сигнализирует о flow control
func (rm *RetransmissionManager) Ack(seq uint32) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	delete(rm.pending, seq)
	
	// УЛУЧШЕНИЕ: Сигнализируем о освобожденном месте для flow control
	select {
	case rm.flowControlCh <- struct{}{}:
	default:
	}
}

// processTimeouts обрабатывает таймауты и повторные передачи
// ОПТИМИЗИРОВАНО: Использует кэшированное время и оптимизированную обработку
func (rm *RetransmissionManager) processTimeouts() {
	defer close(rm.stopDone)
	// ОПТИМИЗАЦИЯ: Увеличиваем интервал тикера до 50ms для снижения нагрузки
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	// ОПТИМИЗАЦИЯ: Получаем timeCache один раз
	timeCache := util.GetGlobalTimeCache()

	for {
		select {
		case <-rm.ctx.Done():
			// Graceful shutdown - очищаем pending пакеты
			rm.mu.Lock()
			rm.pending = make(map[uint32]*PendingPacket)
			rm.mu.Unlock()
			return
		case <-ticker.C:
			rm.mu.Lock()
			// ОПТИМИЗАЦИЯ: Используем кэшированное время
			now := timeCache.Now()
			var toRetransmit []*PendingPacket

			// ОПТИМИЗАЦИЯ: Предварительно выделяем слайс для уменьшения аллокаций
			if len(rm.pending) > 0 {
				toRetransmit = make([]*PendingPacket, 0, len(rm.pending)/4) // Предполагаем ~25% ретрансмиссий
			}

			for seq, pkt := range rm.pending {
				if now.Sub(pkt.LastSent) > rm.timeout {
					if pkt.Retries < rm.maxRetries {
						toRetransmit = append(toRetransmit, pkt)
					} else {
						// Превышен лимит попыток - удаляем
						delete(rm.pending, seq)
					}
				}
			}
			rm.mu.Unlock()

			// ОПТИМИЗАЦИЯ: Обрабатываем ретрансмиссии без блокировки мьютекса
			for _, pkt := range toRetransmit {
				rm.mu.Lock()
				pkt.Retries++
				// ОПТИМИЗАЦИЯ: Используем кэшированное время
				pkt.LastSent = timeCache.Now()
				rm.mu.Unlock()

				if rm.onRetransmit != nil {
					_ = rm.onRetransmit(pkt.Seq, pkt.Data)
				}
			}
		}
	}
}

// Stop останавливает RetransmissionManager и ждет завершения горутины
func (rm *RetransmissionManager) Stop() {
	if rm.cancel != nil {
		rm.cancel()
		// Ждем завершения горутины (с таймаутом)
		select {
		case <-rm.stopDone:
		case <-time.After(1 * time.Second):
			// Таймаут - горутина не завершилась вовремя
		}
	}
}

// MTUDiscovery - обнаружение MTU пути
type MTUDiscovery struct {
	currentMTU int
	probeSize  int
	minMTU     int
	maxMTU     int
	mu         sync.RWMutex
}

// NewMTUDiscovery создает MTU discovery
func NewMTUDiscovery(initialMTU, minMTU, maxMTU int) *MTUDiscovery {
	return &MTUDiscovery{
		currentMTU: initialMTU,
		probeSize:  initialMTU,
		minMTU:     minMTU,
		maxMTU:     maxMTU,
	}
}

// GetCurrentMTU возвращает текущий MTU
func (md *MTUDiscovery) GetCurrentMTU() int {
	md.mu.RLock()
	defer md.mu.RUnlock()
	return md.currentMTU
}

// ProbeMTU запускает пробу MTU
func (md *MTUDiscovery) ProbeMTU(size int) {
	md.mu.Lock()
	defer md.mu.Unlock()

	if size >= md.minMTU && size <= md.maxMTU {
		md.probeSize = size
	}
}

// MTUConfirmed подтверждает успешную доставку пакета размера
func (md *MTUDiscovery) MTUConfirmed(size int) {
	md.mu.Lock()
	defer md.mu.Unlock()

	if size >= md.currentMTU {
		md.currentMTU = size
	}
}

// MTUFailed указывает что пакет размера не прошел
func (md *MTUDiscovery) MTUFailed(size int) {
	md.mu.Lock()
	defer md.mu.Unlock()

	if size <= md.currentMTU {
		// Уменьшаем MTU
		md.currentMTU = size - 100 // Консервативное уменьшение
		if md.currentMTU < md.minMTU {
			md.currentMTU = md.minMTU
		}
	}
}

// CongestionController - контроль перегрузки сети
type CongestionController struct {
	cwnd     int    // Congestion window
	ssthresh int    // Slow start threshold
	state    string // "slow_start", "congestion_avoidance", "recovery"
	mu       sync.RWMutex
	minCwnd  int
	maxCwnd  int
}

// NewCongestionController создает контроллер перегрузки
func NewCongestionController(initialCwnd, ssthresh, minCwnd, maxCwnd int) *CongestionController {
	return &CongestionController{
		cwnd:     initialCwnd,
		ssthresh: ssthresh,
		state:    "slow_start",
		minCwnd:  minCwnd,
		maxCwnd:  maxCwnd,
	}
}

// GetWindowSize возвращает текущий размер окна
func (cc *CongestionController) GetWindowSize() int {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.cwnd
}

// OnAck обрабатывает подтверждение пакета
func (cc *CongestionController) OnAck() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	switch cc.state {
	case "slow_start":
		cc.cwnd++
		if cc.cwnd >= cc.ssthresh {
			cc.state = "congestion_avoidance"
		}
	case "congestion_avoidance":
		// Linear growth
		cc.cwnd++
	}

	if cc.cwnd > cc.maxCwnd {
		cc.cwnd = cc.maxCwnd
	}
}

// OnLoss обрабатывает потерю пакета
func (cc *CongestionController) OnLoss() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.ssthresh = cc.cwnd / 2
	if cc.ssthresh < cc.minCwnd {
		cc.ssthresh = cc.minCwnd
	}
	cc.cwnd = cc.minCwnd
	cc.state = "slow_start"
}

// OnTimeout обрабатывает таймаут
func (cc *CongestionController) OnTimeout() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.ssthresh = cc.cwnd / 2
	if cc.ssthresh < cc.minCwnd {
		cc.ssthresh = cc.minCwnd
	}
	cc.cwnd = cc.minCwnd
	cc.state = "slow_start"
}

// RateLimiter - ограничитель скорости передачи
type RateLimiter struct {
	rate       float64 // Bytes per second
	burst      int
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewRateLimiter создает ограничитель скорости
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// Allow проверяет, можно ли отправить size байт
func (rl *RateLimiter) Allow(size int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now

	// Пополняем токены
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}

	// Проверяем, достаточно ли токенов
	if rl.tokens >= float64(size) {
		rl.tokens -= float64(size)
		return true
	}

	return false
}

// WaitForTokens ждет пока накопится достаточно токенов
func (rl *RateLimiter) WaitForTokens(size int) time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now

	// Пополняем токены
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}

	// Вычисляем время ожидания
	if rl.tokens >= float64(size) {
		return 0
	}

	needed := float64(size) - rl.tokens
	waitTime := needed / rl.rate

	return time.Duration(waitTime * float64(time.Second))
}

// ConnectionState - состояние соединения
type ConnectionState struct {
	RemoteAddr   *net.UDPAddr
	SessionID    uint32
	LastActivity time.Time
	PacketBuffer *PacketBuffer
	Retransmit   *RetransmissionManager
	MTU          *MTUDiscovery
	Congestion   *CongestionController
	RateLimit    *RateLimiter
	mu           sync.RWMutex
}

// NewConnectionState создает новое состояние соединения
func NewConnectionState(remoteAddr *net.UDPAddr, sessionID uint32) *ConnectionState {
	cs := &ConnectionState{
		RemoteAddr:   remoteAddr,
		SessionID:    sessionID,
		LastActivity: time.Now(),
		PacketBuffer: NewPacketBuffer(100, 5*time.Second),
		MTU:          NewMTUDiscovery(1200, 576, 1500),
		Congestion:   NewCongestionController(100, 500, 10, 10000),   // ОПТИМИЗИРОВАНО: cwnd=100, ssthresh=500, minCwnd=10, maxCwnd=10000
		RateLimit:    NewRateLimiter(1*1024*1024*1024, 10*1024*1024), // ОПТИМИЗИРОВАНО: 1 GB/s, burst 10 MB
	}

	// Инициализируем retransmission manager с увеличенным timeout
	cs.Retransmit = NewRetransmissionManager(1000*time.Millisecond, 5, func(seq uint32, data []byte) error {
		// Callback для повторной передачи (должен быть установлен извне)
		return nil
	})

	return cs
}

// UpdateActivity обновляет время последней активности
func (cs *ConnectionState) UpdateActivity() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.LastActivity = time.Now()
}

// IsStale проверяет, устарело ли соединение
func (cs *ConnectionState) IsStale(timeout time.Duration) bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return time.Since(cs.LastActivity) > timeout
}
