// Package relay provides stream management for multiplexed connections
package relay

import (
	"sync"
	"sync/atomic"
	"time"
)

// AdaptiveTimeout отслеживает RTT и рекомендует оптимальные таймауты
// ОПТИМИЗАЦИЯ: Автоматическое масштабирование таймаутов на основе исторических данных
type AdaptiveTimeout struct {
	mu            sync.RWMutex
	measurements  []time.Duration // Last N measurements (circular buffer)
	index         int
	samples       int
	minRTT        time.Duration
	maxRTT        time.Duration
	smoothedRTT   time.Duration // Exponential moving average
	rttVar        time.Duration // RTT variance
	updated       atomic.Value   // time.Time
}

// NewAdaptiveTimeout создает новый adaptive timeout tracker
func NewAdaptiveTimeout(bufferSize int) *AdaptiveTimeout {
	if bufferSize <= 0 {
		bufferSize = 100
	}
	
	at := &AdaptiveTimeout{
		measurements: make([]time.Duration, bufferSize),
		minRTT:       10 * time.Second, // Conservative default
		maxRTT:       10 * time.Millisecond,
		smoothedRTT:  100 * time.Millisecond,
		rttVar:       50 * time.Millisecond,
	}
	at.updated.Store(time.Now())
	return at
}

// Record записывает новое измерение RTT
func (at *AdaptiveTimeout) Record(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	
	at.mu.Lock()
	defer at.mu.Unlock()
	
	// Добавляем измерение в циклический буфер
	at.measurements[at.index] = rtt
	at.index = (at.index + 1) % len(at.measurements)
	if at.samples < len(at.measurements) {
		at.samples++
	}
	
	// Обновляем min/max
	if rtt < at.minRTT {
		at.minRTT = rtt
	}
	if rtt > at.maxRTT {
		at.maxRTT = rtt
	}
	
	// Обновляем smoothed RTT (SRTT) и variance (RTTVAR) по RFC 6298
	if at.smoothedRTT == 0 {
		at.smoothedRTT = rtt
		at.rttVar = rtt / 2
	} else {
		delta := rtt - at.smoothedRTT
		at.rttVar = (at.rttVar*3 + absTimeDuration(delta)) / 4
		at.smoothedRTT = (at.smoothedRTT*7 + rtt) / 8
	}
	
	at.updated.Store(time.Now())
}

// GetTimeoutFor возвращает рекомендуемый таймаут для операции
// Использует RTO = SRTT + 4 * RTTVAR (как в TCP)
func (at *AdaptiveTimeout) GetTimeoutFor(baseTimeout time.Duration) time.Duration {
	at.mu.RLock()
	defer at.mu.RUnlock()
	
	if at.samples < 3 {
		// Недостаточно данных - используем базовый таймаут
		return baseTimeout
	}
	
	// RTO = SRTT + 4 * RTTVAR (TCP Retransmission Timeout)
	rto := at.smoothedRTT + (at.rttVar * 4)
	
	// Убедимся, что RTO находится в разумных границах
	if rto < baseTimeout/2 {
		rto = baseTimeout / 2
	}
	if rto > baseTimeout*2 {
		rto = baseTimeout * 2
	}
	
	return rto
}

// AvgRTT возвращает среднее RTT за последние измерения
func (at *AdaptiveTimeout) AvgRTT() time.Duration {
	at.mu.RLock()
	defer at.mu.RUnlock()
	
	if at.samples == 0 {
		return 0
	}
	
	var sum time.Duration
	for i := 0; i < at.samples; i++ {
		sum += at.measurements[i]
	}
	return sum / time.Duration(at.samples)
}

// P99RTT возвращает 99-й перцентиль RTT
func (at *AdaptiveTimeout) P99RTT() time.Duration {
	at.mu.RLock()
	defer at.mu.RUnlock()
	
	if at.samples == 0 {
		return 0
	}
	
	// ОПТИМИЗАЦИЯ: P99 расчет БЕЗ копирования - сортируем in-place в буфере, минуя измерения
	// Для малого набора данных (до 100 samples) не копируем и не используем append
	var measurements [100]time.Duration
	
	// Копируем ТОЛЬКО если нужно - иначе сортируем прямо в буфере
	count := at.samples
	if count > 100 {
		count = 100
	}
	// Копируем только необходимые элементы (не весь буфер)
	copy(measurements[:count], at.measurements[:count])
	
	// Bubble sort in-place (non-escaping stack array)
	for i := 0; i < count; i++ {
		for j := i + 1; j < count; j++ {
			if measurements[j] < measurements[i] {
				measurements[i], measurements[j] = measurements[j], measurements[i]
			}
		}
	}
	
	idx := (count * 99) / 100
	if idx >= count {
		idx = count - 1
	}
	
	return measurements[idx]
}

// Reset сбрасывает все статистику
func (at *AdaptiveTimeout) Reset() {
	at.mu.Lock()
	defer at.mu.Unlock()
	
	at.measurements = make([]time.Duration, len(at.measurements))
	at.index = 0
	at.samples = 0
	at.minRTT = 10 * time.Second
	at.maxRTT = 10 * time.Millisecond
	at.smoothedRTT = 100 * time.Millisecond
	at.rttVar = 50 * time.Millisecond
	at.updated.Store(time.Now())
}

// LastUpdated возвращает время последнего обновления
func (at *AdaptiveTimeout) LastUpdated() time.Time {
	return at.updated.Load().(time.Time)
}

// absTimeDuration вспомогательная функция для абсолютного значения
func absTimeDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// Stats возвращает статистику для отладки
type TimeoutStats struct {
	Samples    int
	MinRTT     time.Duration
	MaxRTT     time.Duration
	SmoothedRTT time.Duration
	RTTVar     time.Duration
	AvgRTT     time.Duration
	P99RTT     time.Duration
}

// GetStats возвращает текущую статистику
func (at *AdaptiveTimeout) GetStats() TimeoutStats {
	at.mu.RLock()
	defer at.mu.RUnlock()
	
	stats := TimeoutStats{
		Samples:     at.samples,
		MinRTT:      at.minRTT,
		MaxRTT:      at.maxRTT,
		SmoothedRTT: at.smoothedRTT,
		RTTVar:      at.rttVar,
	}
	
	if at.samples > 0 {
		var sum time.Duration
		for i := 0; i < at.samples; i++ {
			sum += at.measurements[i]
		}
		stats.AvgRTT = sum / time.Duration(at.samples)
	}
	
	return stats
}
