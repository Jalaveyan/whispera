package relay

import (
	"sync"
	"sync/atomic"
	"time"
)

type AdaptiveTimeout struct {
	mu           sync.RWMutex
	measurements []time.Duration
	index        int
	samples      int
	minRTT       time.Duration
	maxRTT       time.Duration
	smoothedRTT  time.Duration
	rttVar       time.Duration
	updated      atomic.Value
}

func NewAdaptiveTimeout(bufferSize int) *AdaptiveTimeout {
	if bufferSize <= 0 {
		bufferSize = 100
	}

	at := &AdaptiveTimeout{
		measurements: make([]time.Duration, bufferSize),
		minRTT:       10 * time.Millisecond,
		maxRTT:       10 * time.Second,
		smoothedRTT:  100 * time.Millisecond,
		rttVar:       50 * time.Millisecond,
	}
	at.updated.Store(time.Now())
	return at
}

func (at *AdaptiveTimeout) Record(rtt time.Duration) {
	if rtt <= 0 {
		return
	}

	at.mu.Lock()
	defer at.mu.Unlock()

	at.measurements[at.index] = rtt
	at.index = (at.index + 1) % len(at.measurements)
	if at.samples < len(at.measurements) {
		at.samples++
	}

	if rtt < at.minRTT {
		at.minRTT = rtt
	}
	if rtt > at.maxRTT {
		at.maxRTT = rtt
	}

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

func (at *AdaptiveTimeout) GetTimeoutFor(baseTimeout time.Duration) time.Duration {
	at.mu.RLock()
	defer at.mu.RUnlock()

	if at.samples < 3 {
		return baseTimeout
	}

	rto := at.smoothedRTT + (at.rttVar * 4)

	if rto < baseTimeout/2 {
		rto = baseTimeout / 2
	}
	if rto > baseTimeout*2 {
		rto = baseTimeout * 2
	}

	return rto
}

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

func (at *AdaptiveTimeout) P99RTT() time.Duration {
	at.mu.RLock()
	defer at.mu.RUnlock()

	if at.samples == 0 {
		return 0
	}

	var measurements [100]time.Duration

	count := at.samples
	if count > 100 {
		count = 100
	}
	copy(measurements[:count], at.measurements[:count])

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

func (at *AdaptiveTimeout) Reset() {
	at.mu.Lock()
	defer at.mu.Unlock()

	at.measurements = make([]time.Duration, len(at.measurements))
	at.index = 0
	at.samples = 0
	at.minRTT = 10 * time.Millisecond
	at.maxRTT = 10 * time.Second
	at.smoothedRTT = 100 * time.Millisecond
	at.rttVar = 50 * time.Millisecond
	at.updated.Store(time.Now())
}

func (at *AdaptiveTimeout) LastUpdated() time.Time {
	return at.updated.Load().(time.Time)
}
func absTimeDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

type TimeoutStats struct {
	Samples     int
	MinRTT      time.Duration
	MaxRTT      time.Duration
	SmoothedRTT time.Duration
	RTTVar      time.Duration
	AvgRTT      time.Duration
	P99RTT      time.Duration
}

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
