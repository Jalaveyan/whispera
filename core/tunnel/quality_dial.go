package tunnel

import (
	mrand "math/rand"
	"sync/atomic"
	"time"
	"whispera/common/runtime/interfaces"
)

func (m *Manager) updateQualityRTT(rtt time.Duration) {
	const alpha = 0.2
	old := atomic.LoadInt64(&m.qualityRTTEWMA)
	var newEWMA int64
	if old == 0 {
		newEWMA = int64(rtt)
	} else {
		newEWMA = int64(float64(old)*(1-alpha) + float64(rtt)*alpha)
	}
	atomic.StoreInt64(&m.qualityRTTEWMA, newEWMA)

	threshold := m.config.QualityThresholdRTT
	if threshold > 0 && time.Duration(newEWMA) > threshold {
		go m.Reconnect(m.Context())
	}
}

func (m *Manager) GetQualityMetrics() (avgRTT time.Duration, missedKeepalives int) {
	return time.Duration(atomic.LoadInt64(&m.qualityRTTEWMA)),
		int(atomic.LoadInt32(&m.missedKAs))
}

func (m *Manager) HealthCheck() interfaces.HealthStatus {
	status := m.Module.HealthCheck()
	status.Details["state"] = m.sm.Get().String()
	if lastErr := m.sm.LastError(); lastErr != nil {
		status.Details["last_error"] = lastErr.Error()
	}
	status.Details["server"] = m.config.ServerAddr
	status.Details["active_streams"] = len(m.streamConns)
	m.connMu.RLock()
	status.Details["draining_conns"] = len(m.drainingConns)
	m.connMu.RUnlock()
	if rtt := time.Duration(atomic.LoadInt64(&m.qualityRTTEWMA)); rtt > 0 {
		status.Details["quality_rtt_ms"] = rtt.Milliseconds()
		status.Details["quality_missed_kas"] = atomic.LoadInt32(&m.missedKAs)
	}
	return status
}

func (m *Manager) getReconnectDelay() time.Duration {
	attempts := atomic.LoadUint32(&m.reconnectAttempts)
	if attempts == 0 {
		return m.config.ReconnectInterval
	}
	delay := m.config.ReconnectInterval
	for i := uint32(0); i < attempts && i < 10; i++ {
		delay = time.Duration(float64(delay) * 2)
	}
	if delay > m.config.ReconnectMaxDelay {
		delay = m.config.ReconnectMaxDelay
	}
	jitter := time.Duration(mrand.Int63n(int64(delay) / 4))
	return delay + jitter
}

func (m *Manager) Stats() (bytesUp, bytesDown uint64) {
	return atomic.LoadUint64(&m.bytesUp), atomic.LoadUint64(&m.bytesDown)
}
