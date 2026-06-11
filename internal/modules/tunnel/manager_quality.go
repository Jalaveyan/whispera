package tunnel

import (
	"fmt"
	mrand "math/rand"
	"sync/atomic"
	"time"

	"whispera/internal/core/interfaces"
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
		log.Warn("Quality failover: avg RTT=%v > threshold=%v, triggering reconnect",
			time.Duration(newEWMA), threshold)
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

func (m *Manager) GetTransport() string {
	return m.config.Transport
}

func (m *Manager) SetTransport(transport string) {
	m.config.Transport = transport
}

func (m *Manager) SetSpoofIPs(ips []string) {
	m.connMu.Lock()
	m.spoofIPs = ips
	m.connMu.Unlock()
}

func (m *Manager) SetRateLimit(kbps int) {
	atomic.StoreInt32(&m.rateLimitKB, int32(kbps))
}

func (m *Manager) GetRateLimit() int {
	return int(atomic.LoadInt32(&m.rateLimitKB))
}

func (m *Manager) SetTLSFragmentSize(size int) {
	if size < 0 {
		size = 0
	}
	atomic.StoreInt32(&m.tlsFragmentSize, int32(size))
	if m.config != nil {
		m.config.TLSFragmentSize = size
	}
}

func (m *Manager) GetTLSFragmentSize() int {
	return int(atomic.LoadInt32(&m.tlsFragmentSize))
}

func (m *Manager) SetForceObfuscation(enabled bool) {
	if enabled {
		atomic.StoreInt32(&m.transportSecureOverride, 0)
		atomic.StoreInt32(&m.forceObfuscation, 1)
	} else {
		atomic.StoreInt32(&m.transportSecureOverride, 1)
		atomic.StoreInt32(&m.forceObfuscation, 0)
	}
}

func (m *Manager) IsForceObfuscation() bool {
	return atomic.LoadInt32(&m.transportSecureOverride) == 0
}

func (m *Manager) SetBehavioralProfile(profile string) error {
	if m.obfuscator == nil {
		return fmt.Errorf("obfuscator not initialized")
	}
	if profile == "" {
		return nil
	}
	return m.obfuscator.SetProfile(profile)
}
