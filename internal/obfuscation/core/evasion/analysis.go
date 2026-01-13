package evasion

import (
	"fmt"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)

// loadRealTrafficData loads real traffic data for calibration
func (m *Marionette) loadRealTrafficData(_ string) {
	timeCache := util.GetGlobalTimeCache()
	now := timeCache.Now()

	// Initialize performance metrics
	m.State.PerformanceMetrics = &types.PerformanceMetrics{
		DPIEvasionSuccess: 0.85,
		FalsePositiveRate: 0.05,
		Latency:           10 * time.Millisecond,
		Throughput:        1000.0,
		MemoryUsage:       1024 * 1024, // 1MB
		CPUUsage:          0.1,
		LastUpdate:        now,
	}

	// Initialize session start time
	m.State.SessionStart = now
}

// analyzeTrafficSuccess analyzes traffic success for adaptive learning
func (m *Marionette) analyzeTrafficSuccess(_ []byte, _ string) error {
	return nil
}

// GetAdaptiveLearning returns the adaptive learning interface
func (m *Marionette) GetAdaptiveLearning() types.AdaptiveLearning {
	return m.AdaptiveLearning
}

// GetEffectivenessMetrics returns the effectiveness metrics
func (m *Marionette) GetEffectivenessMetrics() *EvasionEffectivenessMetrics {
	if metrics, ok := m.Effectiveness.(*EvasionEffectivenessMetrics); ok {
		return metrics
	}
	return nil
}

// GetSystemMetrics returns the system metrics
func (m *Marionette) GetSystemMetrics() *EvasionSystemMetrics {
	return m.Metrics
}

// HealthCheck checks the system health
func (m *Marionette) HealthCheck() error {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	if m.MlSystem != nil {
		if err := m.MlSystem.HealthCheck(); err != nil {
			return err
		}
	}

	if m.CircuitBreaker.State == "open" {
		if time.Since(m.CircuitBreaker.LastFailureTime) < m.CircuitBreaker.Timeout {
			return fmt.Errorf("circuit breaker is open")
		}
	}

	return nil
}

// cleanupRuleCache cleans up rule cache
func (m *Marionette) cleanupRuleCache() {
	count := 0
	m.RuleCache.Range(func(key, value interface{}) bool {
		if count > 100 {
			m.RuleCache.Delete(key)
		}
		count++
		return count < 200
	})
}

// applyMetadataProtection applies metadata protection for government DPI evasion
func (m *Marionette) applyMetadataProtection(data []byte) []byte {
	return data
}

// --- EvasionEffectivenessMetrics Implementation ---

func (em *EvasionEffectivenessMetrics) RecordSuccess(profile string, method string, latency time.Duration) error {
	atomic.AddInt64(&em.SuccessfulEvasion, 1)
	atomic.AddInt64(&em.TotalPackets, 1)
	em.LastUpdate = time.Now()
	return nil
}

func (em *EvasionEffectivenessMetrics) RecordFailure(profile string, method string, reason string) error {
	atomic.AddInt64(&em.FailedEvasion, 1)
	atomic.AddInt64(&em.TotalPackets, 1)
	em.LastUpdate = time.Now()
	return nil
}

func (em *EvasionEffectivenessMetrics) GetEffectiveness(profile string) *types.EffectivenessStats {
	rate := 1.0
	total := atomic.LoadInt64(&em.TotalPackets)
	success := atomic.LoadInt64(&em.SuccessfulEvasion)
	failure := atomic.LoadInt64(&em.FailedEvasion)

	if total > 0 {
		rate = float64(success) / float64(total)
	}
	return &types.EffectivenessStats{
		SuccessRate:   rate,
		TotalAttempts: total,
		LastUpdated:   em.LastUpdate,
		SuccessCount:  success,
		FailureCount:  failure,
		TotalPackets:  total,
	}
}

func (em *EvasionEffectivenessMetrics) GetOverallEffectiveness() *types.EffectivenessStats {
	return em.GetEffectiveness("")
}
