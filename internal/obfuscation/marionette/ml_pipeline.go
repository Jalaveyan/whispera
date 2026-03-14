package marionette

import (
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/core/types"
)

var mlSampleCounter int64

func (m *Marionette) applyMLPipeline(data []byte, direction string) []byte {
	if m.MlSystem == nil || len(data) < 64 {
		return data
	}

	m.Mutex.RLock()
	protocol := m.State.Protocol
	active := m.Active
	profile := m.Profiles[active]
	m.Mutex.RUnlock()

	ctx := &types.UnifiedTrafficContext{
		Protocol:  protocol,
		Direction: direction,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	processed, err := m.MlSystem.ProcessTraffic(data, ctx)
	if err != nil {
		return data
	}

	cnt := atomic.AddInt64(&mlSampleCounter, 1)
	if cnt%10 == 0 {
		go func() {
			pred, predErr := m.MlSystem.PredictTraffic(data, protocol, direction)
			if predErr != nil {
				return
			}
			m.MlSystem.CollectSample(data, protocol, direction, pred)
			m.reactToMLPrediction(pred, profile, active)
		}()
	}

	return processed
}

func (m *Marionette) reactToMLPrediction(pred *types.MLPredictionResponse, profile *types.TrafficProfile, activeProfile string) {
	if pred == nil || len(pred.Predictions) == 0 {
		return
	}

	p := pred.Predictions[0]

	if p.DPIType > 0 && p.Confidence > 0.7 {
		m.Mutex.Lock()
		m.State.ThreatLevel = p.DPIType * 2
		if m.State.ThreatLevel > 10 {
			m.State.ThreatLevel = 10
		}
		m.Mutex.Unlock()
	}

	if p.IsAnomaly && p.AnomalyScore > 0.8 {
		m.Mutex.Lock()
		if m.State.ThreatLevel < 8 {
			m.State.ThreatLevel = 8
		}
		m.Mutex.Unlock()
	}
}

func (m *Marionette) mlDrivenProfileSwitch(dpiThreat float64, currentProfile string, locked bool) {
	if locked || m.MlSystem == nil {
		return
	}

	m.Mutex.RLock()
	threatLevel := m.State.ThreatLevel
	m.Mutex.RUnlock()

	if dpiThreat < 0.5 && threatLevel < 5 {
		return
	}

	var targetProfile string
	switch {
	case threatLevel >= 8:
		targetProfile = "vk"
	case threatLevel >= 5:
		targetProfile = "websocket"
	default:
		return
	}

	if targetProfile == currentProfile {
		return
	}

	m.Mutex.RLock()
	_, exists := m.Profiles[targetProfile]
	m.Mutex.RUnlock()

	if !exists {
		return
	}

	_ = m.SwitchProfile(targetProfile, "ml_dpi_detection")
}
