package tunnel

import (
	"context"
	mrand "math/rand"
	"sync/atomic"
	"time"
	"whispera/neural"
)

type keepaliveController struct {
	m      *Manager
	cancel context.CancelFunc
}

func newKeepaliveController(m *Manager) *keepaliveController {
	return &keepaliveController{m: m}
}

func (k *keepaliveController) start() {
	k.stop()
	k.send()

	ctx, cancel := context.WithCancel(context.Background())
	k.cancel = cancel

	go func() {
		m := k.m
		for {
			rttMs := float64(atomic.LoadInt64(&m.qualityRTTEWMA)) / 1e6
			missed := int(atomic.LoadInt32(&m.missedKAs))
			kaView := neural.KeepaliveView{RTTMs: rttMs, MissedKAs: missed}

			base := m.config.KeepaliveInterval
			if m.ml.kaAgent != nil {
				base = m.ml.kaAgent.Decide(kaView)
			}

			jitterFrac := 0.30
			if m.ml.jitterAgent != nil {
				jitterFrac = m.ml.jitterAgent.Decide(neural.JitterView{
					RTTMs: rttMs, MissedKAs: missed,
				})
			}

			jitter := time.Duration(float64(base) * jitterFrac * (2*mrand.Float64() - 1))
			timer := time.NewTimer(base + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				k.send()
			}
		}
	}()
}

func (k *keepaliveController) stop() {
	if k.cancel != nil {
		k.cancel()
	}
}

func (k *keepaliveController) send() {
	m := k.m

	if !m.lastPong.IsZero() && m.GetState() == StateConnected {
		silentDuration := time.Since(m.lastPong)
		maxSilence := 90 * time.Second
		if silentDuration > maxSilence {
			go m.Reconnect(m.Context())
			return
		}

		if !m.lastKeepalive.IsZero() && m.lastPong.Before(m.lastKeepalive) {
			missed := atomic.AddInt32(&m.missedKAs, 1)
			if m.ml.kaAgent != nil {
				m.ml.kaAgent.RecordOutcome(0)
			}
			if m.ml.jitterAgent != nil {
				m.ml.jitterAgent.RecordOutcome(0)
			}
			threshold := m.config.QualityMissedKeepalives
			if threshold > 0 && int(missed) >= threshold {
				atomic.StoreInt32(&m.missedKAs, 0)
				go m.Reconnect(m.Context())
				return
			}
		}

		halfInterval := m.config.KeepaliveInterval / 2
		if halfInterval > 0 && silentDuration < halfInterval {
			m.lastKeepalive = time.Now()
			atomic.StoreInt32(&m.missedKAs, 0)
			return
		}
	}

	pingFrame := make([]byte, 8)
	pingFrame[2] = 0x06

	sendTimeout := m.config.KeepaliveInterval
	if sendTimeout <= 0 {
		sendTimeout = 30 * time.Second
	}

	done := make(chan error, 1)
	go func() { done <- m.Send(pingFrame) }()

	select {
	case err := <-done:
		if err != nil {
			if m.GetState() == StateConnected {
				go m.Reconnect(m.Context())
			}
		} else {
			m.lastKeepalive = time.Now()
		}
	case <-time.After(sendTimeout):
		if m.GetState() == StateConnected {
			go m.Reconnect(m.Context())
		}
	}
}
