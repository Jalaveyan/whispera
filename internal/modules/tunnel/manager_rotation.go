package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"time"
)

var defaultSNIPool = []string{
	"kion.ru",
	"rutube.ru",
	"vk.com",
	"ok.ru",
	"dzen.ru",
	"music.yandex.ru",
	"cloud.mail.ru",
	"premier.one",
	"wink.ru",
	"ivi.ru",
	"start.ru",
	"more.tv",
}

func (m *Manager) selectNewSNI() string {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return m.selectNewSNILocked()
}

func (m *Manager) selectNewSNILocked() string {
	pool := m.russianSNIs
	if len(pool) == 0 {
		pool = defaultSNIPool
	}
	if len(pool) == 0 {
		m.currentSNI = ""
		return m.currentSNI
	}

	if m.sniAgent != nil {
		state := m.sniAgent.EncodeState(0, 0, 0, false, 0)
		domain, _ := m.sniAgent.Select(state)
		if domain != "" {
			m.currentSNI = domain
			m.lastRotation = time.Now()
			log.Info("[ROTATION EVENT] RL SNI agent selected: %s (eps=%.2f)",
				m.currentSNI, m.sniAgent.Epsilon())
			return m.currentSNI
		}
	}

	idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	if err != nil {
		m.currentSNI = pool[0]
	} else {
		m.currentSNI = pool[idxBig.Int64()]
	}
	m.lastRotation = time.Now()
	log.Info("[ROTATION EVENT] Selected new SNI: %s (fallback crypto/rand)", m.currentSNI)
	return m.currentSNI
}

func (m *Manager) getRotationSNI() string {
	if m.config.NoSNI {
		return ""
	}

	m.connMu.RLock()
	sni := m.currentSNI
	m.connMu.RUnlock()

	if sni != "" {
		return sni
	}

	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.currentSNI != "" {
		return m.currentSNI
	}

	return m.selectNewSNILocked()
}

func (m *Manager) RotateSNI() {
	oldSNI := m.currentSNI
	oldTransport := m.config.Transport
	newSNI := m.selectNewSNI()
	log.Info("Initiating Seamless SNI Rotation to: %s", newSNI)

	if m.config.MLServerURL != "" {
		if rec, conf := m.mlRecommendTransport(m.Context()); rec != "" && conf >= 0.55 && rec != oldTransport {
			log.Info("[ML-Rotate] Transport switch during SNI rotation: %s → %s (confidence=%.2f)", oldTransport, rec, conf)
			m.config.Transport = rec
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.connectInternal(ctx, true); err != nil {
		log.Error("SNI Rotation failed: %v - keeping existing connection", err)

		m.connMu.Lock()
		m.currentSNI = oldSNI
		m.connMu.Unlock()
		m.config.Transport = oldTransport
		m.setState(StateConnected)

		if m.config.MLServerURL != "" {
			go m.mlSendFeedback(m.config.Transport, false, 0)
		}
		return
	}

	if m.config.MLServerURL != "" {
		go m.mlSendFeedback(m.config.Transport, true, 0)
	}
	log.Info("SNI Rotation complete. Old connections will drain gracefully.")
}

func (m *Manager) maybePreemptiveRotate(streak int32) {
	if streak == 2 && m.transportAgent != nil {
		log.Info("[preemptive] %d consecutive TLS errors — rotating transport before block", streak)
		go m.rotateTransport()
	}
}

func (m *Manager) rotateTransport() {
	m.connMu.RLock()
	poolSize := len(m.activePool)
	m.connMu.RUnlock()

	if poolSize == 0 {
		return
	}

	oldTransport := m.config.Transport
	if m.config.MLServerURL != "" {
		if rec, conf := m.mlRecommendTransport(m.Context()); rec != "" && conf >= 0.55 {
			if rec != oldTransport {
				log.Info("[REKEY] ML recommends transport switch: %s → %s (confidence=%.2f)", oldTransport, rec, conf)
				m.config.Transport = rec
			}
		}
	}

	log.Info("[REKEY] Rotating %d transport connections for PFS (transport=%s)", poolSize, m.config.Transport)

	m.setState(StateReconnecting)
	m.Reconnect(m.Context())

	if m.config.MLServerURL != "" {
		go func() {
			time.Sleep(5 * time.Second)
			m.connMu.RLock()
			success := len(m.activePool) > 0
			m.connMu.RUnlock()
			m.mlSendFeedback(m.config.Transport, success, 0)
			if !success && m.config.Transport != oldTransport {
				log.Warn("[REKEY] ML transport %s failed, reverting to %s", m.config.Transport, oldTransport)
				m.config.Transport = oldTransport
				m.Reconnect(m.Context())
			}
		}()
	}
}

func (m *Manager) startRekey() {
	if m.config.RekeyInterval <= 0 {
		return
	}
	m.stopRekey()

	ctx, cancel := context.WithCancel(context.Background())
	m.rekeyCancel = cancel
	m.rekeyTicker = time.NewTicker(m.config.RekeyInterval)

	safeGo("rekey", func() {
		defer m.rekeyTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.rekeyTicker.C:
				m.performRekey()
			}
		}
	})
	log.Info("[REKEY] Periodic rekeying started (interval=%v)", m.config.RekeyInterval)
}

func (m *Manager) stopRekey() {
	if m.rekeyCancel != nil {
		m.rekeyCancel()
		m.rekeyCancel = nil
	}
	if m.rekeyTicker != nil {
		m.rekeyTicker.Stop()
		m.rekeyTicker = nil
	}
}

func (m *Manager) performRekey() {
	if m.GetState() != StateConnected {
		return
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		log.Warn("[REKEY] Failed to generate seed: %v", err)
		return
	}

	frame := make([]byte, FrameHeaderSize+32)
	binary.BigEndian.PutUint16(frame[0:2], 0)
	frame[2] = FrameTypeRekey
	frame[3] = 0x00
	binary.BigEndian.PutUint32(frame[4:8], 32)
	copy(frame[FrameHeaderSize:], seed)

	if err := m.Send(frame); err != nil {
		log.Warn("[REKEY] Failed to send rekey frame: %v", err)
		return
	}
	log.Info("[REKEY] Sent in-place rekey frame (PFS, seed=%x...)", seed[:4])
}

func (m *Manager) AddRussianSNI(sni string) {
	if sni == "" {
		return
	}
	m.russianSNIsMu.Lock()
	defer m.russianSNIsMu.Unlock()
	for _, existing := range m.russianSNIs {
		if existing == sni {
			return
		}
	}
	m.russianSNIs = append(m.russianSNIs, sni)
}

func (m *Manager) GetRussianSNIs() []string {
	m.russianSNIsMu.RLock()
	defer m.russianSNIsMu.RUnlock()
	out := make([]string, len(m.russianSNIs))
	copy(out, m.russianSNIs)
	return out
}
