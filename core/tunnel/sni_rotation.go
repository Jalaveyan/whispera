package tunnel

import (
	"context"
	"crypto/rand"
	"math/big"
	"sync"
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

type rotationManager struct {
	m *Manager

	rotationTicker *time.Ticker
	rotationCancel context.CancelFunc

	rekeyTicker *time.Ticker
	rekeyCancel context.CancelFunc

	russianSNIs   []string
	russianSNIsMu sync.RWMutex

	currentSNI   string
	lastRotation time.Time
}

func newRotationManager(m *Manager) *rotationManager {
	return &rotationManager{m: m}
}

func (rm *rotationManager) selectNewSNI() string {
	m := rm.m
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return rm.selectNewSNILocked()
}

func (rm *rotationManager) selectNewSNILocked() string {
	pool := rm.russianSNIs
	if len(pool) == 0 {
		pool = defaultSNIPool
	}
	if len(pool) == 0 {
		rm.currentSNI = ""
		return rm.currentSNI
	}

	idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	if err != nil {
		rm.currentSNI = pool[0]
	} else {
		rm.currentSNI = pool[idxBig.Int64()]
	}
	rm.lastRotation = time.Now()
	return rm.currentSNI
}

func (rm *rotationManager) RotateSNI() {
	m := rm.m
	oldSNI := rm.currentSNI
	oldTransport := m.config.Transport
	rm.selectNewSNI()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.connectInternal(ctx, true); err != nil {
		log.Error("SNI Rotation failed: %v - keeping existing connection", err)

		m.connMu.Lock()
		rm.currentSNI = oldSNI
		m.connMu.Unlock()
		m.config.Transport = oldTransport
		m.setState(StateConnected)
		return
	}
}

func (rm *rotationManager) AddRussianSNI(sni string) {
	if sni == "" {
		return
	}
	rm.russianSNIsMu.Lock()
	defer rm.russianSNIsMu.Unlock()
	for _, existing := range rm.russianSNIs {
		if existing == sni {
			return
		}
	}
	rm.russianSNIs = append(rm.russianSNIs, sni)
}

func (rm *rotationManager) GetRussianSNIs() []string {
	rm.russianSNIsMu.RLock()
	defer rm.russianSNIsMu.RUnlock()
	out := make([]string, len(rm.russianSNIs))
	copy(out, rm.russianSNIs)
	return out
}

func (m *Manager) RotateSNI() { m.rotation.RotateSNI() }

func (m *Manager) AddRussianSNI(sni string) { m.rotation.AddRussianSNI(sni) }

func (m *Manager) GetRussianSNIs() []string { return m.rotation.GetRussianSNIs() }
