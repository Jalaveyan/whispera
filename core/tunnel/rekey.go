package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"time"
)

func (rm *rotationManager) startRekey() {
	m := rm.m
	if m.config.RekeyInterval <= 0 {
		return
	}
	rm.stopRekey()

	ctx, cancel := context.WithCancel(context.Background())
	rm.rekeyCancel = cancel
	rm.rekeyTicker = time.NewTicker(m.config.RekeyInterval)

	safeGo("rekey", func() {
		defer rm.rekeyTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-rm.rekeyTicker.C:
				rm.performRekey()
			}
		}
	})
}

func (rm *rotationManager) stopRekey() {
	if rm.rekeyCancel != nil {
		rm.rekeyCancel()
		rm.rekeyCancel = nil
	}
	if rm.rekeyTicker != nil {
		rm.rekeyTicker.Stop()
		rm.rekeyTicker = nil
	}
}

func (rm *rotationManager) performRekey() {
	m := rm.m
	if m.GetState() != StateConnected {
		return
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return
	}

	frame := make([]byte, FrameHeaderSize+32)
	binary.BigEndian.PutUint16(frame[0:2], 0)
	frame[2] = FrameTypeRekey
	frame[3] = 0x00
	binary.BigEndian.PutUint32(frame[4:8], 32)
	copy(frame[FrameHeaderSize:], seed)

	if err := m.Send(frame); err != nil {
		return
	}
}

func (m *Manager) startRekey() { m.rotation.startRekey() }

func (m *Manager) stopRekey() { m.rotation.stopRekey() }
