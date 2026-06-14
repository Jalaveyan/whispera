package bridgepool

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"
)

type TrustManager struct {
	registry *Registry
}

func NewTrustManager(registry *Registry) *TrustManager {
	return &TrustManager{registry: registry}
}
func (t *TrustManager) VerifyBridge(b *BridgeInfo, signature []byte, message []byte) error {
	if b.PublicKey == "" {
		return errors.New("bridge has no public key")
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(b.PublicKey)
	if err != nil {
		return errors.New("invalid public key encoding")
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return errors.New("invalid public key size")
	}

	if !ed25519.Verify(pubKeyBytes, message, signature) {
		return errors.New("signature verification failed")
	}

	return nil
}

func (t *TrustManager) CalculateTrustLevel(b *BridgeInfo) int {
	score := 0
	switch b.Type {
	case BridgeOperator:
		score = 100
		return score
	case BridgeWhite:
		score = 85
	case BridgeUser:
		score = 60
	case BridgeCommunity:
		score = 30
	}

	if b.IsAlive {
		score += 10
	}
	if b.Latency > 0 && b.Latency < 100 {
		score += 15
	} else if b.Latency < 200 {
		score += 10
	} else if b.Latency < 500 {
		score += 5
	}

	age := time.Since(b.CreatedAt)
	if age > 30*24*time.Hour {
		score += 20
	} else if age > 7*24*time.Hour {
		score += 10
	} else if age > 24*time.Hour {
		score += 5
	}
	if b.PublicKey != "" {
		score += 10
	}

	if score > 100 {
		score = 100
	}

	return score
}

func (t *TrustManager) RecalculateAllTrust() {
	bridges := t.registry.GetAllBridges()
	for _, b := range bridges {
		newTrust := t.CalculateTrustLevel(b)
		t.registry.mu.Lock()
		if bridge, exists := t.registry.bridges[b.ID]; exists {
			bridge.TrustLevel = newTrust
		}
		t.registry.mu.Unlock()
	}
}
