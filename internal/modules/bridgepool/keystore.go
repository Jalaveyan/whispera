package bridgepool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

type EncryptedKeyStore struct {
	masterKey  [32]byte
	auditLog   *AuditLog
	mu         sync.RWMutex
	persistDir string
}

type AuditEntry struct {
	Timestamp time.Time `json:"ts"`
	Action    string    `json:"action"`
	KeyID     string    `json:"key_id"`
	UserID    string    `json:"user_id"`
	BridgeID  string    `json:"bridge_id"`
	SourceIP  string    `json:"source_ip"`
	Success   bool      `json:"success"`
	Reason    string    `json:"reason,omitempty"`
}

type AuditLog struct {
	mu         sync.Mutex
	persistPath string
}

func NewEncryptedKeyStore(serverSecret string, persistDir string) *EncryptedKeyStore {
	ks := &EncryptedKeyStore{
		persistDir: persistDir,
		auditLog:   &AuditLog{persistPath: persistDir + ".audit.jsonl"},
	}
	hkdfReader := hkdf.New(sha256.New, []byte(serverSecret), []byte("whispera-keystore-v1"), []byte("aes-256-gcm"))
	_, _ = io.ReadFull(hkdfReader, ks.masterKey[:])
	return ks
}

func (ks *EncryptedKeyStore) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ks.masterKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (ks *EncryptedKeyStore) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ks.masterKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

func (ks *EncryptedKeyStore) SaveKeys(keys map[string]*AccessKey, path string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	encrypted, err := ks.Encrypt(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encrypted, 0600)
}

func (ks *EncryptedKeyStore) LoadKeys(path string) (map[string]*AccessKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	encrypted, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]*AccessKey), nil
		}
		return nil, err
	}

	if len(encrypted) == 0 {
		return make(map[string]*AccessKey), nil
	}

	data, err := ks.Decrypt(encrypted)
	if err != nil {
		var keys map[string]*AccessKey
		if json.Unmarshal(encrypted, &keys) == nil {
			return keys, nil
		}
		return nil, fmt.Errorf("decrypt keys: %w", err)
	}

	var keys map[string]*AccessKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func GenerateChallengeHMAC(challengeSecret []byte, keyID, bridgeID, userID string) string {
	mac := hmac.New(sha256.New, challengeSecret)
	mac.Write([]byte(keyID + ":" + bridgeID + ":" + userID))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyChallengeHMAC(challengeSecret []byte, keyID, bridgeID, userID, expected string) bool {
	computed := GenerateChallengeHMAC(challengeSecret, keyID, bridgeID, userID)
	return hmac.Equal([]byte(computed), []byte(expected))
}

func GenerateTOTPCode(keyID string, window int64) string {
	step := time.Now().Unix() / 30
	if window > 0 {
		step = window
	}
	mac := hmac.New(sha256.New, []byte(keyID))
	mac.Write([]byte(fmt.Sprintf("%d", step)))
	return hex.EncodeToString(mac.Sum(nil))[:12]
}

func VerifyTOTPCode(keyID, code string) bool {
	now := time.Now().Unix() / 30
	for delta := int64(-1); delta <= 1; delta++ {
		mac := hmac.New(sha256.New, []byte(keyID))
		mac.Write([]byte(fmt.Sprintf("%d", now+delta)))
		expected := hex.EncodeToString(mac.Sum(nil))[:12]
		if hmac.Equal([]byte(code), []byte(expected)) {
			return true
		}
	}
	return false
}

func (al *AuditLog) Log(entry AuditEntry) {
	if al == nil {
		return
	}
	al.mu.Lock()
	defer al.mu.Unlock()

	entry.Timestamp = time.Now()
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	f, err := os.OpenFile(al.persistPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(data, '\n'))
}

func (al *AuditLog) ReadEntries(limit int) []AuditEntry {
	if al == nil {
		return nil
	}
	al.mu.Lock()
	defer al.mu.Unlock()

	data, err := os.ReadFile(al.persistPath)
	if err != nil {
		return nil
	}

	var entries []AuditEntry
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e AuditEntry
		if json.Unmarshal(line, &e) == nil {
			entries = append(entries, e)
		}
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	return entries
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
