package phantom

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type ClientConfig struct {
	ServerPublicKey string
	ShortId string
	PrivateKey []byte
}

type ClientAuth struct {
	config *ClientConfig
}

func NewClientAuth(cfg *ClientConfig) *ClientAuth {
	return &ClientAuth{config: cfg}
}

func (c *ClientAuth) GenerateAuthData() ([]byte, error) {
	data := make([]byte, 16)

	timestamp := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(data[0:8], timestamp)

	shortIdBytes, err := base64.StdEncoding.DecodeString(c.config.ShortId)
	if err != nil {
		shortIdBytes = []byte(c.config.ShortId)
	}
	copy(data[8:16], shortIdBytes)

	return data, nil
}

func (c *ClientAuth) GenerateAuthDataWithSignature() ([]byte, error) {
	data := make([]byte, 48)

	timestamp := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(data[0:8], timestamp)

	shortIdBytes, _ := base64.StdEncoding.DecodeString(c.config.ShortId)
	copy(data[8:16], shortIdBytes)

	if len(c.config.PrivateKey) == 32 && c.config.ServerPublicKey != "" {
		serverPub, err := base64.StdEncoding.DecodeString(c.config.ServerPublicKey)
		if err == nil && len(serverPub) == 32 {
			sharedSecret, err := curve25519.X25519(c.config.PrivateKey, serverPub)
			if err == nil {
				copy(data[16:48], sharedSecret)
			}
		}
	}

	return data, nil
}

func (c *ClientAuth) CreatePhantomExtension() (extensionType uint16, extensionData []byte, err error) {
	authData, err := c.GenerateAuthData()
	if err != nil {
		return 0, nil, err
	}

	return phantomExtensionID, authData, nil
}

func ValidateServerPublicKey(key string) bool {
	if len(key) >= 43 {
		if b, err := base64.StdEncoding.DecodeString(key); err == nil && len(b) == 32 {
			return true
		}
	}
	return false
}

func (c *ClientAuth) GenerateSessionID() (clientRandom, sessionID []byte, err error) {
	if c.config.ServerPublicKey == "" {
		return nil, nil, fmt.Errorf("server public key required")
	}

	serverPub, err := base64.StdEncoding.DecodeString(c.config.ServerPublicKey)
	if err != nil || len(serverPub) != 32 {
		return nil, nil, fmt.Errorf("invalid server public key (must be 32 bytes Base64)")
	}

	ephemeralPriv := make([]byte, 32)
	if len(c.config.PrivateKey) == 32 {
		copy(ephemeralPriv, c.config.PrivateKey)
	} else if _, err := rand.Read(ephemeralPriv); err != nil {
		return nil, nil, err
	}

	ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := curve25519.X25519(ephemeralPriv, serverPub)
	if err != nil {
		return nil, nil, err
	}

	hkdfR := hkdf.New(sha256.New, sharedSecret, nil, []byte("whispera-auth-key"))
	authKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfR, authKey); err != nil {
		return nil, nil, err
	}

	timestamp := uint64(time.Now().UnixMilli())
	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte("whispera-session-id"))
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, timestamp)
	mac.Write(timestampBytes)
	hmacResult := mac.Sum(nil)

	sessionID = make([]byte, 32)
	binary.BigEndian.PutUint64(sessionID[0:8], timestamp)
	copy(sessionID[8:32], hmacResult[:24])
	return ephemeralPub, sessionID, nil
}
