// Package phantom provides client-side Phantom protocol support
package phantom

import (
	"encoding/binary"
	"encoding/hex"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ClientConfig holds client-side Phantom configuration
type ClientConfig struct {
	// ServerPublicKey is the server's x25519 public key (hex encoded)
	ServerPublicKey string

	// ShortId is the client's identifier
	ShortId string

	// PrivateKey is the client's x25519 private key (optional, for signature)
	PrivateKey []byte
}

// ClientAuth generates authentication data for ClientHello extension
type ClientAuth struct {
	config *ClientConfig
}

// NewClientAuth creates a new client authenticator
func NewClientAuth(cfg *ClientConfig) *ClientAuth {
	return &ClientAuth{config: cfg}
}

// GenerateAuthData creates authentication data to embed in ClientHello
// Format:
//
//	[0-7]   timestamp (unix ms, big-endian)
//	[8-15]  shortId (8 bytes, zero-padded)
func (c *ClientAuth) GenerateAuthData() ([]byte, error) {
	data := make([]byte, 16)

	// Timestamp
	timestamp := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(data[0:8], timestamp)

	// ShortId (hex decode and pad to 8 bytes)
	shortIdBytes, err := hex.DecodeString(c.config.ShortId)
	if err != nil {
		// Use raw bytes if not hex
		shortIdBytes = []byte(c.config.ShortId)
	}
	copy(data[8:16], shortIdBytes)

	return data, nil
}

// GenerateAuthDataWithSignature creates signed authentication data
// Format:
//
//	[0-7]   timestamp (unix ms, big-endian)
//	[8-15]  shortId (8 bytes, zero-padded)
//	[16-48] x25519 shared secret (32 bytes)
func (c *ClientAuth) GenerateAuthDataWithSignature() ([]byte, error) {
	data := make([]byte, 48)

	// Timestamp
	timestamp := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(data[0:8], timestamp)

	// ShortId
	shortIdBytes, _ := hex.DecodeString(c.config.ShortId)
	copy(data[8:16], shortIdBytes)

	// Generate signature if we have keys
	if len(c.config.PrivateKey) == 32 && c.config.ServerPublicKey != "" {
		serverPub, err := hex.DecodeString(c.config.ServerPublicKey)
		if err == nil && len(serverPub) == 32 {
			// Compute shared secret
			sharedSecret, err := curve25519.X25519(c.config.PrivateKey, serverPub)
			if err == nil {
				copy(data[16:48], sharedSecret)
			}
		}
	}

	return data, nil
}

// CreatePhantomExtension creates a TLS extension for Phantom authentication
func (c *ClientAuth) CreatePhantomExtension() (extensionType uint16, extensionData []byte, err error) {
	authData, err := c.GenerateAuthData()
	if err != nil {
		return 0, nil, err
	}

	return phantomExtensionID, authData, nil
}

// ValidateServerPublicKey validates the server's public key
func ValidateServerPublicKey(hexKey string) bool {
	if len(hexKey) != 64 { // 32 bytes = 64 hex chars
		return false
	}
	_, err := hex.DecodeString(hexKey)
	return err == nil
}
