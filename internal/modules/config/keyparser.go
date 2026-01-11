package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ConnectionKey holds parsed connection key data
type ConnectionKey struct {
	Version    int    `json:"v"`
	Name       string `json:"name"`
	Server     string `json:"server"`     // Primary server (UDP)
	ServerTCP  string `json:"server_tcp"` // TCP server (optional)
	ServerWS   string `json:"server_ws"`  // WebSocket server (optional)
	PSK        string `json:"psk"`        // Pre-shared key
	ServerPub  string `json:"pub"`        // Server public key
	ObfsPreset string `json:"obfs"`       // Obfuscation profile: default, stealth, aggressive
	Transport  string `json:"transport"`  // auto|tcp|ws|udp
	EnableML   bool   `json:"enable_ml"`  // Enable ML obfuscation
	EnableFTE  bool   `json:"enable_fte"` // Enable FTE obfuscation

	// ASN Bypass - for VPN/Datacenter IP detection evasion
	EnableASNBypass    bool   `json:"asn_bypass"`      // Enable ASN bypass
	TLSFingerprint     string `json:"tls_fingerprint"` // Browser fingerprint: chrome, firefox, safari
	DomainFrontHost    string `json:"front_host"`      // Domain fronting host (CDN)
	ResidentialProxies string `json:"res_proxies"`     // Comma-separated residential proxy list
}

// ParseConnectionKey parses a whispera:// or wpn:// connection key
func ParseConnectionKey(key string) (*ConnectionKey, error) {
	// Remove protocol prefix
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, "whispera://")
	key = strings.TrimPrefix(key, "wpn://")

	// Try standard Base64 first
	data, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		// Try URL-safe Base64
		data, err = base64.URLEncoding.DecodeString(key)
		if err != nil {
			// Try RawURL encoding (no padding)
			data, err = base64.RawURLEncoding.DecodeString(key)
			if err != nil {
				return nil, fmt.Errorf("invalid key encoding: %w", err)
			}
		}
	}

	var ck ConnectionKey
	if err := json.Unmarshal(data, &ck); err != nil {
		return nil, fmt.Errorf("invalid key format: %w", err)
	}

	// Validate - must have at least one server address
	if ck.Server == "" && ck.ServerTCP == "" {
		return nil, fmt.Errorf("key must contain at least one server address (server or server_tcp)")
	}

	// Set defaults
	if ck.Transport == "" {
		ck.Transport = "auto"
	}
	if ck.ObfsPreset == "" {
		ck.ObfsPreset = "default"
	}
	if ck.Version == 0 {
		ck.Version = 1
	}

	return &ck, nil
}

// ToClientConfig converts ConnectionKey to ClientConfig
func (ck *ConnectionKey) ToClientConfig() *ClientConfig {
	cfg := &ClientConfig{
		Server:     ck.Server,
		ServerTCP:  ck.ServerTCP,
		ServerWS:   ck.ServerWS,
		PSK:        ck.PSK,
		ServerPub:  ck.ServerPub,
		ObfsPreset: ck.ObfsPreset,
	}

	// Set transport preference
	switch ck.Transport {
	case "tcp":
		cfg.UDPOnly = false
	case "udp":
		cfg.UDPOnly = true
	}

	return cfg
}

// GetPrimaryServer returns the best server address based on transport preference
func (ck *ConnectionKey) GetPrimaryServer() string {
	switch ck.Transport {
	case "tcp":
		if ck.ServerTCP != "" {
			return ck.ServerTCP
		}
		return ck.Server
	case "ws":
		if ck.ServerWS != "" {
			return ck.ServerWS
		}
		return ck.ServerTCP
	case "udp":
		return ck.Server
	default: // auto
		// Prefer UDP, fallback to TCP
		if ck.Server != "" {
			return ck.Server
		}
		return ck.ServerTCP
	}
}

// GenerateConnectionKey creates a connection key from configuration
func GenerateConnectionKey(cfg *ClientConfig, name string) (string, error) {
	ck := ConnectionKey{
		Version:    1,
		Name:       name,
		Server:     cfg.Server,
		ServerTCP:  cfg.ServerTCP,
		ServerWS:   cfg.ServerWS, // Optional
		PSK:        cfg.PSK,
		ServerPub:  cfg.ServerPub,
		ObfsPreset: cfg.ObfsPreset,
		Transport:  "auto",
		EnableML:   true,
		EnableFTE:  true,
	}

	// Don't include empty optional fields
	if ck.ServerWS == "" {
		ck.ServerWS = ""
	}

	data, err := json.Marshal(ck)
	if err != nil {
		return "", fmt.Errorf("failed to encode key: %w", err)
	}

	return "whispera://" + base64.StdEncoding.EncodeToString(data), nil
}

// ValidateKey validates a connection key string without fully parsing
func ValidateKey(key string) error {
	_, err := ParseConnectionKey(key)
	return err
}
