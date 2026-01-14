package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ConnectionKey holds parsed connection key data
type ConnectionKey struct {
	Version    int    `json:"v"`
	Name       string `json:"name,omitempty"`
	Server     string `json:"server"`               // Primary server (UDP)
	ServerTCP  string `json:"server_tcp,omitempty"` // TCP server (optional)
	ServerWS   string `json:"server_ws,omitempty"`  // WebSocket server (optional)
	PSK        string `json:"psk"`                  // Pre-shared key
	ServerPub  string `json:"pub"`                  // Server public key
	ObfsPreset string `json:"obfs"`                 // Obfuscation level: default, stealth, aggressive
	Transport  string `json:"transport"`            // auto|tcp|ws|udp

	// Behavioral obfuscation profile (vk, telegram, instagram, max, wechat, facebook, vk_ios, etc.)
	ObfsProfile string `json:"obfs_profile,omitempty"`

	// ML and FTE obfuscation
	EnableML  bool `json:"enable_ml"`  // Enable ML obfuscation
	EnableFTE bool `json:"enable_fte"` // Enable FTE obfuscation

	// ASN Bypass - for VPN/Datacenter IP detection evasion
	EnableASNBypass    bool   `json:"asn_bypass"`                // Enable ASN bypass
	TLSFingerprint     string `json:"tls_fingerprint,omitempty"` // Browser fingerprint: chrome, firefox, safari
	DomainFrontHost    string `json:"front_host,omitempty"`      // Domain fronting host (CDN)
	ResidentialProxies string `json:"res_proxies,omitempty"`     // Comma-separated residential proxy list

	// Phantom protocol (TLS masquerading)
	PhantomEnabled bool   `json:"phantom,omitempty"`     // Enable Phantom protocol
	PhantomSNI     string `json:"phantom_sni,omitempty"` // SNI for Phantom (e.g., cloudflare.com)
	PhantomShortID string `json:"phantom_sid,omitempty"` // Phantom short ID
}

// ParseConnectionKey parses a whispera:// or wpn:// connection key
func ParseConnectionKey(key string) (*ConnectionKey, error) {
	// Remove leading whitespace
	key = strings.TrimSpace(key)

	// Check for URL format first (contains params)
	// Example: whispera://IP:PORT?key=...&pub=...&profile=vk&phantom=1
	if strings.HasPrefix(key, "whispera://") && strings.Contains(key, "?") {
		// Parse as URL
		u, err := url.Parse(key)
		if err != nil {
			return nil, fmt.Errorf("invalid URL key format: %w", err)
		}

		ck := &ConnectionKey{
			Version:     1,
			Server:      u.Host,
			Transport:   "auto",
			ObfsPreset:  "default",
			ObfsProfile: "vk", // VK Messenger as default behavioral profile
			EnableML:    true,
			EnableFTE:   true,
		}

		q := u.Query()
		ck.PSK = q.Get("key")
		ck.ServerPub = q.Get("pub")

		// Basic settings
		if val := q.Get("obfs"); val != "" {
			ck.ObfsPreset = val
		}
		if val := q.Get("transport"); val != "" {
			ck.Transport = val
		}
		if val := q.Get("name"); val != "" {
			ck.Name = val
		}

		// Behavioral obfuscation profile
		if val := q.Get("profile"); val != "" {
			ck.ObfsProfile = val
		}

		// Phantom protocol
		if q.Get("phantom") == "1" || q.Get("phantom") == "true" {
			ck.PhantomEnabled = true
		}
		if val := q.Get("sni"); val != "" {
			ck.PhantomSNI = val
			ck.PhantomEnabled = true
		}
		if val := q.Get("sid"); val != "" {
			ck.PhantomShortID = val
		}

		// ASN Bypass
		if q.Get("asn") == "1" || q.Get("asn_bypass") == "1" {
			ck.EnableASNBypass = true
		}
		if val := q.Get("tls"); val != "" {
			ck.TLSFingerprint = val
		}
		if val := q.Get("front"); val != "" {
			ck.DomainFrontHost = val
		}

		return ck, nil
	}

	// Legacy/Standard format: Base64 JSON blob
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
		AppProfile: ck.ObfsProfile, // Map application profile
	}

	// Set transport preference
	switch ck.Transport {
	case "tcp":
		cfg.UDPOnly = false
	case "udp":
		cfg.UDPOnly = true
	}

	// Map Phantom Configuration
	if ck.PhantomEnabled {
		cfg.Phantom = &ClientPhantomConfig{
			Enabled:         true,
			SNI:             ck.PhantomSNI,
			ShortId:         ck.PhantomShortID,
			ServerPublicKey: ck.ServerPub, // Use the server public key for Phantom
		}
	}

	// Map ASN Bypass Configuration
	if ck.EnableASNBypass {
		cfg.ASNBypass = &ClientASNBypassConfig{
			Enabled:         true,
			Strategy:        "tls_masquerade", // Default to TLS masquerade
			TLSFingerprint:  ck.TLSFingerprint,
			DomainFrontHost: ck.DomainFrontHost,
		}
		// If domain fronting host is set, prefer that strategy
		if ck.DomainFrontHost != "" {
			cfg.ASNBypass.Strategy = "domain_fronting"
		}
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

// GenerateConnectionKey creates a connection key from configuration (base64 format)
func GenerateConnectionKey(cfg *ClientConfig, name string) (string, error) {
	ck := ConnectionKey{
		Version:     1,
		Name:        name,
		Server:      cfg.Server,
		ServerTCP:   cfg.ServerTCP,
		ServerWS:    cfg.ServerWS,
		PSK:         cfg.PSK,
		ServerPub:   cfg.ServerPub,
		ObfsPreset:  cfg.ObfsPreset,
		ObfsProfile: "vk", // VK Messenger as default
		Transport:   "auto",
		EnableML:    true,
		EnableFTE:   true,
	}

	data, err := json.Marshal(ck)
	if err != nil {
		return "", fmt.Errorf("failed to encode key: %w", err)
	}

	return "whispera://" + base64.StdEncoding.EncodeToString(data), nil
}

// GenerateConnectionKeyURL creates a human-readable URL format key
// Format: whispera://server:port?key=...&pub=...&profile=vk&phantom=1&sni=cloudflare.com
func GenerateConnectionKeyURL(cfg *ClientConfig, opts *KeyGenOptions) string {
	if opts == nil {
		opts = &KeyGenOptions{
			ObfsProfile: "vk",
		}
	}

	// Default profile to VK if not specified
	if opts.ObfsProfile == "" {
		opts.ObfsProfile = "vk"
	}

	params := url.Values{}

	// Required params
	if cfg.PSK != "" {
		params.Set("key", cfg.PSK)
	}
	if cfg.ServerPub != "" {
		params.Set("pub", cfg.ServerPub)
	}

	// Behavioral profile (default: vk)
	params.Set("profile", opts.ObfsProfile)

	// Optional params
	if opts.Name != "" {
		params.Set("name", opts.Name)
	}
	if opts.Transport != "" && opts.Transport != "auto" {
		params.Set("transport", opts.Transport)
	}
	if opts.ObfsPreset != "" && opts.ObfsPreset != "default" {
		params.Set("obfs", opts.ObfsPreset)
	}

	// Phantom protocol
	if opts.PhantomEnabled {
		params.Set("phantom", "1")
		if opts.PhantomSNI != "" {
			params.Set("sni", opts.PhantomSNI)
		}
		if opts.PhantomShortID != "" {
			params.Set("sid", opts.PhantomShortID)
		}
	}

	// ASN Bypass
	if opts.ASNBypass {
		params.Set("asn", "1")
		if opts.TLSFingerprint != "" {
			params.Set("tls", opts.TLSFingerprint)
		}
		if opts.DomainFront != "" {
			params.Set("front", opts.DomainFront)
		}
	}

	return fmt.Sprintf("whispera://%s?%s", cfg.Server, params.Encode())
}

// KeyGenOptions holds options for URL key generation
type KeyGenOptions struct {
	Name           string
	ObfsProfile    string // vk, telegram, instagram, max, wechat, facebook, vk_ios, etc.
	ObfsPreset     string // default, stealth, aggressive
	Transport      string // auto, tcp, udp, ws
	PhantomEnabled bool
	PhantomSNI     string
	PhantomShortID string
	ASNBypass      bool
	TLSFingerprint string
	DomainFront    string
}

// DefaultKeyGenOptions returns default options with VK profile
func DefaultKeyGenOptions() *KeyGenOptions {
	return &KeyGenOptions{
		ObfsProfile:    "vk",
		ObfsPreset:     "default",
		Transport:      "auto",
		PhantomEnabled: true,
		PhantomSNI:     "cloudflare.com",
		ASNBypass:      true,
		TLSFingerprint: "chrome",
	}
}

// ValidateKey validates a connection key string without fully parsing
func ValidateKey(key string) error {
	_, err := ParseConnectionKey(key)
	return err
}
