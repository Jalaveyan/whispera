package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type ConnectionKey struct {
	Version    int    `json:"v"`
	Name       string `json:"name,omitempty"`
	KeyID      string `json:"kid,omitempty"`
	ExpiresAt  int64  `json:"exp,omitempty"`
	Server     string `json:"server"`
	ServerTCP  string `json:"server_tcp,omitempty"`
	ServerWS   string `json:"server_ws,omitempty"`
	PSK        string `json:"psk"`
	ServerPub  string `json:"pub"`
	ObfsPreset string `json:"obfs"`
	Transport  string `json:"transport"`

	ObfsProfile string `json:"obfs_profile,omitempty"`

	EnableML  bool `json:"enable_ml"`
	EnableFTE bool `json:"enable_fte"`

	EnableASNBypass    bool   `json:"asn_bypass"`
	TLSFingerprint     string `json:"tls_fingerprint,omitempty"`
	DomainFrontHost    string `json:"front_host,omitempty"`
	ResidentialProxies string `json:"res_proxies,omitempty"`

	PhantomEnabled bool   `json:"phantom,omitempty"`
	PhantomSNI     string `json:"phantom_sni,omitempty"`
	PhantomShortID string `json:"phantom_sid,omitempty"`
	RussianService string `json:"russian_service,omitempty"`

	TransportConfig map[string]interface{} `json:"transport_config,omitempty"`
}

func (ck *ConnectionKey) IsExpired() bool {
	return ck.ExpiresAt > 0 && time.Now().Unix() > ck.ExpiresAt
}

func ParseConnectionKey(key string) (*ConnectionKey, error) {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "whispera://") && strings.Contains(key, "?") {
		u, err := url.Parse(key)
		if err != nil {
			return nil, fmt.Errorf("invalid URL key format: %w", err)
		}

		ck := &ConnectionKey{
			Version:     1,
			Server:      u.Host,
			Transport:   "auto",
			ObfsPreset:  "default",
			ObfsProfile: "vk", 
			EnableML:    true,
			EnableFTE:   true,
		}

		q := u.Query()
		ck.PSK = q.Get("psk")
		if ck.PSK == "" {
			ck.PSK = q.Get("key")
		}
		ck.ServerPub = q.Get("pub")

		if val := q.Get("obfs"); val != "" {
			ck.ObfsPreset = val
		}
		if val := q.Get("transport"); val != "" {
			ck.Transport = val
		}
		if val := q.Get("name"); val != "" {
			ck.Name = val
		}

		if val := q.Get("profile"); val != "" {
			ck.ObfsProfile = val
		}
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

		if q.Get("asn") == "1" || q.Get("asn_bypass") == "1" {
			ck.EnableASNBypass = true
		}
		if val := q.Get("tls"); val != "" {
			ck.TLSFingerprint = val
		}
		if val := q.Get("front"); val != "" {
			ck.DomainFrontHost = val
		}

		if val := q.Get("front"); val != "" {
			ck.DomainFrontHost = val
		}

		if val := q.Get("russian"); val != "" {
			ck.RussianService = val
		} else if val := q.Get("rs"); val != "" {
			ck.RussianService = val
		}

		if val := q.Get("kid"); val != "" {
			ck.KeyID = val
		}
		if val := q.Get("exp"); val != "" {
			var exp int64
			fmt.Sscanf(val, "%d", &exp)
			ck.ExpiresAt = exp
		}

		if ck.IsExpired() {
			return nil, fmt.Errorf("connection key expired")
		}

		if val := q.Get("cfg"); val != "" {
			decoded, err := base64.RawURLEncoding.DecodeString(val)
			if err == nil {
				var tc map[string]interface{}
				if json.Unmarshal(decoded, &tc) == nil {
					ck.TransportConfig = tc
				}
			}
		}

		return ck, nil
	}

	key = strings.TrimPrefix(key, "whispera://")
	key = strings.TrimPrefix(key, "wpn://")

	data, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(key)
		if err != nil {
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

	if ck.IsExpired() {
		return nil, fmt.Errorf("connection key expired")
	}

	if ck.Server == "" && ck.ServerTCP == "" {
		return nil, fmt.Errorf("key must contain at least one server address (server or server_tcp)")
	}

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

func (ck *ConnectionKey) ToClientConfig() *ClientConfig {
	cfg := &ClientConfig{
		Server:          ck.Server,
		ServerTCP:       ck.ServerTCP,
		ServerWS:        ck.ServerWS,
		PSK:             ck.PSK,
		ServerPub:       ck.ServerPub,
		ObfsPreset:      ck.ObfsPreset,
		AppProfile:      ck.ObfsProfile,
		RussianService:  ck.RussianService,
		TransportConfig: ck.TransportConfig,
		Transport:       ck.Transport,
	}

	switch ck.Transport {
	case "tcp":
		cfg.UDPOnly = false
	case "udp":
		cfg.UDPOnly = true
	}

	if ck.PhantomEnabled {
		cfg.Phantom = &ClientPhantomConfig{
			Enabled:         true,
			SNI:             ck.PhantomSNI,
			ShortId:         ck.PhantomShortID,
			ServerPublicKey: ck.ServerPub,
			PSK:             ck.PSK,
		}
	}

	if ck.EnableASNBypass {
		cfg.ASNBypass = &ClientASNBypassConfig{
			Enabled:         true,
			Strategy:        "tls_masquerade",
			TLSFingerprint:  ck.TLSFingerprint,
			DomainFrontHost: ck.DomainFrontHost,
		}
		if ck.DomainFrontHost != "" {
			cfg.ASNBypass.Strategy = "domain_fronting"
		}
	}

	return cfg
}

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
	default:
		if ck.Server != "" {
			return ck.Server
		}
		return ck.ServerTCP
	}
}

func GenerateConnectionKey(cfg *ClientConfig, name string) (string, error) {
	ck := ConnectionKey{
		Version:     2,
		Name:        name,
		Server:      cfg.Server,
		ServerTCP:   cfg.ServerTCP,
		ServerWS:    cfg.ServerWS,
		PSK:         cfg.PSK,
		ServerPub:   cfg.ServerPub,
		ObfsPreset:  cfg.ObfsPreset,
		ObfsProfile: "vk",
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

func GenerateConnectionKeyURL(cfg *ClientConfig, opts *KeyGenOptions) string {
	if opts == nil {
		opts = &KeyGenOptions{
			ObfsProfile: "vk",
		}
	}

	if opts.ObfsProfile == "" {
		opts.ObfsProfile = "vk"
	}

	params := url.Values{}

	if cfg.PSK != "" {
		params.Set("key", cfg.PSK)
	}
	if cfg.ServerPub != "" {
		params.Set("pub", cfg.ServerPub)
	}
	params.Set("profile", opts.ObfsProfile)

	if opts.Name != "" {
		params.Set("name", opts.Name)
	}
	if opts.Transport != "" && opts.Transport != "auto" {
		params.Set("transport", opts.Transport)
	}
	if opts.ObfsPreset != "" && opts.ObfsPreset != "default" {
		params.Set("obfs", opts.ObfsPreset)
	}

	if opts.PhantomEnabled {
		params.Set("phantom", "1")
		if opts.PhantomSNI != "" {
			params.Set("sni", opts.PhantomSNI)
		}
		if opts.PhantomShortID != "" {
			params.Set("sid", opts.PhantomShortID)
		}
	}

	if opts.ASNBypass {
		params.Set("asn", "1")
		if opts.TLSFingerprint != "" {
			params.Set("tls", opts.TLSFingerprint)
		}
		if opts.DomainFront != "" {
			params.Set("front", opts.DomainFront)
		}
	}

	if cfg.RussianService != "" {
		params.Set("russian", cfg.RussianService)
	}

	if opts.KeyID != "" {
		params.Set("kid", opts.KeyID)
	}
	if opts.ExpiresAt > 0 {
		params.Set("exp", fmt.Sprintf("%d", opts.ExpiresAt))
	}

	if len(opts.TransportConfig) > 0 {
		cfgData, err := json.Marshal(opts.TransportConfig)
		if err == nil {
			params.Set("cfg", base64.RawURLEncoding.EncodeToString(cfgData))
		}
	}

	return fmt.Sprintf("whispera://%s?%s", cfg.Server, params.Encode())
}

type KeyGenOptions struct {
	Name              string
	KeyID             string
	ExpiresAt         int64
	ObfsProfile       string
	ObfsPreset        string
	Transport         string
	PhantomEnabled    bool
	PhantomSNI        string
	PhantomShortID    string
	ASNBypass         bool
	TLSFingerprint    string
	DefaultMarionette string
	DomainFront       string
	RussianService    string
	TransportConfig   map[string]interface{}
}

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

func ValidateKey(key string) error {
	_, err := ParseConnectionKey(key)
	return err
}
