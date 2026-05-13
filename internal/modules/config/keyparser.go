package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
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
	// ServerAlts lists additional "host:port" endpoints that accept the same
	// key. Used for seamless port migration: operators add the new port to
	// the list, wait for clients to pick it up, then drop the old entry.
	ServerAlts []string `json:"server_alts,omitempty"`
	ServerTCP  string   `json:"server_tcp,omitempty"`
	ServerWS   string   `json:"server_ws,omitempty"`
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

	MLServerURL string `json:"ml_server_url,omitempty"`

	MLToken string `json:"ml_token,omitempty"`

	// SubscriptionURL points to an endpoint that returns a fresh connection key
	// (or a newline-separated list of keys). The client refreshes it periodically.
	SubscriptionURL string `json:"sub_url,omitempty"`
}

func (ck *ConnectionKey) IsExpired() bool {
	return ck.ExpiresAt > 0 && time.Now().Unix() > ck.ExpiresAt
}

// ParseConnectionKey parses a connection key in any supported format:
//   - whispera://... — native Whispera format
//   - vless://uuid@server:port?... — XRay/VLESS
//   - vmess://base64json — V2Ray VMess
//   - trojan://password@server:port?... — Trojan
//   - ss://... — Shadowsocks
//   - plain base64 JSON — native compact format
func ParseConnectionKey(key string) (*ConnectionKey, error) {
	key = strings.TrimSpace(key)

	switch {
	case strings.HasPrefix(key, "vless://"):
		return parseVLESSKey(key)
	case strings.HasPrefix(key, "vmess://"):
		return parseVMessKey(key)
	case strings.HasPrefix(key, "trojan://"):
		return parseTrojanKey(key)
	case strings.HasPrefix(key, "ss://"):
		return parseSSKey(key)
	}

	if strings.HasPrefix(key, "whispera://") && strings.Contains(key, "?") {
		u, err := url.Parse(key)
		if err != nil {
			return nil, fmt.Errorf("invalid URL key format: %w", err)
		}

		hostPart := u.Host
		if hostPart != "" {
			if decoded, err := base64.StdEncoding.DecodeString(hostPart); err == nil {
				if json.Valid(decoded) {
					var ck ConnectionKey
					if err := json.Unmarshal(decoded, &ck); err == nil {
						if ck.IsExpired() {
							return nil, fmt.Errorf("connection key expired")
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
						q := u.Query()
						if val := q.Get("ml_token"); val != "" {
							ck.MLToken = val
						}
						if val := q.Get("ml"); val != "" && ck.MLServerURL == "" {
							ck.MLServerURL = val
						}
						return &ck, nil
					}
				}
			}
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

		if val := q.Get("ml"); val != "" {
			ck.MLServerURL = val
		}
		if val := q.Get("ml_token"); val != "" {
			ck.MLToken = val
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
		ServerAlts:      append([]string(nil), ck.ServerAlts...),
		ServerTCP:       ck.ServerTCP,
		ServerWS:        ck.ServerWS,
		PSK:             ck.PSK,
		ServerPub:       ck.ServerPub,
		ObfsPreset:      ck.ObfsPreset,
		AppProfile:      ck.ObfsProfile,
		RussianService:  ck.RussianService,
		TransportConfig: ck.TransportConfig,
		Transport:       ck.Transport,
		MLServerURL:     ck.MLServerURL,
		MLToken:         ck.MLToken,
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

	if srv := ck.GetPrimaryServer(); srv != "" {
		host, _, err := net.SplitHostPort(srv)
		if err != nil {
			host = srv
		}
		cfg.BridgeDiscoveryURL = "https://" + host + "/api/bridge-list"
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
		ServerAlts:  append([]string(nil), cfg.ServerAlts...),
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

	if cfg.MLServerURL != "" {
		params.Set("ml", cfg.MLServerURL)
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

// FetchSubscription downloads a subscription URL and returns all valid
// connection keys found in the response. Supports:
//   - Single key (whispera://, vless://, vmess://, etc.)
//   - Newline-separated list of keys
//   - Base64-encoded newline-separated list (standard Clash/Sing-box format)
//   - JSON array of key strings
func FetchSubscription(rawURL string) ([]*ConnectionKey, error) {
	resp, err := subscriptionHTTPGet(rawURL)
	if err != nil {
		return nil, fmt.Errorf("subscription fetch: %w", err)
	}
	body := strings.TrimSpace(resp)

	// Try JSON array first.
	var arr []string
	if json.Unmarshal([]byte(body), &arr) == nil {
		return parseKeyList(arr)
	}

	// Try base64-encoded block (standard VPN subscription format).
	if decoded, err := base64.StdEncoding.DecodeString(body); err == nil {
		body = strings.TrimSpace(string(decoded))
	} else if decoded, err := base64.URLEncoding.DecodeString(body); err == nil {
		body = strings.TrimSpace(string(decoded))
	}

	lines := strings.Split(body, "\n")
	return parseKeyList(lines)
}

func parseKeyList(lines []string) ([]*ConnectionKey, error) {
	var out []*ConnectionKey
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ck, err := ParseConnectionKey(line)
		if err != nil {
			continue
		}
		if ck.IsExpired() {
			continue
		}
		out = append(out, ck)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("subscription: no valid keys found")
	}
	return out, nil
}

// parseVLESSKey parses vless://uuid@server:port?type=ws&security=tls&sni=...&path=/ws#name
func parseVLESSKey(raw string) (*ConnectionKey, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("vless: parse url: %w", err)
	}
	uuid := u.User.Username()
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	q := u.Query()

	ck := &ConnectionKey{
		Version:    1,
		Name:       u.Fragment,
		Server:     net.JoinHostPort(host, port),
		PSK:        uuid,
		Transport:  mapXRayTransport(q.Get("type")),
		ObfsPreset: "default",
	}

	sec := strings.ToLower(q.Get("security"))
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("host")
	}
	if sni == "" {
		sni = host
	}

	if sec == "reality" || sec == "tls" {
		ck.PhantomEnabled = true
		ck.PhantomSNI = sni
		ck.ServerPub = q.Get("pbk")
		ck.PhantomShortID = q.Get("sid")
	}

	tc := make(map[string]interface{})
	if path := q.Get("path"); path != "" {
		tc["ws_path"] = path
	}
	if host := q.Get("host"); host != "" {
		tc["ws_sni"] = host
	}
	if svc := q.Get("serviceName"); svc != "" {
		tc["grpc_service"] = svc
	}
	if len(tc) > 0 {
		ck.TransportConfig = tc
	}

	return ck, nil
}

// parseVMessKey parses vmess://base64json (V2Ray format).
func parseVMessKey(raw string) (*ConnectionKey, error) {
	b64 := strings.TrimPrefix(raw, "vmess://")
	b64 = strings.TrimRight(b64, "#")
	if idx := strings.Index(b64, "#"); idx >= 0 {
		b64 = b64[:idx]
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("vmess: decode base64: %w", err)
		}
	}

	var v struct {
		Name    string      `json:"ps"`
		Add     string      `json:"add"`
		Port    interface{} `json:"port"`
		ID      string      `json:"id"`
		Net     string      `json:"net"`
		Type    string      `json:"type"`
		Host    string      `json:"host"`
		Path    string      `json:"path"`
		TLS     string      `json:"tls"`
		SNI     string      `json:"sni"`
		SvcName string      `json:"serviceName"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("vmess: parse json: %w", err)
	}

	port := "443"
	switch p := v.Port.(type) {
	case float64:
		port = fmt.Sprintf("%d", int(p))
	case string:
		if p != "" {
			port = p
		}
	}

	sni := v.SNI
	if sni == "" {
		sni = v.Host
	}
	if sni == "" {
		sni = v.Add
	}

	ck := &ConnectionKey{
		Version:    1,
		Name:       v.Name,
		Server:     net.JoinHostPort(v.Add, port),
		PSK:        v.ID,
		Transport:  mapXRayTransport(v.Net),
		ObfsPreset: "default",
	}
	if strings.ToLower(v.TLS) == "tls" {
		ck.PhantomEnabled = true
		ck.PhantomSNI = sni
	}
	tc := make(map[string]interface{})
	if v.Path != "" {
		tc["ws_path"] = v.Path
	}
	if v.Host != "" {
		tc["ws_sni"] = v.Host
	}
	if v.SvcName != "" {
		tc["grpc_service"] = v.SvcName
	}
	if len(tc) > 0 {
		ck.TransportConfig = tc
	}
	return ck, nil
}

// parseTrojanKey parses trojan://password@server:port?sni=...&type=...
func parseTrojanKey(raw string) (*ConnectionKey, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("trojan: parse url: %w", err)
	}
	password := u.User.Username()
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("host")
	}
	if sni == "" {
		sni = host
	}
	ck := &ConnectionKey{
		Version:        1,
		Name:           u.Fragment,
		Server:         net.JoinHostPort(host, port),
		PSK:            password,
		Transport:      mapXRayTransport(q.Get("type")),
		ObfsPreset:     "default",
		PhantomEnabled: true,
		PhantomSNI:     sni,
	}
	tc := make(map[string]interface{})
	if path := q.Get("path"); path != "" {
		tc["ws_path"] = path
	}
	if h := q.Get("host"); h != "" {
		tc["ws_sni"] = h
	}
	if svc := q.Get("serviceName"); svc != "" {
		tc["grpc_service"] = svc
	}
	if len(tc) > 0 {
		ck.TransportConfig = tc
	}
	return ck, nil
}

// parseSSKey parses Shadowsocks URI: ss://base64(method:password)@server:port#name
// or ss://method:password@server:port#name
func parseSSKey(raw string) (*ConnectionKey, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ss: parse url: %w", err)
	}
	name := u.Fragment
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	var method, password string
	if u.User != nil {
		userinfo := u.User.Username()
		// Try to decode as base64(method:password)
		if decoded, err := base64.StdEncoding.DecodeString(userinfo); err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
			}
		} else {
			// Plain method:password
			method = userinfo
			password, _ = u.User.Password()
		}
	}

	_ = method // method informs cipher selection but we map to PSK for now
	return &ConnectionKey{
		Version:    1,
		Name:       name,
		Server:     net.JoinHostPort(host, port),
		PSK:        password,
		Transport:  "tcp",
		ObfsPreset: "default",
	}, nil
}

// mapXRayTransport converts XRay/V2Ray transport names to Whispera transport names.
func mapXRayTransport(t string) string {
	switch strings.ToLower(t) {
	case "ws", "websocket":
		return "websocket"
	case "grpc":
		return "grpc"
	case "quic":
		return "quic"
	case "h2", "http":
		return "h2c"
	case "tcp", "":
		return "tcp"
	default:
		return "tcp"
	}
}
