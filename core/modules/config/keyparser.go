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
	Version    int      `json:"v"`
	Name       string   `json:"name,omitempty"`
	KeyID      string   `json:"kid,omitempty"`
	ExpiresAt  int64    `json:"exp,omitempty"`
	Server     string   `json:"server"`
	ServerAlts []string `json:"server_alts,omitempty"`
	ServerTCP  string   `json:"server_tcp,omitempty"`
	ServerWS   string   `json:"server_ws,omitempty"`
	PSK        string   `json:"psk"`
	ServerPub  string   `json:"pub"`
	ObfsPreset string   `json:"obfs"`
	Transport  string   `json:"transport"`

	ObfsProfile string `json:"obfs_profile,omitempty"`

	EnableML  bool `json:"enable_ml"`
	EnableFTE bool `json:"enable_fte"`

	EnableASNBypass    bool   `json:"asn_bypass"`
	TLSFingerprint     string `json:"tls_fingerprint,omitempty"`
	DomainFrontHost    string `json:"front_host,omitempty"`
	ResidentialProxies string `json:"res_proxies,omitempty"`

	RussianService string `json:"russian_service,omitempty"`

	ChameleonAddr     string `json:"chameleon_addr,omitempty"`
	ChameleonSNI      string `json:"chameleon_sni,omitempty"`
	ChameleonQUICAddr string `json:"chameleon_quic_addr,omitempty"`

	TransportConfig map[string]interface{} `json:"transport_config,omitempty"`

	MLServerURL string `json:"ml_server_url,omitempty"`

	MLToken string `json:"ml_token,omitempty"`

	SubscriptionURL string `json:"sub_url,omitempty"`
}

func (ck *ConnectionKey) IsExpired() bool {
	return ck.ExpiresAt > 0 && time.Now().Unix() > ck.ExpiresAt
}

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
		Server:            ck.Server,
		ServerAlts:        append([]string(nil), ck.ServerAlts...),
		ServerTCP:         ck.ServerTCP,
		ServerWS:          ck.ServerWS,
		PSK:               ck.PSK,
		ServerPub:         ck.ServerPub,
		ObfsPreset:        ck.ObfsPreset,
		AppProfile:        ck.ObfsProfile,
		RussianService:    ck.RussianService,
		TransportConfig:   ck.TransportConfig,
		Transport:         ck.Transport,
		MLServerURL:       ck.MLServerURL,
		MLToken:           ck.MLToken,
		ChameleonAddr:     ck.ChameleonAddr,
		ChameleonSNI:      ck.ChameleonSNI,
		ChameleonQUICAddr: ck.ChameleonQUICAddr,
	}

	switch ck.Transport {
	case "tcp":
		cfg.UDPOnly = false
	case "udp":
		cfg.UDPOnly = true
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

type KeyGenOptions struct {
	Name              string
	KeyID             string
	ExpiresAt         int64
	ObfsProfile       string
	ObfsPreset        string
	Transport         string
	ASNBypass         bool
	TLSFingerprint    string
	DefaultMarionette string
	DomainFront       string
	RussianService    string
	TransportConfig   map[string]interface{}
}

func FetchSubscription(rawURL string) ([]*ConnectionKey, error) {
	resp, err := subscriptionHTTPGet(rawURL)
	if err != nil {
		return nil, fmt.Errorf("subscription fetch: %w", err)
	}
	body := strings.TrimSpace(resp)

	var arr []string
	if json.Unmarshal([]byte(body), &arr) == nil {
		return parseKeyList(arr)
	}

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
	if sec == "reality" || sec == "tls" {
		ck.ServerPub = q.Get("pbk")
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

	ck := &ConnectionKey{
		Version:    1,
		Name:       v.Name,
		Server:     net.JoinHostPort(v.Add, port),
		PSK:        v.ID,
		Transport:  mapXRayTransport(v.Net),
		ObfsPreset: "default",
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
	ck := &ConnectionKey{
		Version:    1,
		Name:       u.Fragment,
		Server:     net.JoinHostPort(host, port),
		PSK:        password,
		Transport:  mapXRayTransport(q.Get("type")),
		ObfsPreset: "default",
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
		if decoded, err := base64.StdEncoding.DecodeString(userinfo); err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
			}
		} else {
			method = userinfo
			password, _ = u.User.Password()
		}
	}

	_ = method
	return &ConnectionKey{
		Version:    1,
		Name:       name,
		Server:     net.JoinHostPort(host, port),
		PSK:        password,
		Transport:  "tcp",
		ObfsPreset: "default",
	}, nil
}

func mapXRayTransport(t string) string {
	switch strings.ToLower(t) {
	case "grpc":
		return "grpc"
	case "quic":
		return "quic"
	case "tcp", "":
		return "tcp"
	default:
		return "tcp"
	}
}
