package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: duration must be a scalar, keeping default", value.Line)}}
	}

	if n, err := strconv.ParseInt(value.Value, 10, 64); err == nil {
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}

	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: cannot parse %q as duration (use integer seconds or '30s'), keeping default", value.Line, value.Value)}}
	}
	*d = Duration(dur)
	return nil
}

const (
	ModuleName    = "config.provider"
	ModuleVersion = "1.0.0"
)

type MLConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`

	ServerURL string `yaml:"server_url" json:"server_url"`

	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`

	TokenFile string `yaml:"token_file" json:"token_file"`
}

type ServerConfig struct {
	Server         ServerSettings     `yaml:"server"`
	Transport      TransportConfig    `yaml:"transport"`
	Session        SessionConfig      `yaml:"session"`
	Routing        RoutingConfig      `yaml:"routing"`
	Obfuscation    ObfuscationConfig  `yaml:"obfuscation"`
	API            APIConfig          `yaml:"api"`
	Metrics        MetricsConfig      `yaml:"metrics"`
	Logging        LoggingConfig      `yaml:"logging"`
	Relay          RelayConfig        `yaml:"relay"`
	Chameleon      ChameleonConfig    `yaml:"chameleon"`
	Inbounds       []InboundConfig    `yaml:"inbounds" json:"inbounds"`
	Outbounds      []OutboundConfig   `yaml:"outbounds" json:"outbounds"`
	RelayMode      string             `yaml:"relay_mode" json:"relay_mode"`
	UpstreamServer string             `yaml:"upstream_server" json:"upstream_server"`
	Bridge         BridgeConfig       `yaml:"bridge" json:"bridge"`
	VKRelay        VKRelayConfig      `yaml:"vk_relay" json:"vk_relay"`
	StealthMode    string             `yaml:"stealth_mode" json:"stealth_mode"`
	Cache          CacheConfig        `yaml:"cache" json:"cache"`
	Database       DatabaseConfig     `yaml:"database" json:"database"`
	Notifications  NotificationConfig `yaml:"notifications" json:"notifications"`
	Bot            BotConfig          `yaml:"bot" json:"bot"`
	NATS           NATSConfig         `yaml:"nats" json:"nats"`
	Update         UpdateConfig       `yaml:"update" json:"update"`
	Correlation    CorrelationConfig  `yaml:"correlation" json:"correlation"`
	SNIBypass      SNIBypassConfig    `yaml:"sni_bypass" json:"sni_bypass"`
	ML             MLConfig           `yaml:"ml" json:"ml"`
}

func (p *Provider) SaveConfig(path string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.saveConfig(path)
}

func (p *Provider) saveConfig(path string) error {
	cfg := p.config

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	if err := p.UpdateChecksum(); err != nil {
		return fmt.Errorf("failed to update checksum: %w", err)
	}

	return nil
}

func (p *Provider) Update(fn func(*ServerConfig)) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldConfig := *p.config
	fn(p.config)

	if p.configPath != "" {
		if err := p.saveConfig(p.configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	p.notifyChanges(&oldConfig, p.config)

	go p.SendNotification("Configuration updated successfully via API.")

	return nil
}

func (p *Provider) watchConfigFile() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.fileWatcher:
			return
		case <-ticker.C:
			if p.configPath == "" {
				continue
			}

			info, err := os.Stat(p.configPath)
			if err != nil {
				continue
			}

			if info.ModTime().After(p.lastModified) {
				if err := p.VerifyIntegrity(); err != nil {
					p.AlertAndDie(fmt.Sprintf("Unauthorized configuration change detected! %v", err))
					return
				}

				if err := p.Reload(); err != nil {
					p.SetHealthy(false, fmt.Sprintf("reload error: %v", err))
				} else {
					p.lastModified = info.ModTime()
					go p.SendNotification("Configuration reloaded from disk (Authorized).")
				}
			}
		}
	}
}

func (p *Provider) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := p.Module.Init(ctx, cfg); err != nil {
		return err
	}
	if p.configPath != "" {
		if err := p.Load(p.configPath); err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if err := p.VerifyIntegrity(); err != nil {
			log.Printf("[config] Startup integrity mismatch — auto-repairing checksum: %v", err)
			_ = p.UpdateChecksum()
		}
	}

	return nil
}

func (p *Provider) Start() error {
	if err := p.Module.Start(); err != nil {
		return err
	}

	if p.configPath != "" {
		go p.watchConfigFile()
	}

	p.SetHealthy(true, "config provider running")
	p.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"config_path": p.configPath,
	})

	go p.SendNotification("Server started successfully. Integrity check passed.")

	return nil
}

type CacheConfig struct {
	RedisURL string `yaml:"redis_url" json:"redis_url"`
}
type BotConfig struct {
	Enabled         bool    `yaml:"enabled" json:"enabled"`
	Token           string  `yaml:"token" json:"token"`
	Debug           bool    `yaml:"debug" json:"debug"`
	AdminID         int64   `yaml:"admin_id" json:"admin_id"`
	MonitorAdminIDs []int64 `yaml:"monitor_admin_ids" json:"monitor_admin_ids"`
}

func (c *BotConfig) Validate() error {
	if c.Enabled && c.Token == "" {
		return fmt.Errorf("bot token is required when enabled")
	}
	return nil
}

type DatabaseConfig struct {
	PostgresURL string `yaml:"postgres_url" json:"postgres_url"`
	MaxConns    int    `yaml:"max_conns" json:"max_conns"`
	MinConns    int    `yaml:"min_conns" json:"min_conns"`
}

type NATSConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	URL     string `yaml:"url" json:"url"`
	Prefix  string `yaml:"prefix" json:"prefix"`
}

type UpdateConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	ManifestURL   string   `yaml:"manifest_url" json:"manifest_url"`
	PublicKey     string   `yaml:"public_key" json:"public_key"`
	Channel       string   `yaml:"channel" json:"channel"`
	CheckInterval Duration `yaml:"check_interval" json:"check_interval"`
}

type CorrelationConfig struct {
	Enabled         bool `yaml:"enabled" json:"enabled"`
	PaddingEnabled  bool `yaml:"padding" json:"padding"`
	JitterEnabled   bool `yaml:"jitter" json:"jitter"`
	CoverTraffic    bool `yaml:"cover_traffic" json:"cover_traffic"`
	MaxJitterMs     int  `yaml:"max_jitter_ms" json:"max_jitter_ms"`
	CoverRateMs     int  `yaml:"cover_rate_ms" json:"cover_rate_ms"`
	RateBytesPerSec int  `yaml:"rate_bytes_per_sec" json:"rate_bytes_per_sec"`
}

type SNIBypassConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	Mode         string `yaml:"mode" json:"mode"`
	FragmentSize int    `yaml:"fragment_size" json:"fragment_size"`
	Fingerprint  string `yaml:"fingerprint" json:"fingerprint"`
}

type VKRelayConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Mode       string `yaml:"mode" json:"mode"`
	Token      string `yaml:"token" json:"token"`
	GroupID    int64  `yaml:"group_id" json:"group_id"`
	PeerID     int64  `yaml:"peer_id" json:"peer_id"`
	ServerMode bool   `yaml:"server_mode" json:"server_mode"`
	StreamKey  string `yaml:"stream_key" json:"stream_key"`
}

type OutboundConfig struct {
	Tag      string                 `yaml:"tag" json:"tag"`
	Protocol string                 `yaml:"protocol" json:"protocol"`
	Address  string                 `yaml:"address" json:"address"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
	Chain    []string               `yaml:"chain" json:"chain"`
}

type InboundConfig struct {
	Tag      string `yaml:"tag" json:"tag"`
	Protocol string `yaml:"protocol" json:"protocol"`
	Listen   string `yaml:"listen" json:"listen"`
	Port     int    `yaml:"port" json:"port"`
	Ports    []int  `yaml:"ports,omitempty" json:"ports,omitempty"`

	Mode       string `yaml:"mode,omitempty" json:"mode,omitempty"`
	RemoteAddr string `yaml:"remote_addr,omitempty" json:"remote_addr,omitempty"`

	Settings map[string]interface{} `yaml:"settings" json:"settings"`

	StreamSettings StreamConfig `yaml:"stream_settings" json:"stream_settings"`

	Sniffing SniffingConfig `yaml:"sniffing" json:"sniffing"`
}

func (c *InboundConfig) AllPorts() []int {
	seen := make(map[int]struct{})
	var out []int
	for _, p := range append([]int{c.Port}, c.Ports...) {
		if p > 0 {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	return out
}

type StreamConfig struct {
	Network  string                 `yaml:"network" json:"network"`
	Security string                 `yaml:"security" json:"security"`
	TLS      TLSConfig              `yaml:"tls" json:"tls"`
	WS       WebSocketConfig        `yaml:"ws" json:"ws"`
	H2C      H2CStreamConfig        `yaml:"h2c" json:"h2c"`
	Params   map[string]interface{} `yaml:"params,omitempty" json:"params,omitempty"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

type WebSocketConfig struct {
	Path string `yaml:"path" json:"path"`
}

type H2CStreamConfig struct {
	Path string `yaml:"path" json:"path"`
}

type SniffingConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	DestOverride []string `yaml:"dest_override" json:"dest_override"`
}

type ChameleonConfig struct {
	Enabled       bool   `yaml:"enabled" json:"enabled"`
	ListenAddr    string `yaml:"listen_addr" json:"listen_addr"`
	TLSCert       string `yaml:"tls_cert" json:"tls_cert"`
	TLSKey        string `yaml:"tls_key" json:"tls_key"`
	Domain        string `yaml:"domain" json:"domain"`
	ACMEDir       string `yaml:"acme_dir" json:"acme_dir"`
	DecoyOrigin   string `yaml:"decoy_origin" json:"decoy_origin"`
	GANIface      string `yaml:"gan_iface" json:"gan_iface"`
	GANPort       int    `yaml:"gan_port" json:"gan_port"`
	GANMaxPadding int    `yaml:"gan_max_padding" json:"gan_max_padding"`
	Secret        string `yaml:"secret" json:"secret"`
}

type ServerSettings struct {
	Name         string   `yaml:"name" json:"name"`
	ListenAddr   string   `yaml:"listen_addr" json:"listen_addr"`
	TUNName      string   `yaml:"tun_name" json:"tun_name"`
	MTU          int      `yaml:"mtu" json:"mtu"`
	Workers      int      `yaml:"workers" json:"workers"`
	GracefulStop Duration `yaml:"graceful_stop" json:"graceful_stop"`
	PrivateKey   string   `yaml:"private_key" json:"private_key"`
	UUID         string   `yaml:"uuid" json:"uuid"`
	PublicURL    string   `yaml:"public_url" json:"public_url"`
}

type BridgeConfig struct {
	AutoRegister      bool   `yaml:"auto_register" json:"auto_register"`
	Type              string `yaml:"type" json:"type"`
	Provider          string `yaml:"provider" json:"provider"`
	Region            string `yaml:"region" json:"region"`
	RegistrationToken string `yaml:"registration_token" json:"registration_token"`
}

type TransportConfig struct {
	UDP struct {
		Enabled       bool   `yaml:"enabled"`
		ListenAddr    string `yaml:"listen_addr"`
		MaxPacketSize int    `yaml:"max_packet_size"`
		BufferSize    int    `yaml:"buffer_size"`
		Workers       int    `yaml:"workers"`
	} `yaml:"udp"`

	TCP struct {
		Enabled    bool   `yaml:"enabled"`
		ListenAddr string `yaml:"listen_addr"`
	} `yaml:"tcp"`

	WebSocket struct {
		Enabled    bool   `yaml:"enabled"`
		ListenAddr string `yaml:"listen_addr"`
		Path       string `yaml:"path"`
	} `yaml:"websocket"`

	XHTTP struct {
		Enabled        bool   `yaml:"enabled"`
		ListenAddr     string `yaml:"listen_addr"`
		Mode           string `yaml:"mode"`
		MaxConcurrency int    `yaml:"max_concurrency"`
	} `yaml:"xhttp"`
}

type SessionConfig struct {
	MaxSessions       int      `yaml:"max_sessions"`
	SessionTimeout    Duration `yaml:"session_timeout"`
	CleanupInterval   Duration `yaml:"cleanup_interval"`
	KeepaliveInterval Duration `yaml:"keepalive_interval"`
	RekeyInterval     Duration `yaml:"rekey_interval"`
}

type RoutingConfig struct {
	RulesFile    string `yaml:"rules_file"`
	DefaultRoute string `yaml:"default_route"`

	Geo struct {
		Enabled        bool     `yaml:"enabled"`
		GeoIPFile      string   `yaml:"geoip_file"`
		GeoSiteFile    string   `yaml:"geosite_file"`
		UpdateInterval Duration `yaml:"update_interval"`
	} `yaml:"geo"`

	DNS struct {
		Enabled     bool   `yaml:"enabled"`
		Upstream    string `yaml:"upstream"`
		FakeIPRange string `yaml:"fakeip_range"`
	} `yaml:"dns"`
}

type ObfuscationConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Profile     string `yaml:"profile"`
	ThreatLevel int    `yaml:"threat_level"`

	Padding struct {
		Enabled bool `yaml:"enabled"`
		MinSize int  `yaml:"min_size"`
		MaxSize int  `yaml:"max_size"`
	} `yaml:"padding"`

	Chaff struct {
		Enabled  bool     `yaml:"enabled"`
		Interval Duration `yaml:"interval"`
		MinSize  int      `yaml:"min_size"`
		MaxSize  int      `yaml:"max_size"`
	} `yaml:"chaff"`
}

type APIConfig struct {
	Enabled        bool     `yaml:"enabled"`
	ListenAddr     string   `yaml:"listen_addr"`
	AuthToken      string   `yaml:"auth_token"`
	WebRoot        string   `yaml:"web_root"`
	EnableCORS     bool     `yaml:"enable_cors"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	TLSCert        string   `yaml:"tls_cert"`
	TLSKey         string   `yaml:"tls_key"`
	AdminUsername  string   `yaml:"admin_username"`
	AdminPassword  string   `yaml:"admin_password"`
	LoginRateLimit int      `yaml:"login_rate_limit"`
}

type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Path       string `yaml:"path"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
	File   string `yaml:"file"`
}

func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Server: ServerSettings{
			Name:         "whispera-server",
			ListenAddr:   ":443",
			TUNName:      "tun0",
			MTU:          1420,
			Workers:      8,
			GracefulStop: Duration(30 * time.Second),
		},
		Transport: TransportConfig{
			UDP: struct {
				Enabled       bool   `yaml:"enabled"`
				ListenAddr    string `yaml:"listen_addr"`
				MaxPacketSize int    `yaml:"max_packet_size"`
				BufferSize    int    `yaml:"buffer_size"`
				Workers       int    `yaml:"workers"`
			}{
				Enabled:       true,
				ListenAddr:    ":8443",
				MaxPacketSize: 65535,
				BufferSize:    4096,
				Workers:       8,
			},
		},
		Inbounds: []InboundConfig{
			{
				Tag:      "default-inbound",
				Protocol: "whispera",
				Listen:   "0.0.0.0",
				Port:     8443,
				StreamSettings: StreamConfig{
					Network:  "tcp",
					Security: "none",
				},
			},
		},
		Session: SessionConfig{
			MaxSessions:       10000,
			SessionTimeout:    Duration(24 * time.Hour),
			CleanupInterval:   Duration(1 * time.Minute),
			KeepaliveInterval: Duration(30 * time.Second),
			RekeyInterval:     Duration(12 * time.Hour),
		},
		Routing: RoutingConfig{
			DefaultRoute: "direct",
		},
		Obfuscation: ObfuscationConfig{
			Enabled:     true,
			Profile:     "default",
			ThreatLevel: 5,
		},
		API: APIConfig{
			Enabled:    true,
			ListenAddr: ":8080",
			EnableCORS: true,
			WebRoot:    "",
		},
		Metrics: MetricsConfig{
			Enabled:    true,
			ListenAddr: ":9090",
			Path:       "/metrics",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
		Relay: RelayConfig{
			MaxStreams: 10000,
			EnableTCP:  true,
			EnableUDP:  true,
			Debug:      false,
		},
		Bot: BotConfig{
			Enabled:         false,
			Token:           "",
			Debug:           false,
			AdminID:         0,
			MonitorAdminIDs: []int64{},
		},
	}
}

type Provider struct {
	*base.Module
	mu           sync.RWMutex
	config       *ServerConfig
	configPath   string
	watchers     map[string][]chan interface{}
	watchersMu   sync.RWMutex
	fileWatcher  chan struct{}
	lastModified time.Time
}

func New(configPath string) (*Provider, error) {
	p := &Provider{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		configPath:  configPath,
		config:      DefaultServerConfig(),
		watchers:    make(map[string][]chan interface{}),
		fileWatcher: make(chan struct{}),
	}

	return p, nil
}

func (p *Provider) Stop() error {
	close(p.fileWatcher)

	p.watchersMu.Lock()
	for _, watchers := range p.watchers {
		for _, ch := range watchers {
			close(ch)
		}
	}
	p.watchers = nil
	p.watchersMu.Unlock()

	p.PublishEvent(events.EventTypeModuleStopped, nil)
	return p.Module.Stop()
}

func (p *Provider) Load(source string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	cfgPtr := DefaultServerConfig()
	cfg := *cfgPtr

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		if te, ok := err.(*yaml.TypeError); ok {
			for _, msg := range te.Errors {
				log.Printf("[config] %s: invalid value ignored, using default: %s", source, msg)
			}
		} else {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	}

	p.mu.Lock()
	oldConfig := p.config
	p.config = &cfg
	p.configPath = source
	p.mu.Unlock()

	if info, err := os.Stat(source); err == nil {
		p.lastModified = info.ModTime()
	}
	p.notifyChanges(oldConfig, &cfg)

	return nil
}

func (p *Provider) Reload() error {
	if p.configPath == "" {
		return fmt.Errorf("no config path set")
	}

	if err := p.Load(p.configPath); err != nil {
		return err
	}

	p.PublishEvent(events.EventTypeConfigReloaded, map[string]interface{}{
		"config_path": p.configPath,
	})

	return nil
}

func (p *Provider) GetConfig() *ServerConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

func (p *Provider) Get(key string) interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	switch key {
	case "server.listen_addr":
		return p.config.Server.ListenAddr
	case "server.mtu":
		return p.config.Server.MTU
	case "session.max_sessions":
		return p.config.Session.MaxSessions
	case "session.timeout":
		return p.config.Session.SessionTimeout.D()
	case "obfuscation.profile":
		return p.config.Obfuscation.Profile
	default:
		return nil
	}
}

func (p *Provider) GetString(key string) string {
	if v := p.Get(key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (p *Provider) GetInt(key string) int {
	if v := p.Get(key); v != nil {
		if i, ok := v.(int); ok {
			return i
		}
	}
	return 0
}

func (p *Provider) GetBool(key string) bool {
	if v := p.Get(key); v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func (p *Provider) GetDuration(key string) time.Duration {
	if v := p.Get(key); v != nil {
		if d, ok := v.(time.Duration); ok {
			return d
		}
	}
	return 0
}

func (p *Provider) Set(key string, value interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch key {
	case "server.listen_addr":
		if v, ok := value.(string); ok {
			p.config.Server.ListenAddr = v
		}
	case "server.mtu":
		if v, ok := value.(int); ok {
			p.config.Server.MTU = v
		}
	}

	p.notifyWatchers(key, value)
}

func (p *Provider) Watch(key string) <-chan interface{} {
	ch := make(chan interface{}, 10)

	p.watchersMu.Lock()
	p.watchers[key] = append(p.watchers[key], ch)
	p.watchersMu.Unlock()

	return ch
}

func (p *Provider) notifyWatchers(key string, value interface{}) {
	p.watchersMu.RLock()
	defer p.watchersMu.RUnlock()

	if watchers, ok := p.watchers[key]; ok {
		for _, ch := range watchers {
			select {
			case ch <- value:
			default:
			}
		}
	}
}

func (p *Provider) notifyChanges(old, new *ServerConfig) {
	if old == nil || new == nil {
		return
	}

	if old.Server.ListenAddr != new.Server.ListenAddr {
		p.notifyWatchers("server.listen_addr", new.Server.ListenAddr)
	}
	if old.Server.MTU != new.Server.MTU {
		p.notifyWatchers("server.mtu", new.Server.MTU)
	}
	if old.Session.MaxSessions != new.Session.MaxSessions {
		p.notifyWatchers("session.max_sessions", new.Session.MaxSessions)
	}
	if old.Obfuscation.Profile != new.Obfuscation.Profile {
		p.notifyWatchers("obfuscation.profile", new.Obfuscation.Profile)
	}
	if len(old.Outbounds) != len(new.Outbounds) {
		p.notifyWatchers("outbounds", new.Outbounds)
	}
}

func (p *Provider) GetConfigPath() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.configPath
}

func (p *Provider) Validate() error {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()

	if cfg.Server.ListenAddr == "" {
		return fmt.Errorf("server.listen_addr is required")
	}
	if cfg.Server.MTU < 576 || cfg.Server.MTU > 65535 {
		return fmt.Errorf("server.mtu must be between 576 and 65535")
	}
	if cfg.Session.MaxSessions < 1 {
		return fmt.Errorf("session.max_sessions must be at least 1")
	}

	return nil
}
