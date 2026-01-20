// Package config provides configuration management with hot-reload support
package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "config.provider"
	ModuleVersion = "1.0.0"
)

// ServerConfig represents the complete server configuration
type ServerConfig struct {
	// Server settings
	Server ServerSettings `yaml:"server"`

	// Transport settings
	Transport TransportConfig `yaml:"transport"`

	// Session settings
	Session SessionConfig `yaml:"session"`

	// Routing settings
	Routing RoutingConfig `yaml:"routing"`

	// Obfuscation settings
	Obfuscation ObfuscationConfig `yaml:"obfuscation"`

	// API settings
	API APIConfig `yaml:"api"`

	// Metrics settings
	Metrics MetricsConfig `yaml:"metrics"`

	// Logging settings
	Logging LoggingConfig `yaml:"logging"`

	// Relay settings
	Relay RelayConfig `yaml:"relay"`

	// Phantom protocol settings for SNI masquerading and TLS proxying
	Phantom PhantomConfig `yaml:"phantom"`
}

// PhantomConfig contains Phantom protocol settings for SNI masquerading
// This allows the server to appear as a legitimate destination to DPI systems
// Phantom proxies TLS handshakes to real servers while authenticating Whispera clients
type PhantomConfig struct {
	// Enabled enables Phantom protocol
	Enabled bool `yaml:"enabled"`

	// Dest is the target server to proxy TLS handshake to (e.g., "cloudflare.com:443")
	// When a non-authenticated client connects, traffic is proxied to this server
	Dest string `yaml:"dest"`

	// ServerNames are the allowed SNI values clients can use
	ServerNames []string `yaml:"server_names"`

	// PrivateKey is the x25519 private key for client authentication (hex encoded)
	PrivateKey string `yaml:"private_key"`

	// ShortIds are the allowed shortId values for client identification
	ShortIds []string `yaml:"short_ids"`

	// MaxTimeDiff is the maximum allowed time difference for replay protection (ms)
	MaxTimeDiff int `yaml:"max_time_diff"`

	// Fingerprint is the default browser fingerprint for outbound connections
	Fingerprint string `yaml:"fingerprint"`
}

// ServerSettings contains basic server settings
type ServerSettings struct {
	Name         string        `yaml:"name"`
	ListenAddr   string        `yaml:"listen_addr"`
	TUNName      string        `yaml:"tun_name"`
	MTU          int           `yaml:"mtu"`
	Workers      int           `yaml:"workers"`
	GracefulStop time.Duration `yaml:"graceful_stop"`
	PrivateKey   string        `yaml:"private_key"`
	UUID         string        `yaml:"uuid"`
}

// TransportConfig contains transport layer settings
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

// SessionConfig contains session management settings
type SessionConfig struct {
	MaxSessions       int           `yaml:"max_sessions"`
	SessionTimeout    time.Duration `yaml:"session_timeout"`
	CleanupInterval   time.Duration `yaml:"cleanup_interval"`
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
	RekeyInterval     time.Duration `yaml:"rekey_interval"`
}

// RoutingConfig contains routing settings
type RoutingConfig struct {
	RulesFile    string `yaml:"rules_file"`
	DefaultRoute string `yaml:"default_route"`

	Geo struct {
		Enabled        bool          `yaml:"enabled"`
		GeoIPFile      string        `yaml:"geoip_file"`
		GeoSiteFile    string        `yaml:"geosite_file"`
		UpdateInterval time.Duration `yaml:"update_interval"`
	} `yaml:"geo"`

	DNS struct {
		Enabled     bool   `yaml:"enabled"`
		Upstream    string `yaml:"upstream"`
		FakeIPRange string `yaml:"fakeip_range"`
	} `yaml:"dns"`
}

// ObfuscationConfig contains obfuscation settings
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
		Enabled  bool          `yaml:"enabled"`
		Interval time.Duration `yaml:"interval"`
		MinSize  int           `yaml:"min_size"`
		MaxSize  int           `yaml:"max_size"`
	} `yaml:"chaff"`
}

// APIConfig contains API server settings
type APIConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	AuthToken  string `yaml:"auth_token"`
	WebRoot    string `yaml:"web_root"`
	EnableCORS bool   `yaml:"enable_cors"`
	TLSCert    string `yaml:"tls_cert"`
	TLSKey     string `yaml:"tls_key"`
}

// MetricsConfig contains metrics settings
type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Path       string `yaml:"path"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
	File   string `yaml:"file"`
}

// DefaultServerConfig returns a default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Server: ServerSettings{
			Name:         "whispera-server",
			ListenAddr:   ":443",
			TUNName:      "tun0",
			MTU:          1420,
			Workers:      8,
			GracefulStop: 30 * time.Second,
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
		Session: SessionConfig{
			MaxSessions:       10000,
			SessionTimeout:    30 * time.Minute,
			CleanupInterval:   1 * time.Minute,
			KeepaliveInterval: 30 * time.Second,
			RekeyInterval:     12 * time.Hour,
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
		Phantom: PhantomConfig{
			Enabled:     false, // Disabled by default, requires configuration
			Dest:        "",    // e.g., "cloudflare.com:443"
			ServerNames: []string{},
			PrivateKey:  "", // Generate with: ./whispera x25519
			ShortIds:    []string{""},
			MaxTimeDiff: 60000, // 60 seconds
			Fingerprint: "chrome",
		},
	}
}

// Provider implements interfaces.ConfigProvider as a module
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

// New creates a new configuration provider
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

// Init initializes the config provider
func (p *Provider) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := p.Module.Init(ctx, cfg); err != nil {
		return err
	}

	// Load initial configuration
	if p.configPath != "" {
		if err := p.Load(p.configPath); err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	return nil
}

// Start starts the config provider (including file watcher)
func (p *Provider) Start() error {
	if err := p.Module.Start(); err != nil {
		return err
	}

	// Start file watcher if config path is set
	if p.configPath != "" {
		go p.watchConfigFile()
	}

	p.SetHealthy(true, "config provider running")
	p.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"config_path": p.configPath,
	})

	return nil
}

// Stop stops the config provider
func (p *Provider) Stop() error {
	close(p.fileWatcher)

	// Close all watcher channels
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

// Load loads configuration from a file
func (p *Provider) Load(source string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Start with default configuration to ensure missing fields use defaults
	cfgPtr := DefaultServerConfig()
	// Dereference to get a copy we can modify
	cfg := *cfgPtr

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	p.mu.Lock()
	oldConfig := p.config
	p.config = &cfg
	p.configPath = source
	p.mu.Unlock()

	// Get file info for modification time
	if info, err := os.Stat(source); err == nil {
		p.lastModified = info.ModTime()
	}

	// Notify watchers of changes
	p.notifyChanges(oldConfig, &cfg)

	return nil
}

// Reload reloads the configuration from the current file
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

// GetConfig returns the current configuration
func (p *Provider) GetConfig() *ServerConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

// Get gets a configuration value by key
func (p *Provider) Get(key string) interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// This is a simplified implementation
	// A more complete implementation would use reflection
	switch key {
	case "server.listen_addr":
		return p.config.Server.ListenAddr
	case "server.mtu":
		return p.config.Server.MTU
	case "session.max_sessions":
		return p.config.Session.MaxSessions
	case "session.timeout":
		return p.config.Session.SessionTimeout
	case "obfuscation.profile":
		return p.config.Obfuscation.Profile
	default:
		return nil
	}
}

// GetString gets a string configuration value
func (p *Provider) GetString(key string) string {
	if v := p.Get(key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetInt gets an integer configuration value
func (p *Provider) GetInt(key string) int {
	if v := p.Get(key); v != nil {
		if i, ok := v.(int); ok {
			return i
		}
	}
	return 0
}

// GetBool gets a boolean configuration value
func (p *Provider) GetBool(key string) bool {
	if v := p.Get(key); v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// GetDuration gets a duration configuration value
func (p *Provider) GetDuration(key string) time.Duration {
	if v := p.Get(key); v != nil {
		if d, ok := v.(time.Duration); ok {
			return d
		}
	}
	return 0
}

// Set sets a configuration value
func (p *Provider) Set(key string, value interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// This is a simplified implementation
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

	// Notify watchers
	p.notifyWatchers(key, value)
}

// Watch watches for configuration changes on a key
func (p *Provider) Watch(key string) <-chan interface{} {
	ch := make(chan interface{}, 10)

	p.watchersMu.Lock()
	p.watchers[key] = append(p.watchers[key], ch)
	p.watchersMu.Unlock()

	return ch
}

// notifyWatchers notifies watchers of a key change
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

// notifyChanges compares old and new config and notifies watchers
func (p *Provider) notifyChanges(old, new *ServerConfig) {
	if old == nil || new == nil {
		return
	}

	// Compare and notify for specific fields
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
}

// watchConfigFile watches the config file for changes
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
				if err := p.Reload(); err != nil {
					p.SetHealthy(false, fmt.Sprintf("reload error: %v", err))
				} else {
					p.lastModified = info.ModTime()
				}
			}
		}
	}
}

// SaveConfig saves the current configuration to a file
func (p *Provider) SaveConfig(path string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.saveConfig(path)
}

// saveConfig saves the current configuration to a file (internal, no lock)
func (p *Provider) saveConfig(path string) error {
	cfg := p.config

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Update updates the configuration safely and saves it
func (p *Provider) Update(fn func(*ServerConfig)) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldConfig := *p.config // shallow copy for comparison logic if needed
	fn(p.config)

	if p.configPath != "" {
		if err := p.saveConfig(p.configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	// Notify watchers of potential changes
	// We pass pointers to the actual current config and the copy of old
	p.notifyChanges(&oldConfig, p.config)

	return nil
}

// Validate validates the current configuration
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

// Factory creates config provider modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var path string
	if s, ok := cfg.(string); ok {
		path = s
	}
	return New(path)
}
