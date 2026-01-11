package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ClientConfig holds optional client settings. Zero values mean "unspecified".
type ClientConfig struct {
	Server       string `yaml:"server" json:"server"`
	ServerTCP    string `yaml:"server_tcp" json:"server_tcp"`
	ServerWS     string `yaml:"server_ws" json:"server_ws"`
	ServerWS2    string `yaml:"server_ws2" json:"server_ws2"`
	TUN          string `yaml:"tun" json:"tun"`
	TunIP        string `yaml:"tun_ip" json:"tun_ip"`
	TunGateway   string `yaml:"tun_gateway" json:"tun_gateway"`
	TunPrefix    int    `yaml:"tun_prefix" json:"tun_prefix"`
	Metrics      string `yaml:"metrics" json:"metrics"`
	ServerPub    string `yaml:"server_pub" json:"server_pub"`
	PSK          string `yaml:"psk" json:"psk"`
	DualMode     bool   `yaml:"dual_mode" json:"dual_mode"`
	StunSrv      string `yaml:"stun_srv" json:"stun_srv"`
	ProxyMode    bool   `yaml:"proxy_mode" json:"proxy_mode"`
	KeepaliveSec int    `yaml:"keepalive" json:"keepalive"`

	SplitTunnel      bool   `yaml:"split_tunnel" json:"split_tunnel"`
	SplitTunnelRules string `yaml:"split_tunnel_rules" json:"split_tunnel_rules"`
	SplitTunnelMode  string `yaml:"split_tunnel_mode" json:"split_tunnel_mode"`

	AutoProfile      bool   `yaml:"auto_profile" json:"auto_profile"`
	EnableMonitoring bool   `yaml:"enable_monitoring" json:"enable_monitoring"`
	EnableTesting    bool   `yaml:"enable_testing" json:"enable_testing"`
	AppProfile       string `yaml:"app_profile" json:"app_profile"`

	RekeyMin      int     `yaml:"rekey" json:"rekey"`
	MTU           int     `yaml:"mtu" json:"mtu"`
	PadMin        int     `yaml:"pad_min" json:"pad_min"`
	PadMax        int     `yaml:"pad_max" json:"pad_max"`
	ChaffSec      int     `yaml:"chaff" json:"chaff"`
	ObfsPreset    string  `yaml:"obfs_preset" json:"obfs_preset"`
	ObfsStrict    bool    `yaml:"obfs_strict" json:"obfs_strict"`
	HSReadTimeout int     `yaml:"handshake_timeout" json:"handshake_timeout"`
	UDPRetries    int     `yaml:"udp_retries" json:"udp_retries"`
	UDPOnly       bool    `yaml:"udp_only" json:"udp_only"`
	Watchdog      int     `yaml:"watchdog" json:"watchdog"`
	RekeyBytes    int64   `yaml:"rekey_bytes" json:"rekey_bytes"`
	RekeyPkts     int64   `yaml:"rekey_pkts" json:"rekey_pkts"`
	AutoSwitch    *bool   `yaml:"auto_switch" json:"auto_switch"`
	UDPUpgradeSec int     `yaml:"udp_upgrade_sec" json:"udp_upgrade_sec"`
	ChaffDist     string  `yaml:"chaff_dist" json:"chaff_dist"`
	ChaffAlpha    float64 `yaml:"chaff_alpha" json:"chaff_alpha"`
	ChaffXm       float64 `yaml:"chaff_xm" json:"chaff_xm"`
	ChaffSizeMin  int     `yaml:"chaff_size_min" json:"chaff_size_min"`
	ChaffSizeMax  int     `yaml:"chaff_size_max" json:"chaff_size_max"`
	ShapeMeanMs   int     `yaml:"shape_mean_ms" json:"shape_mean_ms"`
	ShapeTarget   int     `yaml:"shape_target" json:"shape_target"`
	PProf         string  `yaml:"pprof" json:"pprof"`

	UseTLS        bool   `yaml:"use_tls" json:"use_tls"`
	TLSMode       string `yaml:"tls_mode" json:"tls_mode"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify" json:"tls_skip_verify"`

	SpeedtestEnabled bool   `yaml:"speedtest_enabled" json:"speedtest_enabled"`
	SpeedtestServer  string `yaml:"speedtest_server" json:"speedtest_server"`

	P2PEnabled      bool   `yaml:"p2p_enabled" json:"p2p_enabled"`
	P2PBootstrapCSV string `yaml:"p2p_bootstrap_csv" json:"p2p_bootstrap_csv"`
	P2PListen       string `yaml:"p2p_listen" json:"p2p_listen"`
	P2PSendID       string `yaml:"p2p_send_id" json:"p2p_send_id"`
	P2PSendMsg      string `yaml:"p2p_send_msg" json:"p2p_send_msg"`

	TunstackLocalEgress    bool `yaml:"tunstack_local_egress" json:"tunstack_local_egress"`
	TunstackMaxUDPSessions int  `yaml:"tunstack_max_udp_sessions" json:"tunstack_max_udp_sessions"`

	NetstackEnable  bool `yaml:"netstack_enable" json:"netstack_enable"`
	NetstackDebug   bool `yaml:"netstack_debug" json:"netstack_debug"`
	NetstackTCPOnly bool `yaml:"netstack_tcp_only" json:"netstack_tcp_only"`

	ConfigURI      string `yaml:"config_uri" json:"config_uri"`
	CoreEnable     bool   `yaml:"core_enable" json:"core_enable"`
	UseV2          bool   `yaml:"use_v2" json:"use_v2"`
	VerbosePackets bool   `yaml:"verbose_packets" json:"verbose_packets"`

	// Phase 2: Routing, DNS, AdBlock
	Routing *ClientRoutingConfig `yaml:"routing,omitempty" json:"routing,omitempty"`
	DNS     *ClientDNSConfig     `yaml:"dns,omitempty" json:"dns,omitempty"`
	AdBlock *ClientAdBlockConfig `yaml:"adblock,omitempty" json:"adblock,omitempty"`

	// Phase 3: Security features
	KillSwitch *ClientKillSwitchConfig `yaml:"kill_switch,omitempty" json:"kill_switch,omitempty"`
	Failover   *ClientFailoverConfig   `yaml:"failover,omitempty" json:"failover,omitempty"`

	// Phase 4: ASN Bypass (for VPN/Datacenter IP detection evasion)
	ASNBypass *ClientASNBypassConfig `yaml:"asn_bypass,omitempty" json:"asn_bypass,omitempty"`
}

// ClientRoutingConfig holds routing rules and engine settings
type ClientRoutingConfig struct {
	Rules []ClientRoutingRule `yaml:"rules" json:"rules"`
}

// ClientRoutingRule mirrors the structure in internal/routing/engine.go
type ClientRoutingRule struct {
	Type        string   `yaml:"type" json:"type"`
	Domain      []string `yaml:"domain,omitempty" json:"domain,omitempty"`
	IP          []string `yaml:"ip,omitempty" json:"ip,omitempty"`
	Port        string   `yaml:"port,omitempty" json:"port,omitempty"`
	Network     string   `yaml:"network,omitempty" json:"network,omitempty"`
	Source      []string `yaml:"source,omitempty" json:"source,omitempty"`
	OutboundTag string   `yaml:"outbound_tag" json:"outbound_tag"`
	BalancerTag string   `yaml:"balancer_tag,omitempty" json:"balancer_tag,omitempty"`
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Priority    int      `yaml:"priority" json:"priority"`
}

// ClientDNSConfig holds DNS settings
type ClientDNSConfig struct {
	Upstream    string `yaml:"upstream" json:"upstream"`
	FakeIP      bool   `yaml:"fake_ip" json:"fake_ip"`
	FakeIPRange string `yaml:"fake_ip_range" json:"fake_ip_range"`
}

// ClientAdBlockConfig holds ad-blocking settings
type ClientAdBlockConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	DNSBlocking   bool          `yaml:"dns_blocking" json:"dns_blocking"`
	HTTPSBlocking bool          `yaml:"https_blocking" json:"https_blocking"`
	MLEnabled     bool          `yaml:"ml_enabled" json:"ml_enabled"`
	CustomRules   []AdBlockRule `yaml:"custom_rules,omitempty" json:"custom_rules,omitempty"`
}

// AdBlockRule mirrors the structure in internal/adblock/adblocker.go
type AdBlockRule struct {
	Domain string `yaml:"domain,omitempty" json:"domain,omitempty"`
	URL    string `yaml:"url,omitempty" json:"url,omitempty"`
	Type   string `yaml:"type" json:"type"` // "dns", "https", "both"
}

// ClientKillSwitchConfig holds kill switch settings
type ClientKillSwitchConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	AllowLAN     bool     `yaml:"allow_lan" json:"allow_lan"`         // Allow local network access
	AllowDNS     bool     `yaml:"allow_dns" json:"allow_dns"`         // Allow DNS queries when disconnected
	PersistRules bool     `yaml:"persist_rules" json:"persist_rules"` // Keep rules after app exit
	AllowedIPs   []string `yaml:"allowed_ips,omitempty" json:"allowed_ips,omitempty"`
	AllowedPorts []int    `yaml:"allowed_ports,omitempty" json:"allowed_ports,omitempty"`
}

// ClientFailoverConfig holds failover/HA settings
type ClientFailoverConfig struct {
	Enabled         bool     `yaml:"enabled" json:"enabled"`
	Servers         []string `yaml:"servers" json:"servers"`                   // List of fallback servers
	HealthInterval  int      `yaml:"health_interval" json:"health_interval"`   // Health check interval (seconds)
	Timeout         int      `yaml:"timeout" json:"timeout"`                   // Connection timeout (seconds)
	MaxRetries      int      `yaml:"max_retries" json:"max_retries"`           // Max retries per server
	StickySession   bool     `yaml:"sticky_session" json:"sticky_session"`     // Prefer last working server
	WeightedBalance bool     `yaml:"weighted_balance" json:"weighted_balance"` // Use weighted server selection
}

// ClientASNBypassConfig holds ASN bypass settings for VPN/Datacenter IP evasion
// When traffic comes from VPN/datacenter ASN, anti-bot systems may block
// connections immediately after ClientHello. This config enables bypass techniques.
type ClientASNBypassConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`                         // Enable ASN bypass
	Strategy           string   `yaml:"strategy" json:"strategy"`                       // direct, tls_masquerade, domain_fronting, residential_proxy, websocket, grpc
	TLSFingerprint     string   `yaml:"tls_fingerprint" json:"tls_fingerprint"`         // Browser fingerprint: chrome, firefox, safari, ios, android, edge, 360, qq
	DomainFrontHost    string   `yaml:"front_host" json:"front_host"`                   // CDN domain for domain fronting (e.g., ajax.cloudflare.com)
	ResidentialProxies []string `yaml:"residential_proxies" json:"residential_proxies"` // List of residential SOCKS5/HTTP proxies
	ProxyRotation      bool     `yaml:"proxy_rotation" json:"proxy_rotation"`           // Rotate through proxies
	EnableJA3Random    bool     `yaml:"ja3_randomize" json:"ja3_randomize"`             // Randomize JA3 fingerprint per connection
	EnableECH          bool     `yaml:"enable_ech" json:"enable_ech"`                   // Enable Encrypted Client Hello
	ConnectionBurst    int      `yaml:"connection_burst" json:"connection_burst"`       // Max connections per burst window
	BurstCooldownMs    int      `yaml:"burst_cooldown_ms" json:"burst_cooldown_ms"`     // Cooldown between bursts in ms
}

// LoadClient loads client configuration from path
func LoadClient(path string) (*ClientConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ClientConfig
	switch ext := filepath.Ext(path); ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return nil, err
		}
	case ".json":
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported config format")
	}
	return &cfg, nil
}

// ValidateClientConfig validates the client configuration
func ValidateClientConfig(cfg *ClientConfig) error {
	if cfg == nil {
		return errors.New("config is nil")
	}

	// Make validation less strict if we only supply command line arguments
	// but generally a server address is needed eventually
	// if cfg.Server == "" && cfg.ServerTCP == "" {
	// 	 return errors.New("server address is required")
	// }

	// Validate server address format if present
	if cfg.Server != "" {
		if _, _, err := net.SplitHostPort(cfg.Server); err != nil {
			return fmt.Errorf("invalid server address format %q: %v", cfg.Server, err)
		}
	}

	return nil
}
