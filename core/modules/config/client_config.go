package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ClientConfig struct {
	Server               string   `yaml:"server" json:"server"`
	ServerAlts           []string `yaml:"server_alts,omitempty" json:"server_alts,omitempty"`
	ServerTCP            string   `yaml:"server_tcp" json:"server_tcp"`
	ServerWS             string   `yaml:"server_ws" json:"server_ws"`
	ChameleonAddr        string   `yaml:"chameleon_addr" json:"chameleon_addr"`
	ChameleonSNI         string   `yaml:"chameleon_sni" json:"chameleon_sni"`
	ChameleonCertPin     string   `yaml:"chameleon_cert_pin" json:"chameleon_cert_pin"`
	ChameleonQUICAddr    string   `yaml:"chameleon_quic_addr" json:"chameleon_quic_addr"`
	ChameleonStripeOn    bool     `yaml:"chameleon_stripe_on" json:"chameleon_stripe_on"`
	ChameleonStripeN     int      `yaml:"chameleon_stripe_n" json:"chameleon_stripe_n"`
	ChameleonStripeStart int      `yaml:"chameleon_stripe_start" json:"chameleon_stripe_start"`
	ServerWS2            string   `yaml:"server_ws2" json:"server_ws2"`
	TUN                  string   `yaml:"tun" json:"tun"`
	TunIP                string   `yaml:"tun_ip" json:"tun_ip"`
	TunGateway           string   `yaml:"tun_gateway" json:"tun_gateway"`
	TunPrefix            int      `yaml:"tun_prefix" json:"tun_prefix"`
	Metrics              string   `yaml:"metrics" json:"metrics"`
	ServerPub            string   `yaml:"server_pub" json:"server_pub"`
	PSK                  string   `yaml:"psk" json:"psk"`
	DualMode             bool     `yaml:"dual_mode" json:"dual_mode"`
	StunSrv              string   `yaml:"stun_srv" json:"stun_srv"`
	ProxyMode            bool     `yaml:"proxy_mode" json:"proxy_mode"`
	KeepaliveSec         int      `yaml:"keepalive" json:"keepalive"`

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

	Routing *ClientRoutingConfig `yaml:"routing,omitempty" json:"routing,omitempty"`
	DNS     *ClientDNSConfig     `yaml:"dns,omitempty" json:"dns,omitempty"`
	AdBlock *ClientAdBlockConfig `yaml:"adblock,omitempty" json:"adblock,omitempty"`

	KillSwitch *ClientKillSwitchConfig `yaml:"kill_switch,omitempty" json:"kill_switch,omitempty"`
	Failover   *ClientFailoverConfig   `yaml:"failover,omitempty" json:"failover,omitempty"`

	ASNBypass *ClientASNBypassConfig `yaml:"asn_bypass,omitempty" json:"asn_bypass,omitempty"`

	Transport string `yaml:"transport,omitempty" json:"transport,omitempty"`

	TransportWhitelist []string `yaml:"transport_whitelist,omitempty" json:"transport_whitelist,omitempty"`
	TransportBlacklist []string `yaml:"transport_blacklist,omitempty" json:"transport_blacklist,omitempty"`

	RussianService string `yaml:"russian_service,omitempty" json:"russian_service,omitempty"`

	TransportConfig map[string]interface{} `yaml:"transport_config,omitempty" json:"transport_config,omitempty"`

	MLServerURL string `yaml:"ml_server_url,omitempty" json:"ml_server_url,omitempty"`

	MLToken string `yaml:"ml_token,omitempty" json:"ml_token,omitempty"`

	MLTokenFile string `yaml:"ml_token_file,omitempty" json:"ml_token_file,omitempty"`

	SubscriptionURL string `yaml:"subscription_url,omitempty" json:"subscription_url,omitempty"`

	ForceSNI string `yaml:"force_sni,omitempty" json:"force_sni,omitempty"`

	Regions map[string][]string `yaml:"regions,omitempty" json:"regions,omitempty"`

	PreferredRegion string `yaml:"region,omitempty" json:"region,omitempty"`
}

type ClientRoutingConfig struct {
	Rules []ClientRoutingRule `yaml:"rules" json:"rules"`
}

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

type ClientDNSConfig struct {
	Upstream    string `yaml:"upstream" json:"upstream"`
	FakeIP      bool   `yaml:"fake_ip" json:"fake_ip"`
	FakeIPRange string `yaml:"fake_ip_range" json:"fake_ip_range"`
}

type ClientAdBlockConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	DNSBlocking   bool          `yaml:"dns_blocking" json:"dns_blocking"`
	HTTPSBlocking bool          `yaml:"https_blocking" json:"https_blocking"`
	MLEnabled     bool          `yaml:"ml_enabled" json:"ml_enabled"`
	CustomRules   []AdBlockRule `yaml:"custom_rules,omitempty" json:"custom_rules,omitempty"`
}

type AdBlockRule struct {
	Domain string `yaml:"domain,omitempty" json:"domain,omitempty"`
	URL    string `yaml:"url,omitempty" json:"url,omitempty"`
	Type   string `yaml:"type" json:"type"`
}

type ClientKillSwitchConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	AllowLAN     bool     `yaml:"allow_lan" json:"allow_lan"`
	AllowDNS     bool     `yaml:"allow_dns" json:"allow_dns"`
	PersistRules bool     `yaml:"persist_rules" json:"persist_rules"`
	AllowedIPs   []string `yaml:"allowed_ips,omitempty" json:"allowed_ips,omitempty"`
	AllowedPorts []int    `yaml:"allowed_ports,omitempty" json:"allowed_ports,omitempty"`
}

type ClientFailoverConfig struct {
	Enabled         bool     `yaml:"enabled" json:"enabled"`
	Servers         []string `yaml:"servers" json:"servers"`
	HealthInterval  int      `yaml:"health_interval" json:"health_interval"`
	Timeout         int      `yaml:"timeout" json:"timeout"`
	MaxRetries      int      `yaml:"max_retries" json:"max_retries"`
	StickySession   bool     `yaml:"sticky_session" json:"sticky_session"`
	WeightedBalance bool     `yaml:"weighted_balance" json:"weighted_balance"`
}

type ClientASNBypassConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	Strategy           string   `yaml:"strategy" json:"strategy"`
	TLSFingerprint     string   `yaml:"tls_fingerprint" json:"tls_fingerprint"`
	DomainFrontHost    string   `yaml:"front_host" json:"front_host"`
	ResidentialProxies []string `yaml:"residential_proxies" json:"residential_proxies"`
	ProxyRotation      bool     `yaml:"proxy_rotation" json:"proxy_rotation"`
	EnableJA3Random    bool     `yaml:"ja3_randomize" json:"ja3_randomize"`
	EnableECH          bool     `yaml:"enable_ech" json:"enable_ech"`
	ConnectionBurst    int      `yaml:"connection_burst" json:"connection_burst"`
	BurstCooldownMs    int      `yaml:"burst_cooldown_ms" json:"burst_cooldown_ms"`
}

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
