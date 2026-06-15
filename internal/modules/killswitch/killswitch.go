package killswitch

import (
	"whispera/internal/log"
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

var log = logger.Module("killswitch")

type State int

const (
	StateDisabled State = iota
	StateEnabled
	StateActive
)

func (s State) String() string {
	switch s {
	case StateDisabled:
		return "disabled"
	case StateEnabled:
		return "enabled"
	case StateActive:
		return "active"
	default:
		return "unknown"
	}
}

type Config struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	AllowLAN     bool     `yaml:"allow_lan" json:"allow_lan"`
	AllowDNS     bool     `yaml:"allow_dns" json:"allow_dns"`
	PersistRules bool     `yaml:"persist_rules" json:"persist_rules"`
	AllowedIPs   []string `yaml:"allowed_ips" json:"allowed_ips"`
	AllowedPorts []int    `yaml:"allowed_ports" json:"allowed_ports"`
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:      false,
		AllowLAN:     true,
		AllowDNS:     false,
		PersistRules: false,
		AllowedIPs:   []string{},
		AllowedPorts: []int{},
	}
}

type KillSwitch struct {
	mu       sync.RWMutex
	config   *Config
	state    State
	vpnIP    net.IP
	vpnPort  int
	localIPs []net.IP

	impl Platform

	onStateChange func(State)
	onError       func(error)
	ctx           context.Context
	cancel        context.CancelFunc
}

type Platform interface {
	Name() string
	IsSupported() bool
	Enable(vpnServerIP net.IP, vpnPort int, allowLAN bool, allowDNS bool, allowedIPs []net.IP) error
	Disable() error
	IsActive() (bool, error)
	Cleanup() error
}

func New(cfg *Config) (*KillSwitch, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	ks := &KillSwitch{
		config: cfg,
		state:  StateDisabled,
		ctx:    ctx,
		cancel: cancel,
	}

	impl, err := NewPlatformImpl()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize platform: %w", err)
	}
	ks.impl = impl

	ks.detectLocalIPs()

	return ks, nil
}

func (ks *KillSwitch) SetVPNServer(ip net.IP, port int) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.vpnIP = ip
	ks.vpnPort = port
}

func (ks *KillSwitch) Enable() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.impl.IsSupported() {
		return fmt.Errorf("kill switch not supported on this platform")
	}

	if ks.state == StateActive {
		return nil
	}

	if ks.vpnIP == nil {
		return fmt.Errorf("VPN server IP not set")
	}

	allowedIPs := make([]net.IP, 0, len(ks.config.AllowedIPs))
	for _, ipStr := range ks.config.AllowedIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			allowedIPs = append(allowedIPs, ip)
		}
	}

	if ks.config.AllowLAN {
		allowedIPs = append(allowedIPs, ks.localIPs...)
	}

	if err := ks.impl.Enable(ks.vpnIP, ks.vpnPort, ks.config.AllowLAN, ks.config.AllowDNS, allowedIPs); err != nil {
		return fmt.Errorf("failed to enable kill switch: %w", err)
	}

	ks.state = StateActive
	ks.notifyStateChange(StateActive)

	return nil
}

func (ks *KillSwitch) Disable() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.state == StateDisabled {
		return nil
	}

	if err := ks.impl.Disable(); err != nil {
		return fmt.Errorf("failed to disable kill switch: %w", err)
	}

	ks.state = StateDisabled
	ks.notifyStateChange(StateDisabled)

	return nil
}

func (ks *KillSwitch) IsActive() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.state == StateActive
}

func (ks *KillSwitch) GetState() State {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.state
}

func (ks *KillSwitch) GetConfig() *Config {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.config
}

func (ks *KillSwitch) UpdateConfig(cfg *Config) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	wasActive := ks.state == StateActive

	if wasActive {
		if err := ks.impl.Disable(); err != nil {
			return err
		}
	}

	ks.config = cfg

	if wasActive && cfg.Enabled {
		allowedIPs := make([]net.IP, 0)
		for _, ipStr := range cfg.AllowedIPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				allowedIPs = append(allowedIPs, ip)
			}
		}
		if cfg.AllowLAN {
			allowedIPs = append(allowedIPs, ks.localIPs...)
		}

		if err := ks.impl.Enable(ks.vpnIP, ks.vpnPort, cfg.AllowLAN, cfg.AllowDNS, allowedIPs); err != nil {
			return err
		}
	}

	return nil
}

func (ks *KillSwitch) OnStateChange(callback func(State)) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.onStateChange = callback
}

func (ks *KillSwitch) OnError(callback func(error)) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.onError = callback
}

func (ks *KillSwitch) Shutdown() error {
	ks.cancel()

	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.config.PersistRules {
		if err := ks.impl.Cleanup(); err != nil {
			return err
		}
	}

	ks.state = StateDisabled
	return nil
}

func (ks *KillSwitch) detectLocalIPs() {
	ks.localIPs = []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && !ip.IsLoopback() {
				if ip.To4() != nil {
					if ip.IsPrivate() {
						ks.localIPs = append(ks.localIPs, ip)
					}
				}
			}
		}
	}

}

func (ks *KillSwitch) notifyStateChange(state State) {
	if ks.onStateChange != nil {
		go ks.onStateChange(state)
	}
}

func (ks *KillSwitch) notifyError(err error) {
	if ks.onError != nil {
		go ks.onError(err)
	}
}

func (ks *KillSwitch) MonitorHealth() {
	if !ks.config.Enabled || !ks.impl.IsSupported() {
		return
	}

	active, err := ks.impl.IsActive()
	if err != nil {
		ks.notifyError(fmt.Errorf("health check failed: %v", err))
		return
	}

	if !active && ks.state == StateActive {
		ks.notifyError(fmt.Errorf("kill switch rules unexpectedly deactivated"))
	}
}

type Status struct {
	State       string    `json:"state"`
	Enabled     bool      `json:"enabled"`
	Active      bool      `json:"active"`
	VPNServer   string    `json:"vpn_server,omitempty"`
	AllowLAN    bool      `json:"allow_lan"`
	AllowDNS    bool      `json:"allow_dns"`
	Platform    string    `json:"platform"`
	Supported   bool      `json:"supported"`
	LastChanged time.Time `json:"last_changed,omitempty"`
}

func (ks *KillSwitch) GetStatus() Status {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	status := Status{
		State:     ks.state.String(),
		Enabled:   ks.config.Enabled,
		Active:    ks.state == StateActive,
		AllowLAN:  ks.config.AllowLAN,
		AllowDNS:  ks.config.AllowDNS,
		Platform:  ks.impl.Name(),
		Supported: ks.impl.IsSupported(),
	}

	if ks.vpnIP != nil {
		status.VPNServer = fmt.Sprintf("%s:%d", ks.vpnIP, ks.vpnPort)
	}

	return status
}
