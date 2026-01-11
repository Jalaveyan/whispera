// Package killswitch provides network kill switch functionality
// that blocks all traffic when VPN connection is lost
package killswitch

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/logger"
)

var log = logger.Module("killswitch")

// State represents the current state of the kill switch
type State int

const (
	StateDisabled State = iota
	StateEnabled
	StateActive // Traffic is being blocked
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

// Config holds kill switch configuration
type Config struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	AllowLAN     bool     `yaml:"allow_lan" json:"allow_lan"`         // Allow local network access
	AllowDNS     bool     `yaml:"allow_dns" json:"allow_dns"`         // Allow DNS queries (53/udp)
	PersistRules bool     `yaml:"persist_rules" json:"persist_rules"` // Keep rules after app exit
	AllowedIPs   []string `yaml:"allowed_ips" json:"allowed_ips"`     // Additional allowed IPs
	AllowedPorts []int    `yaml:"allowed_ports" json:"allowed_ports"` // Additional allowed ports
}

// DefaultConfig returns default kill switch configuration
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

// KillSwitch manages network traffic blocking when VPN is disconnected
type KillSwitch struct {
	mu       sync.RWMutex
	config   *Config
	state    State
	vpnIP    net.IP   // VPN server IP (always allowed)
	vpnPort  int      // VPN server port
	localIPs []net.IP // Local network IPs (for LAN exception)

	// Platform-specific implementation
	impl Platform

	// Event callbacks
	onStateChange func(State)
	onError       func(error)

	// Context for background tasks
	ctx    context.Context
	cancel context.CancelFunc
}

// Platform defines the interface for OS-specific implementations
type Platform interface {
	// Name returns platform name
	Name() string

	// IsSupported checks if kill switch is supported on this platform
	IsSupported() bool

	// Enable activates the kill switch (blocks all non-VPN traffic)
	Enable(vpnServerIP net.IP, vpnPort int, allowLAN bool, allowDNS bool, allowedIPs []net.IP) error

	// Disable deactivates the kill switch (restores normal traffic)
	Disable() error

	// IsActive returns true if kill switch rules are currently active
	IsActive() (bool, error)

	// Cleanup removes all kill switch rules (called on shutdown)
	Cleanup() error
}

// New creates a new kill switch instance
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

	// Initialize platform-specific implementation
	impl, err := NewPlatformImpl()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize platform: %w", err)
	}
	ks.impl = impl

	// Detect local network IPs for LAN exception
	ks.detectLocalIPs()

	log.Info("Kill switch initialized (platform: %s, supported: %v)",
		impl.Name(), impl.IsSupported())

	return ks, nil
}

// SetVPNServer sets the VPN server address that should always be allowed
func (ks *KillSwitch) SetVPNServer(ip net.IP, port int) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.vpnIP = ip
	ks.vpnPort = port
	log.Debug("VPN server set: %s:%d", ip, port)
}

// Enable activates the kill switch
func (ks *KillSwitch) Enable() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.impl.IsSupported() {
		return fmt.Errorf("kill switch not supported on this platform")
	}

	if ks.state == StateActive {
		return nil // Already active
	}

	if ks.vpnIP == nil {
		return fmt.Errorf("VPN server IP not set")
	}

	// Parse allowed IPs from config
	allowedIPs := make([]net.IP, 0, len(ks.config.AllowedIPs))
	for _, ipStr := range ks.config.AllowedIPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			allowedIPs = append(allowedIPs, ip)
		}
	}

	// Add local IPs if LAN access is allowed
	if ks.config.AllowLAN {
		allowedIPs = append(allowedIPs, ks.localIPs...)
	}

	// Enable platform-specific rules
	if err := ks.impl.Enable(ks.vpnIP, ks.vpnPort, ks.config.AllowLAN, ks.config.AllowDNS, allowedIPs); err != nil {
		return fmt.Errorf("failed to enable kill switch: %w", err)
	}

	ks.state = StateActive
	ks.notifyStateChange(StateActive)

	log.Info("Kill switch activated (VPN: %s:%d, LAN: %v, DNS: %v)",
		ks.vpnIP, ks.vpnPort, ks.config.AllowLAN, ks.config.AllowDNS)

	return nil
}

// Disable deactivates the kill switch
func (ks *KillSwitch) Disable() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.state == StateDisabled {
		return nil // Already disabled
	}

	if err := ks.impl.Disable(); err != nil {
		return fmt.Errorf("failed to disable kill switch: %w", err)
	}

	ks.state = StateDisabled
	ks.notifyStateChange(StateDisabled)

	log.Info("Kill switch deactivated")
	return nil
}

// IsActive returns true if kill switch is currently blocking traffic
func (ks *KillSwitch) IsActive() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.state == StateActive
}

// GetState returns current kill switch state
func (ks *KillSwitch) GetState() State {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.state
}

// GetConfig returns current configuration
func (ks *KillSwitch) GetConfig() *Config {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.config
}

// UpdateConfig updates kill switch configuration
func (ks *KillSwitch) UpdateConfig(cfg *Config) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	wasActive := ks.state == StateActive

	// If active, need to reapply rules with new config
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

	log.Info("Kill switch config updated")
	return nil
}

// OnStateChange sets callback for state changes
func (ks *KillSwitch) OnStateChange(callback func(State)) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.onStateChange = callback
}

// OnError sets callback for errors
func (ks *KillSwitch) OnError(callback func(error)) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.onError = callback
}

// Shutdown cleanly shuts down the kill switch
func (ks *KillSwitch) Shutdown() error {
	ks.cancel()

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Remove rules unless persist is enabled
	if !ks.config.PersistRules {
		if err := ks.impl.Cleanup(); err != nil {
			log.Warn("Failed to cleanup kill switch rules: %v", err)
			return err
		}
	}

	ks.state = StateDisabled
	log.Info("Kill switch shutdown complete")
	return nil
}

// detectLocalIPs detects local network IP ranges for LAN exception
func (ks *KillSwitch) detectLocalIPs() {
	ks.localIPs = []net.IP{
		// Loopback
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
	}

	// Get local interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Warn("Failed to get network interfaces: %v", err)
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
				// Add local network ranges
				if ip.To4() != nil {
					// For IPv4, add common LAN ranges
					if ip.IsPrivate() {
						ks.localIPs = append(ks.localIPs, ip)
					}
				}
			}
		}
	}

	log.Debug("Detected %d local IPs for LAN exception", len(ks.localIPs))
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

// MonitorHealth periodically checks if kill switch rules are still active
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
		// Try to re-enable?
	}
}

// Status returns current kill switch status for API/monitoring
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

// GetStatus returns current status for API
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
