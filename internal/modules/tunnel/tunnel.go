// Package tunnel provides the VPN tunnel management module
package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"
	"whispera/internal/modules/killswitch"
	"whispera/internal/modules/phantom"
	asnbypass "whispera/internal/modules/transport/asn_bypass"
)

var log = logger.Module("tunnel")

const (
	ModuleName    = "tunnel.manager"
	ModuleVersion = "1.0.0"
)

// TunnelState represents the tunnel state
type TunnelState int

const (
	StateDisconnected TunnelState = iota
	StateConnecting
	StateConnected
	StateReconnecting
	StateError
)

func (s TunnelState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// Config holds tunnel configuration
type Config struct {
	ServerAddr           string        // Server address
	KeepaliveInterval    time.Duration // Keepalive interval
	ReconnectInterval    time.Duration // Reconnect interval
	ReconnectMaxDelay    time.Duration // Max reconnect delay
	MaxReconnectAttempts int           // Max reconnect attempts (0 = infinite)
	ConnectionTimeout    time.Duration // Connection timeout

	// Kill Switch
	KillSwitchEnabled  bool // Enable kill switch
	KillSwitchAllowLAN bool // Allow LAN access when kill switch active
	KillSwitchAllowDNS bool // Allow DNS when kill switch active

	// ASN Bypass (for VPN/Datacenter IP detection evasion)
	EnableASNBypass    bool               // Enable ASN bypass for datacenter IPs
	ASNBypassStrategy  asnbypass.Strategy // Bypass strategy
	TLSFingerprint     string             // Browser TLS fingerprint: chrome, firefox, safari
	DomainFrontHost    string             // Domain fronting host (e.g., CDN domain)
	ResidentialProxies []string           // Residential proxy list for proxy chain strategy
	EnableJA3Randomize bool               // Randomize JA3 fingerprint per connection

	// Phantom Protocol (SNI masquerading)
	EnablePhantom       bool   // Enable Phantom protocol for SNI masquerading
	PhantomSNI          string // SNI to use (e.g., "cloudflare.com")
	PhantomShortId      string // Client short ID for authentication
	PhantomServerPubKey string // Server's x25519 public key (hex)
}

// DefaultConfig returns default tunnel configuration
func DefaultConfig() *Config {
	return &Config{
		KeepaliveInterval:    30 * time.Second,
		ReconnectInterval:    5 * time.Second,
		ReconnectMaxDelay:    60 * time.Second,
		MaxReconnectAttempts: 0,
		ConnectionTimeout:    30 * time.Second,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.KeepaliveInterval <= 0 {
		c.KeepaliveInterval = 30 * time.Second
	}
	if c.ReconnectInterval <= 0 {
		c.ReconnectInterval = 5 * time.Second
	}
	if c.ReconnectMaxDelay <= 0 {
		c.ReconnectMaxDelay = 60 * time.Second
	}
	if c.ConnectionTimeout <= 0 {
		c.ConnectionTimeout = 30 * time.Second
	}
	return nil
}

// Manager implements VPN tunnel management
type Manager struct {
	*base.Module
	config *Config

	// State
	state     TunnelState
	stateMu   sync.RWMutex
	lastError error

	// Connection
	conn      net.Conn
	connMu    sync.RWMutex
	sessionID uint32

	// Dependencies
	tunDevice interfaces.TUNDevice
	handshake interfaces.HandshakeHandler
	dataPlane interfaces.DataPlane
	crypto    interfaces.CryptoProvider

	// Keepalive
	keepaliveTicker *time.Ticker
	keepaliveCancel context.CancelFunc

	// Stats
	reconnectAttempts uint32
	bytesUp           uint64
	bytesDown         uint64
	lastKeepalive     time.Time
	connectedAt       time.Time

	// Callbacks
	onStateChange func(TunnelState)

	// Kill Switch
	killSwitch *killswitch.KillSwitch

	// Obfuscation
	obfuscator interfaces.Obfuscator

	// ASN Bypass - for evading datacenter IP detection
	asnBypassDialer *asnbypass.Dialer

	// Phantom Protocol - for SNI masquerading
	phantomAuth *phantom.ClientAuth
}

// New creates a new tunnel manager
func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	m := &Manager{
		// tun.device removed - client uses SOCKS5 proxy instead of TUN interface
		Module: base.NewModule(ModuleName, ModuleVersion, []string{"handshake.handler"}),
		config: cfg,
		state:  StateDisconnected,
	}

	// Initialize ASN Bypass dialer if enabled
	if cfg.EnableASNBypass {
		asnConfig := &asnbypass.Config{
			Strategy:               cfg.ASNBypassStrategy,
			TLSFingerprint:         cfg.TLSFingerprint,
			FrontDomain:            cfg.DomainFrontHost,
			ResidentialProxies:     cfg.ResidentialProxies,
			EnableJA3Randomization: cfg.EnableJA3Randomize,
			ConnectionBurstLimit:   5,
			ConnectionCooldown:     2 * time.Second,
			FailoverTimeout:        cfg.ConnectionTimeout,
			FallbackStrategies:     []asnbypass.Strategy{asnbypass.StrategyTLSMasquerade, asnbypass.StrategyDomainFronting},
		}
		m.asnBypassDialer = asnbypass.NewDialer(asnConfig)
		log.Info("ASN bypass enabled with strategy: %d, fingerprint: %s", cfg.ASNBypassStrategy, cfg.TLSFingerprint)
	}

	// Initialize Kill Switch if enabled in config
	if cfg.KillSwitchEnabled {
		ksConfig := &killswitch.Config{
			Enabled:      cfg.KillSwitchEnabled,
			AllowLAN:     cfg.KillSwitchAllowLAN,
			AllowDNS:     cfg.KillSwitchAllowDNS,
			PersistRules: false, // Don't persist on exit to avoid locking user out
		}

		ks, err := killswitch.New(ksConfig)
		if err != nil {
			log.Warn("Failed to initialize kill switch: %v", err)
		} else {
			m.killSwitch = ks

			// Set callbacks
			ks.OnStateChange(func(state killswitch.State) {
				m.PublishEvent("killswitch.state_changed", map[string]interface{}{
					"state": state.String(),
				})
			})
		}
	}

	// Initialize Phantom Protocol if enabled
	if cfg.EnablePhantom {
		shortId := cfg.PhantomShortId
		// Auto-generate shortId if not provided
		if shortId == "" {
			shortId = generateRandomShortId()
			log.Info("Phantom: Auto-generated shortId: %s", shortId)
		}

		m.phantomAuth = phantom.NewClientAuth(&phantom.ClientConfig{
			ServerPublicKey: cfg.PhantomServerPubKey,
			ShortId:         shortId,
		})
		log.Info("Phantom protocol enabled (SNI: %s)", cfg.PhantomSNI)
	}

	return m, nil
}

// Init initializes the tunnel manager
func (m *Manager) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := m.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if tunnelCfg, ok := cfg.(*Config); ok {
		m.config = tunnelCfg
	}

	return nil
}

// Start starts the tunnel manager
func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	m.SetHealthy(true, "tunnel manager running")
	m.PublishEvent(events.EventTypeModuleStarted, nil)

	return nil
}

// Stop stops the tunnel manager
func (m *Manager) Stop() error {
	m.Disconnect()
	m.PublishEvent(events.EventTypeModuleStopped, nil)
	return m.Module.Stop()
}

// SetDependencies sets module dependencies
func (m *Manager) SetDependencies(
	tun interfaces.TUNDevice,
	handshake interfaces.HandshakeHandler,
	dataPlane interfaces.DataPlane,
	crypto interfaces.CryptoProvider,
) {
	m.tunDevice = tun
	m.handshake = handshake
	m.dataPlane = dataPlane
	m.crypto = crypto
}

// SetObfuscator sets the obfuscation engine for traffic masking
// The obfuscator applies FTE, Marionette, and ML-based obfuscation
func (m *Manager) SetObfuscator(o interfaces.Obfuscator) {
	m.obfuscator = o
	if o != nil {
		log.Info("Obfuscation enabled for tunnel traffic")
	}
}

// Connect connects to the VPN server
func (m *Manager) Connect(ctx context.Context) error {
	m.setState(StateConnecting)

	var conn net.Conn
	var err error

	// If Phantom protocol is enabled, configure SNI masquerading
	if m.config.EnablePhantom && m.phantomAuth != nil {
		log.Info("Phantom protocol active - using SNI: %s", m.config.PhantomSNI)

		// Configure ASN bypass dialer with Phantom SNI
		if m.asnBypassDialer != nil {
			m.asnBypassDialer.SetPhantomConfig(m.config.PhantomSNI, m.phantomAuth)
		}
	}

	// Try ASN bypass (TCP with TLS masquerading) first if enabled
	// This is critical for VPN/Datacenter IPs that get blocked at ClientHello
	if m.asnBypassDialer != nil && m.config.EnableASNBypass {
		log.Info("Using ASN bypass dialer (strategy: %d, fingerprint: %s)",
			m.config.ASNBypassStrategy, m.config.TLSFingerprint)

		// ASN bypass uses TCP with browser TLS fingerprints
		conn, err = m.asnBypassDialer.DialContext(ctx, "tcp", m.config.ServerAddr)
		if err != nil {
			log.Warn("ASN bypass failed: %v, falling back to direct UDP", err)
			// Fall through to UDP
		} else {
			log.Info("ASN bypass connection established successfully")
		}
	}

	// Fallback to direct UDP connection if ASN bypass not enabled or failed
	if conn == nil {
		// Resolve server address
		addr, err := net.ResolveUDPAddr("udp", m.config.ServerAddr)
		if err != nil {
			m.setError(fmt.Errorf("failed to resolve address: %w", err))
			return err
		}

		// Create UDP connection
		udpConn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			m.setError(fmt.Errorf("failed to dial UDP: %w", err))
			return err
		}
		conn = udpConn
	}

	m.connMu.Lock()
	m.conn = conn
	m.connMu.Unlock()

	// Perform handshake
	// Note: handshake needs to work with both TCP and UDP connections
	if m.handshake != nil {
		session, err := m.handshake.InitiateHandshake(ctx, m.conn, conn.RemoteAddr())
		if err != nil {
			m.setError(fmt.Errorf("handshake failed: %w", err))
			conn.Close()
			return err
		}
		if session != nil {
			m.sessionID = session.ID()
		}
	}

	// Start keepalive
	m.startKeepalive()

	m.connectedAt = time.Now()
	m.setState(StateConnected)

	// Activate Kill Switch
	if m.killSwitch != nil && m.config.KillSwitchEnabled {
		// Extract VPN server IP from connection's remote address
		remoteAddr := conn.RemoteAddr()
		var serverIP net.IP
		var serverPort int

		switch addr := remoteAddr.(type) {
		case *net.UDPAddr:
			serverIP = addr.IP
			serverPort = addr.Port
		case *net.TCPAddr:
			serverIP = addr.IP
			serverPort = addr.Port
		default:
			// Try to parse as string
			host, portStr, _ := net.SplitHostPort(remoteAddr.String())
			serverIP = net.ParseIP(host)
			fmt.Sscanf(portStr, "%d", &serverPort)
		}

		if serverIP != nil {
			m.killSwitch.SetVPNServer(serverIP, serverPort)
			if err := m.killSwitch.Enable(); err != nil {
				log.Error("Failed to enable kill switch: %v", err)
				m.PublishEvent("killswitch.error", err.Error())
			}
		}
	}

	m.PublishEvent("tunnel.connected", map[string]interface{}{
		"server":     m.config.ServerAddr,
		"session_id": m.sessionID,
	})

	return nil
}

// Disconnect disconnects from the VPN server
func (m *Manager) Disconnect() {
	m.stopKeepalive()

	// Deactivate Kill Switch
	if m.killSwitch != nil {
		if err := m.killSwitch.Disable(); err != nil {
			log.Error("Failed to disable kill switch: %v", err)
		}
	}

	m.connMu.Lock()
	if m.conn != nil {
		m.conn.Close()
		m.conn = nil
	}
	m.connMu.Unlock()

	m.setState(StateDisconnected)

	m.PublishEvent("tunnel.disconnected", nil)
}

// Reconnect reconnects to the VPN server
func (m *Manager) Reconnect(ctx context.Context) error {
	m.setState(StateReconnecting)

	delay := m.config.ReconnectInterval
	attempts := 0

	for {
		attempts++
		atomic.StoreUint32(&m.reconnectAttempts, uint32(attempts))

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check max attempts
		if m.config.MaxReconnectAttempts > 0 && attempts > m.config.MaxReconnectAttempts {
			err := fmt.Errorf("max reconnect attempts (%d) exceeded", m.config.MaxReconnectAttempts)
			m.setError(err)
			return err
		}

		// Disconnect existing connection
		m.Disconnect()

		// Try to connect
		err := m.Connect(ctx)
		if err == nil {
			return nil
		}

		// Wait before retry with exponential backoff
		time.Sleep(delay)
		delay = time.Duration(float64(delay) * 1.5)
		if delay > m.config.ReconnectMaxDelay {
			delay = m.config.ReconnectMaxDelay
		}
	}
}

// Send sends data through the tunnel with obfuscation
func (m *Manager) Send(data []byte) error {
	// Apply obfuscation if available (FTE -> Marionette -> ML chain)
	// Also applies anti-reputation timing jitter
	if m.obfuscator != nil {
		obfuscated, delay, err := m.obfuscator.Process(data, interfaces.DirectionOutbound)
		if err == nil && obfuscated != nil {
			data = obfuscated
		}
		// Apply anti-reputation jitter delay
		if delay > 0 && delay < 5*time.Second {
			time.Sleep(delay)
		}
	}

	m.connMu.RLock()
	conn := m.conn
	m.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	n, err := conn.Write(data)
	if err != nil {
		return err
	}

	atomic.AddUint64(&m.bytesUp, uint64(n))
	m.UpdateActivity()

	return nil
}

// Receive receives data from the tunnel with deobfuscation
func (m *Manager) Receive(buf []byte) (int, error) {
	m.connMu.RLock()
	conn := m.conn
	m.connMu.RUnlock()

	if conn == nil {
		return 0, fmt.Errorf("not connected")
	}

	// Set read deadline to avoid blocking forever
	if udpConn, ok := conn.(*net.UDPConn); ok {
		udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	}

	n, err := conn.Read(buf)
	if err != nil {
		// Don't log timeout errors as they are expected
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return n, err
		}
		log.Printf("[TUNNEL] Receive: read error: %v", err)
		return n, err
	}

	if n > 0 {
		log.Printf("[TUNNEL] Receive: got %d bytes from server", n)
	}

	// Apply deobfuscation if available
	if m.obfuscator != nil && n > 0 {
		deobfuscated, _, err := m.obfuscator.Process(buf[:n], interfaces.DirectionInbound)
		if err == nil && deobfuscated != nil {
			copy(buf, deobfuscated)
			n = len(deobfuscated)
		}
	}

	atomic.AddUint64(&m.bytesDown, uint64(n))
	m.UpdateActivity()

	return n, nil
}

// GetState returns the current tunnel state
func (m *Manager) GetState() TunnelState {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.state
}

// IsConnected returns true if connected
func (m *Manager) IsConnected() bool {
	return m.GetState() == StateConnected
}

// GetSessionID returns the session ID
func (m *Manager) GetSessionID() uint32 {
	return m.sessionID
}

// OnStateChange sets the state change callback
func (m *Manager) OnStateChange(callback func(TunnelState)) {
	m.onStateChange = callback
}

// setState sets the tunnel state
func (m *Manager) setState(state TunnelState) {
	m.stateMu.Lock()
	oldState := m.state
	m.state = state
	if state != StateError {
		m.lastError = nil
	}
	m.stateMu.Unlock()

	if oldState != state {
		if m.onStateChange != nil {
			m.onStateChange(state)
		}
		m.PublishEvent("tunnel.state_changed", map[string]interface{}{
			"old_state": oldState.String(),
			"new_state": state.String(),
		})
	}
}

// setError sets error state
func (m *Manager) setError(err error) {
	m.stateMu.Lock()
	m.state = StateError
	m.lastError = err
	m.stateMu.Unlock()

	m.SetHealthy(false, err.Error())
}

// startKeepalive starts the keepalive ticker
func (m *Manager) startKeepalive() {
	m.stopKeepalive()

	ctx, cancel := context.WithCancel(context.Background())
	m.keepaliveCancel = cancel
	m.keepaliveTicker = time.NewTicker(m.config.KeepaliveInterval)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.keepaliveTicker.C:
				m.sendKeepalive()
			}
		}
	}()
}

// stopKeepalive stops the keepalive ticker
func (m *Manager) stopKeepalive() {
	if m.keepaliveCancel != nil {
		m.keepaliveCancel()
		m.keepaliveCancel = nil
	}
	if m.keepaliveTicker != nil {
		m.keepaliveTicker.Stop()
		m.keepaliveTicker = nil
	}
}

// sendKeepalive sends a keepalive packet
func (m *Manager) sendKeepalive() {
	// Simple keepalive packet
	keepalive := []byte{0x00} // Empty packet as keepalive
	m.Send(keepalive)
	m.lastKeepalive = time.Now()
}

// HealthCheck returns health status
func (m *Manager) HealthCheck() interfaces.HealthStatus {
	status := m.Module.HealthCheck()

	m.stateMu.RLock()
	status.Details["state"] = m.state.String()
	if m.lastError != nil {
		status.Details["last_error"] = m.lastError.Error()
	}
	m.stateMu.RUnlock()

	status.Details["server"] = m.config.ServerAddr
	status.Details["session_id"] = m.sessionID
	status.Details["bytes_up"] = atomic.LoadUint64(&m.bytesUp)
	status.Details["bytes_down"] = atomic.LoadUint64(&m.bytesDown)
	status.Details["reconnect_attempts"] = atomic.LoadUint32(&m.reconnectAttempts)
	if !m.connectedAt.IsZero() {
		status.Details["connected_since"] = m.connectedAt
		status.Details["uptime"] = time.Since(m.connectedAt).String()
	}
	if !m.lastKeepalive.IsZero() {
		status.Details["last_keepalive"] = m.lastKeepalive
	}

	return status
}

// Factory creates tunnel manager modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}

// generateRandomShortId generates a random 8-character hex short ID
func generateRandomShortId() string {
	const chars = "0123456789abcdef"
	result := make([]byte, 8)
	for i := range result {
		// Use time-based seed for simplicity
		result[i] = chars[int(time.Now().UnixNano()/int64(i+1))%len(chars)]
	}
	return string(result)
}
