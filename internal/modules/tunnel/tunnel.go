// Package tunnel provides the VPN tunnel management module
package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
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
	quic_transport "whispera/internal/modules/transport/quic"
	"whispera/internal/mux"
	"whispera/internal/obfuscation/russian"
)

var log = logger.Module("tunnel")

const (
	ModuleName    = "tunnel.manager"
	ModuleVersion = "1.0.0"

	// Frame constants for manual parsing (to avoid import cycles)
	FrameHeaderSize  = 8
	FrameTypeConnect = 0x01
	FrameTypeClose   = 0x05
)

// bufferPool recycles buffers to allow zero-allocation packet processing
// Size: 64KB payload + 8B header + safety margin
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 66048)
	},
}

// TunnelState represents the tunnel state
type TunnelState int

const (
	StateDisconnected TunnelState = iota
	StateConnecting
	StateConnected
	StateReconnecting
	StateRotating // New state for SNI rotation
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
	case StateRotating:
		return "rotating"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// Config holds tunnel configuration
type Config struct {
	ServerAddr           string        // Server address (Primary/UDP)
	ServerAddrTCP        string        // Server address TCP (Fallback)
	KeepaliveInterval    time.Duration // Keepalive interval
	ReconnectInterval    time.Duration // Reconnect interval
	ReconnectMaxDelay    time.Duration // Max reconnect delay
	MaxReconnectAttempts int           // Max reconnect attempts (0 = infinite)
	ConnectionTimeout    time.Duration // Connection timeout

	// Rotation
	EnableRotation   bool          // Enable seamless SNI rotation
	RotationInterval time.Duration // Interval for rotation (e.g. 10 min)
	DrainingTimeout  time.Duration // Time to keep old connections alive (e.g. 30 min)

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
		KeepaliveInterval:    15 * time.Second, // INCREASED from 3s for stability
		ReconnectInterval:    5 * time.Second,
		ReconnectMaxDelay:    60 * time.Second,
		MaxReconnectAttempts: 0,
		ConnectionTimeout:    30 * time.Second,
		EnableRotation:       true,
		RotationInterval:     60 * time.Minute, // INCREASED from 30 min
		DrainingTimeout:      90 * time.Minute, // INCREASED from 60 min
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Optimize smux configuration for 4K streaming
	// This part of the configuration is typically set globally or passed to the smux library.
	// If smux.DefaultConfig() is intended to be modified, it should be done once at startup
	// or a custom config should be created and passed to smux.NewClient/NewServer.
	// This code snippet is placed here as per user instruction, but its effect might depend
	// on how smux is initialized elsewhere in the application.
	// Optimize smux configuration for 4K streaming
	// SMUX configuration is now handled dynamically in connectInternal using internal/mux logic
	// but we validate key parameters here.
	if c.KeepaliveInterval <= 0 {
		c.KeepaliveInterval = 10 * time.Second
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
	if c.RotationInterval < 1*time.Minute {
		c.RotationInterval = 15 * time.Minute
	}
	if c.DrainingTimeout < c.RotationInterval {
		c.DrainingTimeout = c.RotationInterval * 2
	}
	return nil
}

// managedConn wraps a net.Conn with management info
type managedConn struct {
	net.Conn
	id        string // Identifier (e.g. SNI used)
	createdAt time.Time
	closing   chan struct{} // Signal to stop reading
}

// Manager implements VPN tunnel management
type Manager struct {
	*base.Module
	config *Config

	// State
	state     TunnelState
	stateMu   sync.RWMutex
	lastError error

	// Connection Management (Seamless Rotation)
	activeConn    *managedConn
	activePool    []*managedConn // Connection Pool for Multipath
	drainingConns []*managedConn
	streamConns   map[uint16]*managedConn // Map StreamID to Connection
	readCh        chan []byte             // Centralized read channel
	connMu        sync.RWMutex
	sessionID     uint32

	// Dependencies
	tunDevice interfaces.TUNDevice
	handshake interfaces.HandshakeHandler
	dataPlane interfaces.DataPlane
	crypto    interfaces.CryptoProvider

	// Keepalive & Rotation
	keepaliveTicker *time.Ticker
	keepaliveCancel context.CancelFunc
	rotationTicker  *time.Ticker
	rotationCancel  context.CancelFunc

	// Stats
	reconnectAttempts uint32
	bytesUp           uint64
	bytesDown         uint64
	lastKeepalive     time.Time
	lastPong          time.Time // Track last PONG response from server
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

	// Track if transport is already secure (e.g. TLS) to skip double-obfuscation
	isTransportSecure bool

	// List of Russian SNIs for rotation
	russianSNIs  []string
	currentSNI   string
	lastRotation time.Time
}

// getMuxConfig creates a tuned mux configuration
func (m *Manager) getMuxConfig() *mux.Config {
	return &mux.Config{
		MaxFrameSize:         65535,             // 64KB - 1 (Max allowed by SMUX uint16)
		MaxReceiveBuffer:     512 * 1024 * 1024, // 512MB (Prevent session locking with multiple 20MB streams)
		MaxStreamBuffer:      20 * 1024 * 1024,  // 20MB (Ultra Aggressive buffering for 8K)
		KeepAliveInterval:    2 * time.Second,   // Aggressive KeepAlive to prevent CWND collapse
		KeepAliveTimeout:     60 * time.Second,  // 60s timeout to survive lag spikes
		MaxConcurrentStreams: 256,
	}
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
		Module:      base.NewModule(ModuleName, ModuleVersion, []string{"handshake.handler"}),
		config:      cfg,
		state:       StateDisconnected,
		streamConns: make(map[uint16]*managedConn),
		readCh:      make(chan []byte, 4096), // Reduced from 32000 to 4096 to save RAM (256MB max)
	}

	// Initialize ASN Bypass dialer if enabled
	if cfg.EnableASNBypass {
		frontDomain := cfg.DomainFrontHost
		enableSNIMask := false

		if cfg.EnablePhantom && cfg.PhantomSNI != "" {
			frontDomain = cfg.PhantomSNI
			enableSNIMask = true
		}

		asnConfig := &asnbypass.Config{
			Strategy:               cfg.ASNBypassStrategy,
			TLSFingerprint:         cfg.TLSFingerprint,
			FrontDomain:            frontDomain,
			EnableSNIMask:          enableSNIMask,
			ResidentialProxies:     cfg.ResidentialProxies,
			EnableJA3Randomization: cfg.EnableJA3Randomize,
			ConnectionBurstLimit:   5,
			ConnectionCooldown:     2 * time.Second,
			FailoverTimeout:        cfg.ConnectionTimeout,
			FallbackStrategies:     []asnbypass.Strategy{asnbypass.StrategyTLSMasquerade, asnbypass.StrategyDomainFronting},
		}

		// FORCE TLS Masquerade strategy if Phantom is enabled
		// This is critical because Phantom Protocol requires a TLS ClientHello
		// to be sent first, which is only handled by the StrategyTLSMasquerade logic.
		if cfg.EnablePhantom {
			asnConfig.Strategy = asnbypass.StrategyTLSMasquerade
		}

		m.asnBypassDialer = asnbypass.NewDialer(asnConfig)
		if cfg.EnablePhantom {
			log.Info("ASN Bypass initialized for Phantom (Forced Strategy: TLSMasquerade)")
		} else {
			log.Info("ASN Bypass initialized (Strategy: %v)", cfg.ASNBypassStrategy)
		}

	}

	// Initialize Kill Switch if enabled in config
	if cfg.KillSwitchEnabled {
		ksConfig := &killswitch.Config{
			Enabled:      cfg.KillSwitchEnabled,
			AllowLAN:     cfg.KillSwitchAllowLAN,
			AllowDNS:     cfg.KillSwitchAllowDNS,
			PersistRules: false,
		}

		ks, err := killswitch.New(ksConfig)
		if err != nil {
			log.Warn("Failed to initialize kill switch: %v", err)
		} else {
			m.killSwitch = ks
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
		if shortId == "" {
			shortId = generateRandomShortId()
			log.Info("Phantom: Auto-generated shortId: %s", shortId)
		}

		m.phantomAuth = phantom.NewClientAuth(&phantom.ClientConfig{
			ServerPublicKey: cfg.PhantomServerPubKey,
			ShortId:         shortId,
		})

		if m.asnBypassDialer != nil {
			m.asnBypassDialer.SetPhantomAuth(m.phantomAuth)
		}

		log.Info("Phantom protocol enabled (SNI: %s)", cfg.PhantomSNI)
	}

	// Initialize Russian SNI list for rotation
	rt := russian.NewRussianTunneler()
	services := rt.GetAvailableServices()
	for _, svcName := range services {
		if info, err := rt.GetServiceInfo(svcName); err == nil {
			m.russianSNIs = append(m.russianSNIs, info.Domain)
		}
	}
	if len(m.russianSNIs) > 0 {
		log.Info("Initialized %d Russian SNIs for rotation", len(m.russianSNIs))
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
	log.Info("[TUNNEL] Starting Tunnel Manager (Build: Zero-Copy Final v3)...")

	// Initiate connection automatically in background
	go m.Reconnect(context.Background())

	return nil
}

// Stop stops the tunnel manager
func (m *Manager) Stop() error {
	m.stopRotation()
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
func (m *Manager) SetObfuscator(o interfaces.Obfuscator) {
	m.obfuscator = o
	if o != nil {
		log.Info("Obfuscation enabled for tunnel traffic")
	}
}

// Connect connects to the VPN server
func (m *Manager) Connect(ctx context.Context) error {
	// Prevent duplicate simultaneous connections
	m.stateMu.Lock()
	if m.state == StateConnecting || m.state == StateConnected {
		currentState := m.state
		m.stateMu.Unlock()
		if currentState == StateConnected {
			log.Warn("[Connect] Already connected, ignoring duplicate Connect call")
		} else {
			log.Warn("[Connect] Connection already in progress, ignoring duplicate call")
		}
		return nil
	}
	m.stateMu.Unlock()

	// Clear old state for fresh connect
	m.Disconnect()

	return m.connectInternal(ctx, false)
}

// connectInternal establishes a connection pool. If isRotation is true, it preserves old connections.
func (m *Manager) connectInternal(ctx context.Context, isRotation bool) error {
	op := "Connect"
	if isRotation {
		op = "Rotate"
	}
	log.Info("[%s] Initiating connection sequence...", op)

	if !isRotation {
		m.setState(StateConnecting)
	} else {
		m.setState(StateRotating)
	}

	start := time.Now()

	// Parallel Dialing for Connection Pool
	// We aim for 4 connections to saturate bandwidth and avoid HoL blocking
	targetPoolSize := 4
	var connectedPool []*managedConn
	var poolMu sync.Mutex
	var wg sync.WaitGroup

	log.Info("[%s] Spawning pool of %d connections...", op, targetPoolSize)

	for i := 0; i < targetPoolSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Dial individual connection
			conn, err := m.dial(ctx)
			if err != nil {
				log.Warn("[%s] Failed to dial connection %d: %v", op, idx, err)
				return
			}

			// Create managed connection
			// ENABLING SMUX WRAPPER
			log.Info("[%s] Upgrading connection %d to SMUX (High Performance Mode)...", op, idx)

			// 1. Create Mux Session
			muxCfg := m.getMuxConfig()
			session, err := mux.Client(conn, muxCfg)
			if err != nil {
				log.Warn("[%s] Failed to create SMUX session for conn %d: %v", op, idx, err)
				conn.Close()
				return
			}

			// 2. Open Stream (This becomes our "transport" connection)
			// We use the stream as the carrier for our VPN frames
			stream, err := session.OpenStream()
			if err != nil {
				log.Warn("[%s] Failed to open SMUX stream for conn %d: %v", op, idx, err)
				session.Close()
				return
			}

			mc := &managedConn{
				Conn:      stream, // Wrap the SMUX stream, so all writes/reads go through SMUX
				id:        fmt.Sprintf("pool-%d-%d", start.Unix(), idx),
				createdAt: time.Now(),
				closing:   make(chan struct{}),
			}

			// Handshake (Per Connection)
			handshakeSuccess := true
			if m.handshake != nil && !m.config.EnablePhantom {
				// Perform full handshake if configured
				// ... (Currently simplified reusing Manager's logic, ideally handshake logic should be stateless or per-conn)
				// For now, if Phantom is enabled (default), we SKIP handshake, so this block is skipped.
				// If Handshake IS required, we might need a Lock on m.handshake if it's not concurrent-safe.
				// Assuming m.handshake.InitiateHandshake IS concurrent safe.
				session, err := m.handshake.InitiateHandshake(ctx, mc, conn.RemoteAddr())
				if err != nil {
					log.Warn("[%s] Handshake failed for conn %d: %v", op, idx, err)
					conn.Close()
					handshakeSuccess = false
				} else if session != nil {
					// Reset session ID? Or just keep one. SessionID is informational mostly.
					if idx == 0 {
						m.sessionID = session.ID()
					}
				}
			} else if m.config.EnablePhantom {
				// Phantom: No handshake
				if idx == 0 {
					m.sessionID = uint32(time.Now().Unix() & 0xFFFFFFFF)
				}
			}

			if handshakeSuccess {
				poolMu.Lock()
				connectedPool = append(connectedPool, mc)
				poolMu.Unlock()

				// Start reading immediately
				go m.readLoop(mc)
			}
		}(i)
	}

	// Wait for all dials to complete (with timeout effectively handled by dial(ctx))
	wg.Wait()

	if len(connectedPool) == 0 {
		err := fmt.Errorf("failed to establish any connection in pool")
		if !isRotation {
			m.setError(err)
		}
		return err
	}

	log.Info("[%s] Dialing complete. Pool ready with %d/%d connections (Latency: %v)", op, len(connectedPool), targetPoolSize, time.Since(start))

	// Activate Kill Switch (using IP of the first connection)
	if !isRotation && m.killSwitch != nil && m.config.KillSwitchEnabled {
		m.enableKillSwitch(connectedPool[0].RemoteAddr())
	}

	// Update State
	m.connMu.Lock()
	if isRotation && m.activePool != nil {
		// Move current active pool to draining
		m.drainingConns = append(m.drainingConns, m.activePool...)
		log.Info("[%s] Old pool moved to draining (Total draining: %d)", op, len(m.drainingConns))
		// Schedule cleanup for draining conns
		for _, c := range m.activePool {
			go m.monitorDrainingConn(c)
		}
	}

	m.activePool = connectedPool
	m.activeConn = connectedPool[0] // Set primary for legacy checks
	m.connMu.Unlock()

	// Start mechanics
	if !isRotation {
		// Keepalive: Use the activePool to send PINGs
		m.startKeepalive()

		m.startRotation()
		m.connectedAt = time.Now()
		m.lastPong = time.Now()
		m.setState(StateConnected)

		m.PublishEvent("tunnel.connected", map[string]interface{}{
			"server":     m.config.ServerAddr,
			"session_id": m.sessionID,
			"pool_size":  len(connectedPool),
		})
	} else {
		m.setState(StateConnected)
		m.PublishEvent("tunnel.rotated", map[string]interface{}{
			"id": connectedPool[0].id,
		})
		log.Info("[%s] Rotation complete.", op)
	}

	return nil
}

// dial handles the low level dialing logic with fallbacks
func (m *Manager) dial(ctx context.Context) (net.Conn, error) {
	var conn net.Conn
	var err error

	// Phantom / ASN Bypass
	targetSNI := m.getRotationSNI()
	if m.config.EnablePhantom && m.phantomAuth != nil {
		log.Info("Phantom protocol active - using SNI: %s", targetSNI)
		if m.asnBypassDialer != nil {
			m.asnBypassDialer.SetPhantomConfig(targetSNI, m.phantomAuth)
		}
		if m.obfuscator != nil {
			m.obfuscator.SetRealityKey(m.config.PhantomServerPubKey)
		}
	} else {
		if m.obfuscator != nil {
			m.obfuscator.SetRealityKey("")
		}
	}

	if m.asnBypassDialer != nil && m.config.EnableASNBypass {
		log.Info("Dialing via ASN Bypass...")
		conn, err = m.asnBypassDialer.DialContext(ctx, "tcp4", m.config.ServerAddr)
		if err != nil {
			log.Warn("ASN bypass dial failed: %v", err)
		} else {
			log.Info("ASN bypass connection established")
			// CRITICAL: Apply TCP Buffer Optimizations to ASN Connection
			// Reverted from 12MB to 64KB to fix TCP Retransmission/Fragmentation issues
			// Large buffers can cause Window Scaling issues and buffer bloat in some networks
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				log.Info("[TUNNEL] Applying 20MB buffers to ASN connection (Ultra High Throughput)")
				tcpConn.SetReadBuffer(20 * 1024 * 1024)
				tcpConn.SetWriteBuffer(20 * 1024 * 1024)
				tcpConn.SetNoDelay(true)
			}
			m.isTransportSecure = true
			return conn, nil
		}
	}

	// Fallback Logic
	// 1. QUIC (Reliable UDP) - Replaces Raw UDP
	// Fallback Logic
	// 1. QUIC (Reliable UDP) - Replaces Raw UDP
	// Enable QUIC regardless of Phantom (User request: "Phantom always on" + expecting QUIC traffic)
	// If QUIC succeeds, we use it. If fails, we fall back to TCP (which will use Phantom/ASN Bypass logic if configured, but wait, ASN Bypass is handled BEFORE this block).
	// Actually, `dial` calls ASN Bypass first. If `EnableASNBypass` is true (and likely `EnablePhantom` implies it or wraps it), it returns early.
	// NOTE: If `EnablePhantom` is true, line 542 (ASN Bypass) usually handles it via `asnBypassDialer`.
	// If the user wants QUIC, they might need to DISABLE ASN Bypass or we need to put QUIC BEFORE ASN Bypass or make ASN Bypass support QUIC.
	// However, usually Phantom + ASN Bypass = TCP.
	// If the user sees "no quic in wireshark", it means the code enters ASN Bypass (TCP) and returns.
	// TO FIX: We should try QUIC *before* or *parallel* to TCP?
	// Or maybe the user *thinks* Phantom is enabled but logic falls through?
	// Let's just enable this block.

	log.Info("Connecting via QUIC to %s", m.config.ServerAddr)

	// Force UDP4 address
	udpAddr, resolveErr := net.ResolveUDPAddr("udp4", m.config.ServerAddr)
	if resolveErr == nil {
		targetAddr := udpAddr.String()

		qConfig := &quic_transport.Config{
			ListenAddr:     ":0",
			MaxConns:       1,
			MaxIdleTimeout: m.config.KeepaliveInterval * 3,
		}
		qTrans, err := quic_transport.New(qConfig)
		if err != nil {
			log.Warn("Failed to init QUIC transport: %v", err)
		} else {
			conn, err = qTrans.Dial(ctx, targetAddr)
			if err == nil {
				m.isTransportSecure = true // QUIC is secure
				log.Info("QUIC connection established to %s", targetAddr)
				return conn, nil
			}
			log.Warn("QUIC dial failed: %v", err)
		}
	} else {
		log.Warn("Failed to resolve UDP4 address: %v", resolveErr)
	}

	// 2. TCP Fallback
	if m.config.ServerAddrTCP != "" {
		log.Warn("Falling back to TCP: %s", m.config.ServerAddrTCP)
		conn, err = net.DialTimeout("tcp4", m.config.ServerAddrTCP, 10*time.Second)
		if err == nil {
			// OPTIMIZATION: Use standard buffers to avoid fragmentation/window scaling issues
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetReadBuffer(20 * 1024 * 1024)  // 20MB for high throughput
				tcpConn.SetWriteBuffer(20 * 1024 * 1024) // 20MB
				tcpConn.SetNoDelay(true)                 // Low latency
			}
			m.isTransportSecure = true
			return conn, nil
		}
	}

	return nil, fmt.Errorf("all dial attempts failed")
}

// getCurrentSNI returns the current SNI without triggering rotation
// This is used during dial() to get the current stable SNI
func (m *Manager) getCurrentSNI() string {
	m.connMu.RLock()
	defer m.connMu.RUnlock()

	if m.currentSNI != "" {
		return m.currentSNI
	}
	if m.config.PhantomSNI != "" {
		return m.config.PhantomSNI
	}
	// Fallback: pick first Russian SNI if available
	if len(m.russianSNIs) > 0 {
		return m.russianSNIs[0]
	}
	return ""
}

// selectNewSNI picks a new random SNI (Thread-Safe Wrapper)
func (m *Manager) selectNewSNI() string {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return m.selectNewSNILocked()
}

// selectNewSNILocked performs the actual selection (Caller must hold ConnMu Lock)
func (m *Manager) selectNewSNILocked() string {
	if len(m.russianSNIs) == 0 {
		m.currentSNI = m.config.PhantomSNI
		return m.currentSNI
	}

	// Use crypto/rand for uniform selection
	idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(m.russianSNIs))))
	if err != nil {
		m.currentSNI = m.russianSNIs[0]
	} else {
		m.currentSNI = m.russianSNIs[idxBig.Int64()]
	}
	m.lastRotation = time.Now()

	// Get next rotation interval based on category
	nextInterval := m.getSNIRotationInterval(m.currentSNI)
	log.Info("[ROTATION EVENT] Selected new SNI: %s (Next rotation in %s)", m.currentSNI, nextInterval)

	return m.currentSNI
}

// getRotationSNI returns current SNI for dial(), initializing it if necessary
func (m *Manager) getRotationSNI() string {
	// Fast path with Read Lock
	m.connMu.RLock()
	sni := m.currentSNI
	m.connMu.RUnlock()

	if sni != "" {
		return sni
	}

	// Initialization path with Write Lock (Double-Checked Locking)
	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.currentSNI != "" {
		return m.currentSNI
	}

	return m.selectNewSNILocked()
}

// getSNIRotationInterval returns the rotation duration based on SNI category
// Intervals are designed to mimic realistic user session durations
// INCREASED for stability - less frequent rotations = more stable connections
func (m *Manager) getSNIRotationInterval(sni string) time.Duration {
	if sni == "" {
		return m.config.RotationInterval // Use default from config
	}

	// Marketplaces (Long shopping sessions) -> 1-2 hours
	if strings.Contains(sni, "ozon") ||
		strings.Contains(sni, "wildberries") ||
		strings.Contains(sni, "avito") ||
		strings.Contains(sni, "market") {
		return 60 * time.Minute
	}

	// Search Engines / Portals -> 30 min
	if strings.Contains(sni, "yandex") ||
		strings.Contains(sni, "ya.ru") ||
		strings.Contains(sni, "google") ||
		strings.Contains(sni, "mail.ru") ||
		strings.Contains(sni, "rambler") ||
		strings.Contains(sni, "bing") {
		return 30 * time.Minute
	}

	// Video / Streaming (Long watch sessions) -> 2-3 hours
	if strings.Contains(sni, "rutube") ||
		strings.Contains(sni, "vk.com") ||
		strings.Contains(sni, "vkvideo") ||
		strings.Contains(sni, "kion") ||
		strings.Contains(sni, "premier") ||
		strings.Contains(sni, "twitch") {
		return 120 * time.Minute
	}

	// Social Media -> 45 min
	if strings.Contains(sni, "vk.com") ||
		strings.Contains(sni, "telegram") {
		return 45 * time.Minute
	}

	// Default -> 30 min (stable baseline)
	return 30 * time.Minute
}

// enableKillSwitch configures firewall
func (m *Manager) enableKillSwitch(remoteAddr net.Addr) {
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
		host, portStr, _ := net.SplitHostPort(remoteAddr.String())
		serverIP = net.ParseIP(host)
		fmt.Sscanf(portStr, "%d", &serverPort)
	}

	if serverIP != nil {
		m.killSwitch.SetVPNServer(serverIP, serverPort)
		if err := m.killSwitch.Enable(); err != nil {
			log.Error("Kill Switch enable failed: %v", err)
		}
	}
}

// Disconnect disconnects everything
func (m *Manager) Disconnect() {
	m.stopKeepalive()
	m.stopRotation()

	if m.killSwitch != nil {
		m.killSwitch.Disable()
	}

	m.connMu.Lock()
	// Close Active
	// Close Active Pool
	for _, c := range m.activePool {
		close(c.closing)
		c.Close()
	}
	m.activePool = nil
	m.activeConn = nil
	// Close Draining
	for _, c := range m.drainingConns {
		close(c.closing)
		c.Close()
	}
	m.drainingConns = nil
	m.streamConns = make(map[uint16]*managedConn) // Clear map
	m.connMu.Unlock()

	// Drain readCh? Not strictly necessary as it will just be GC'd or emptied
	// But to be clean:
	// Loop over readCh until empty? No, blocking.

	m.setState(StateDisconnected)
	m.PublishEvent("tunnel.disconnected", nil)
}

// Reconnect performs a hard reconnect
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

		if m.config.MaxReconnectAttempts > 0 && attempts > m.config.MaxReconnectAttempts {
			err := fmt.Errorf("max reconnect attempts exceeded")
			m.setError(err)
			return err
		}

		m.Disconnect()
		err := m.Connect(ctx)
		if err == nil {
			return nil
		}

		time.Sleep(delay)
		delay = time.Duration(float64(delay) * 1.5)
		if delay > m.config.ReconnectMaxDelay {
			delay = m.config.ReconnectMaxDelay
		}
	}
}

// RotateSNI performs a seamless rotation by:
// 1. Selecting a new SNI
// 2. Establishing a new connection with the new SNI
// 3. Moving old connection to draining (it keeps serving existing streams)
// 4. New streams go to the new connection
func (m *Manager) RotateSNI() {
	// Save current SNI in case rotation fails
	oldSNI := m.currentSNI

	// First, select a new SNI before connecting
	newSNI := m.selectNewSNI()
	log.Info("Initiating Seamless SNI Rotation to: %s", newSNI)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.connectInternal(ctx, true); err != nil {
		log.Error("SNI Rotation failed: %v - keeping existing connection", err)

		// Revert to old SNI so subsequent reconnects don't use the failed one
		m.connMu.Lock()
		m.currentSNI = oldSNI
		m.connMu.Unlock()

		return
	}

	log.Info("SNI Rotation complete. Old connections will drain gracefully.")
}

// readLoop reads frames from a specific connection
func (m *Manager) readLoop(mc *managedConn) {
	defer mc.Close()

	// Use bufio.NewReader for Peek capability
	// Increase buffer to 256KB to maximize throughput on high-speed links (500Mbps+)
	var inputReader io.Reader = mc
	// Only apply Obfuscator if transport is NOT secure.
	// If ASN Bypass (TLS) is active, data is already encrypted/decrypted by the transport layer.
	if m.obfuscator != nil && !m.isTransportSecure {
		inputReader = &deobfuscatingReader{r: mc, obf: m.obfuscator}
	}
	reader := bufio.NewReaderSize(inputReader, 262144)

	// Buffer for header
	header := make([]byte, FrameHeaderSize)
	tlsDrainCount := 0      // Counter to prevent infinite TLS drain loop
	consecutiveGarbage := 0 // Counter for consecutive bad packets
	const maxTLSDrain = 50

	// Track deadline updates to reduce syscalls
	lastDeadlineUpdate := time.Now()
	mc.SetReadDeadline(lastDeadlineUpdate.Add(m.config.KeepaliveInterval * 2))

	for {
		select {
		case <-mc.closing:
			return
		default:
		}

		// 1. Check for TLS data using Peek (ONLY for non-secure raw/obfuscated links)
		// TLS Header is 5 bytes. Frame Header is 8 bytes.
		// If we blindly read 8 bytes, we might swallow a short TLS packet (like CCS, 6 bytes)
		// and parts of the next packet, breaking sync.
		//
		// CRITICAL: Disable this check for 'isTransportSecure' (ASN Bypass/TLS).
		// The net.Conn is already a tls.Conn which handles decryption. We receive raw frames.
		// Random data (e.g. StreamID 0x1703) can mimic a TLS header (0x17 0x03), triggering
		// false positives and discarding valid data.
		if !m.isTransportSecure {
			peek, err := reader.Peek(5)
			if err != nil {
				m.handleReadError(mc, err)
				return
			}

			// Check for TLS signature: Type (20-23) + Version (00 xx - 04 xx)
			if tlsDrainCount < maxTLSDrain && peek[0] >= 0x14 && peek[0] <= 0x17 && peek[1] <= 0x04 {
				tlsLen := int(peek[3])<<8 | int(peek[4])
				log.Debug("Detected TLS data (type=0x%02x, ver=0x%02x, len=%d)", peek[0], peek[1], tlsLen)

				// Discard the 5-byte header
				if _, err := reader.Discard(5); err != nil {
					m.handleReadError(mc, err)
					return
				}

				// Handle payload (Unwrap or Drain)
				if tlsLen > 0 {
					isWrappedFrame := false

					// Optimization: If it's Application Data (0x17), it might contain our VPN Frames wrapped
					if peek[0] == 0x17 {
						// Read the full TLS payload to check contents
						buf := make([]byte, tlsLen)
						if _, err := io.ReadFull(reader, buf); err != nil {
							m.handleReadError(mc, err)
							return
						}

						// Recursive check: Handle up to 5 layers of TLS wrapping (Triple+ TLS)
						processBuf := buf
						for layer := 0; layer < 5; layer++ {
							if len(processBuf) >= FrameHeaderSize {
								// Validate as Frame
								pLen := binary.BigEndian.Uint32(processBuf[4:8])
								fType := processBuf[2]

								// Heuristic: Type must be valid (0-10, 0=Padding) and length must be reasonable
								if fType <= 0x0A && int(pLen) <= 65535 && FrameHeaderSize+int(pLen) <= len(processBuf) {
									log.Debug("Unwrapped TLS ApplicationData containing valid Frame (Layer %d, StreamID=%d, Type=%d, Len=%d)",
										layer, binary.BigEndian.Uint16(processBuf[0:2]), fType, pLen)
									isWrappedFrame = true

									// Process frames from processBuf
									offset := 0
									for offset+FrameHeaderSize <= len(processBuf) {
										if offset+FrameHeaderSize > len(processBuf) {
											break
										}

										pLen := binary.BigEndian.Uint32(processBuf[offset+4 : offset+8])
										fType := processBuf[offset+2]
										frameTotal := FrameHeaderSize + int(pLen)

										// Validate subsequent frames in batch
										if fType > 0x0A || offset+frameTotal > len(processBuf) {
											log.Warn("Invalid frame in TLS batch at offset %d (Type=%d, Len=%d)", offset, fType, pLen)
											break
										}

										// Handle Padding/Ping frames (Type 0x00)
										if fType == 0x00 {
											log.Debug("Skipping Padding frame (Len=%d)", pLen)
											offset += frameTotal
											continue
										}

										frameData := make([]byte, frameTotal)
										copy(frameData, processBuf[offset:offset+frameTotal])

										// Update activity immediately as we have received valid data
										// This prevents keepalive timeout if the consumer channel is blocked
										m.UpdateActivity()

										select {
										case m.readCh <- frameData:
											atomic.AddUint64(&m.bytesDown, uint64(len(frameData)))
										case <-mc.closing:
											return
										}

										offset += frameTotal
									}

									tlsDrainCount = 0 // Valid data processed
									break             // Exit layer loop, we are done
								}
							}

							// If not a frame, check if it is nested TLS (e.g. [17][03][03][LenHigh][LenLow]...)
							if len(processBuf) > 5 && processBuf[0] == 0x17 && processBuf[1] == 0x03 {
								innerLen := int(processBuf[3])<<8 | int(processBuf[4])
								if innerLen+5 <= len(processBuf) {
									log.Debug("Detected nested TLS record inside AppData (Layer %d), unwrapping %d bytes...", layer, innerLen)
									processBuf = processBuf[5 : 5+innerLen]
									continue // Try next layer
								}
							}

							break // Not a frame and not nested TLS, give up
						}

						if isWrappedFrame {
							consecutiveGarbage = 0 // Reset garbage counter
							continue               // Check next packet (outer loop)
						}

						// If we reached here, we failed to identify a frame.
						// Log the header for debugging
						if len(buf) > 0 {
							headerPeek := buf
							if len(headerPeek) > 16 {
								headerPeek = headerPeek[:16]
							}
							log.Warn("Failed to unwrap TLS AppData (Len=%d). First 16 bytes: %x", len(buf), headerPeek)
						}
						// If verification failed, we effectively 'drained' it by reading into buf and doing nothing.
					}

					// If not an unwrapped frame (either not 0x17, or 0x17 but garbage), drain it.
					if !isWrappedFrame && peek[0] != 0x17 {
						// Cap drain to avoid huge allocations/reads on bad data if we haven't read it yet
						if tlsLen > 65535 {
							tlsLen = 65535
						}
						if _, err := io.CopyN(io.Discard, reader, int64(tlsLen)); err != nil {
							m.handleReadError(mc, err)
							return
						}
					}

					// Failure tracking
					if !isWrappedFrame {
						consecutiveGarbage++
						if consecutiveGarbage > 20 {
							log.Error("Too much garbage data (%d packets), triggering reconnect", consecutiveGarbage)
							go m.Reconnect(context.Background())
							return
						}
					}
				}

				tlsDrainCount++
				continue // Check next packet
			}

		}
		consecutiveGarbage = 0 // Reset on non-TLS (Frame)
		tlsDrainCount = 0      // Reset on non-TLS (Frame)

		// 2. Read Frame Header (8 bytes)
		// OPTIMIZATION: Lazy Deadline Update
		// Instead of calling syscall SetReadDeadline on every frame (expensive!),
		// only update it periodically (e.g. every 5 seconds).
		if time.Since(lastDeadlineUpdate) > 5*time.Second {
			lastDeadlineUpdate = time.Now()
			mc.SetReadDeadline(lastDeadlineUpdate.Add(m.config.KeepaliveInterval * 2))
		}

		if _, err := io.ReadFull(reader, header); err != nil {
			m.handleReadError(mc, err)
			return
		}
		// fmt.Printf("[DEBUG] Tunnel: Read Header: %x\n", header)

		// 3. Parse Payload Length
		// Format: [StreamID:2][Type:1][Flags:1][Length:4]
		payloadLen := binary.BigEndian.Uint32(header[4:8])

		// Safety check for huge frames (max 128KB payload as per protocol)
		if payloadLen > 131072 {
			log.Warn("Frame too large (%d bytes), header: %x. Attempting RESYNC...", payloadLen, header)

			// Resync Logic: Check if we have a TLS header embedded inside this garbage frame header
			// We scan the bytes we just read (header) for a TLS signature: Type (20-23) + Version (00-04)
			foundOffset := -1
			for i := 1; i <= FrameHeaderSize-3; i++ { // Need at least 3 bytes [Type, VerHigh, VerLow] to check
				if header[i] >= 0x14 && header[i] <= 0x17 && header[i+1] == 0x03 && header[i+2] <= 0x04 {
					foundOffset = i
					break
				}
			}

			if foundOffset != -1 {
				// We found a TLS header starting at offset 'foundOffset' inside 'header'
				log.Warn("RESYNC: Found TLS header signature at offset %d inside invalid frame. Recovering...", foundOffset)

				// Reconstruct the TLS header
				tlsHeader := make([]byte, 5)
				// Bytes available in 'header' starting from foundOffset
				available := FrameHeaderSize - foundOffset
				copy(tlsHeader, header[foundOffset:])

				// If we need more bytes to complete the 5-byte TLS header, read them now
				if available < 5 {
					if _, err := io.ReadFull(reader, tlsHeader[available:]); err != nil {
						m.handleReadError(mc, err)
						return
					}
				} else {
					// We read more than 5 bytes of TLS header? (e.g. found at offset 1, we have 7 bytes)
					// Actually 'header' is 8 bytes. If found at 0, we have 8. If found at 1, we have 7.
					// We only need 5. So we might have extra bytes of TLS Payload in 'header'.
					// But let's keep it simple: We just need to parse length from the first 5 bytes.
				}

				// Parse TLS length
				tlsLen := int(tlsHeader[3])<<8 | int(tlsHeader[4])
				log.Warn("RESYNC: Recovered TLS packet (len=%d). Draining...", tlsLen)

				// Calculate how many payload bytes we ALREADY read into 'header'
				// foundOffset + 5 is where payload starts.
				// Total bytes in 'header' = 8.
				// Bytes of payload in 'header' = 8 - (foundOffset + 5)
				payloadBytesInHeader := FrameHeaderSize - (foundOffset + 5)
				if payloadBytesInHeader < 0 {
					payloadBytesInHeader = 0
				}

				remainingToDrain := tlsLen - payloadBytesInHeader

				if remainingToDrain > 0 {
					// Cap drain
					if remainingToDrain > 65535 {
						remainingToDrain = 65535
					}
					if _, err := io.CopyN(io.Discard, reader, int64(remainingToDrain)); err != nil {
						m.handleReadError(mc, err)
						return
					}
				}

				// Resync successful, continue loop
				tlsDrainCount++
				continue
			} else {
				// If not found in header, maybe we should byte-scan the reader?
				// For now, fail but log nicely.
				log.Error("RESYNC failed: No embedded TLS header found. Closing connection.")
				return
			}
		}

		// 4. Read Payload
		needed := FrameHeaderSize + int(payloadLen)
		// Optimize Memory: Use Buffer Pool
		var frameData []byte
		if needed <= 66048 {
			frameData = bufferPool.Get().([]byte)
			frameData = frameData[:needed]
		} else {
			frameData = make([]byte, needed)
		}

		copy(frameData, header)

		if payloadLen > 0 {
			if _, err := io.ReadFull(reader, frameData[FrameHeaderSize:]); err != nil {
				m.handleReadError(mc, err)
				return
			}
		}

		// 4.5. Handle PONG frames (Type 0x07) - update lastPong time
		if len(frameData) >= 3 && frameData[2] == 0x07 {
			m.lastPong = time.Now()
			log.Debug("Received PONG from server")
			continue // Don't send to readCh, just update timestamp
		}

		// Any valid frame from server counts as activity
		m.lastPong = time.Now()

		// 5. Send atomic frame
		select {
		case m.readCh <- frameData:
			atomic.AddUint64(&m.bytesDown, uint64(len(frameData)))
			m.UpdateActivity()
		case <-mc.closing:
			return
		}
	}
}

func (m *Manager) handleReadError(mc *managedConn, err error) {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return
	}

	m.connMu.RLock()
	isActive := (mc == m.activeConn)
	m.connMu.RUnlock()

	if isActive && m.GetState() == StateConnected {
		log.Warn("Active connection read error: %v. Triggering Reconnect...", err)
		m.lastError = err

		// Check state again to avoid race conditions
		if m.GetState() == StateConnected {
			go m.Reconnect(context.Background())
		}
	}
}

// Receive receives data from the tunnel (multiplexed)
func (m *Manager) Receive(buf []byte) (int, error) {
	// Deobfuscation is tricky with multiple connections if Obfuscator is stateful.
	// Assuming Stateless/TLS for now as discussed.

	packet, ok := <-m.readCh
	if !ok {
		return 0, fmt.Errorf("tunnel closed")
	}

	if len(packet) > len(buf) {
		log.Error("Receive buffer too small for packet (%d > %d)", len(packet), len(buf))
		if cap(packet) == 66048 {
			bufferPool.Put(packet)
		}
		return 0, fmt.Errorf("buffer too small")
	}

	copy(buf, packet) // Raw encrypted/obfuscated data?

	// Return buffer to pool
	if cap(packet) == 66048 {
		bufferPool.Put(packet)
	}

	n := len(packet)
	// Deobfuscation is handled in readLoop via deobfuscatingReader
	return n, nil
}

// ReceivePacket returns a packet directly from the channel (Zero Copy)
// Caller MUST call Recycle(packet) when done.
func (m *Manager) ReceivePacket() ([]byte, error) {
	packet, ok := <-m.readCh
	if !ok {
		return nil, fmt.Errorf("tunnel closed")
	}
	return packet, nil
}

// Recycle indicates that the buffer is no longer needed.
// With pool disabled, this is a no-op (let GC handle it).
func (m *Manager) Recycle(buf []byte) {
	// bufferPool.Put(buf)
}

// Send sends data through the tunnel
func (m *Manager) Send(data []byte) error {
	// Route to correct connection
	// Parse Frame Header to get StreamID and Type
	var streamID uint16
	var frameType uint8

	if len(data) >= 8 {
		streamID = binary.BigEndian.Uint16(data[0:2])
		frameType = data[2]
	}

	if m.obfuscator != nil && !m.isTransportSecure {
		obfuscated, delay, err := m.obfuscator.Process(data, interfaces.DirectionOutbound)
		if err != nil {
			return fmt.Errorf("outbound obfuscation failed: %w", err)
		}
		if obfuscated != nil {
			data = obfuscated
		}
		// OPTIMIZATION: Skip delay for DATA frames to maximize throughput
		// Jitter is only needed for handshake/control frames to defeat traffic analysis
		if delay > 0 && delay < 5*time.Second {
			if frameType != 0x04 && frameType != 0x08 && frameType != 0x09 { // Skip for DATA, UDP_DATA, RAW_PACKET
				time.Sleep(delay)
			}
		}
	}

	// Retry loop for reconnect scenarios
	const maxRetries = 10
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		targetConn := m.activeConn

		if len(data) >= 8 {
			m.connMu.Lock()
			if frameType == FrameTypeConnect {
				// New Stream: Assign to a connection in the pool (Hashing by StreamID)
				if len(m.activePool) > 0 {
					idx := streamID % uint16(len(m.activePool))
					selectedConn := m.activePool[idx]
					m.streamConns[streamID] = selectedConn
					targetConn = selectedConn

					// Fallback if selected is nil (should not happen in valid pool)
					if targetConn == nil {
						targetConn = m.activeConn
					}
				} else if m.activeConn != nil {
					m.streamConns[streamID] = m.activeConn
					targetConn = m.activeConn
				}
			} else {
				if c, ok := m.streamConns[streamID]; ok {
					targetConn = c
				}
				if frameType == FrameTypeClose {
					delete(m.streamConns, streamID)
				}
			}
			m.connMu.Unlock()
		}

		m.connMu.RLock()
		if targetConn == nil {
			m.connMu.RUnlock()

			// If reconnecting, wait and retry
			state := m.GetState()
			if state == StateReconnecting || state == StateRotating || state == StateConnecting {
				log.Debug("Send: waiting for reconnect (attempt %d/%d)", attempt+1, maxRetries)
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return fmt.Errorf("not connected")
		}
		conn := targetConn
		m.connMu.RUnlock()

		n, err := conn.Write(data)
		if err != nil {
			lastErr = err

			// Check if it's a "use of closed network connection" error
			// Also handle "connection reset" and "EOF" which imply connection death
			errMsg := err.Error()
			isClosed := strings.Contains(errMsg, "closed") || strings.Contains(errMsg, "broken pipe") || strings.Contains(errMsg, "connection reset") || strings.Contains(errMsg, "EOF")

			if isClosed {
				state := m.GetState()

				// If we encounter a closed connection while supposedly Connected, trigger Reconnect immediately
				if state == StateConnected {
					// Only trigger if this was the active connection (or we can't tell)
					// handleReadError checks if it's activeConn
					log.Warn("Send: connection unexpectedly closed/reset. Triggering Reconnect... (Err: %v)", err)
					m.handleReadError(conn, err)
				}

				// Wait and retry if we are (now) reconnecting
				// We check state again because handleReadError might have changed it
				state = m.GetState()
				if state == StateReconnecting || state == StateRotating || state == StateConnecting {
					log.Debug("Send: connection closed during reconnect (attempt %d/%d). Waiting...", attempt+1, maxRetries)
					time.Sleep(500 * time.Millisecond)
					continue
				}
			}
			return err
		}

		atomic.AddUint64(&m.bytesUp, uint64(n))
		m.UpdateActivity()
		return nil
	}

	return fmt.Errorf("send failed after %d retries: %w", maxRetries, lastErr)
}

// monitorDrainingConn waits and closes old connection
func (m *Manager) monitorDrainingConn(mc *managedConn) {
	time.Sleep(m.config.DrainingTimeout)

	m.connMu.Lock()
	defer m.connMu.Unlock()

	// Remove from list
	for i, c := range m.drainingConns {
		if c == mc {
			m.drainingConns = append(m.drainingConns[:i], m.drainingConns[i+1:]...)
			break
		}
	}

	close(mc.closing)
	mc.Close()
	log.Info("Draining connection closed (Timeout)")
}

// startRotation starts the rotation ticker with dynamic interval based on current SNI
func (m *Manager) startRotation() {
	m.stopRotation()
	if !m.config.EnableRotation {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.rotationCancel = cancel

	// Initial interval from current SNI category, or default
	initialInterval := m.getSNIRotationInterval(m.currentSNI)
	if initialInterval < m.config.RotationInterval {
		initialInterval = m.config.RotationInterval
	}

	log.Info("Starting SNI rotation timer (initial interval: %s)", initialInterval)
	m.rotationTicker = time.NewTicker(initialInterval)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.rotationTicker.C:
				m.RotateSNI()

				// Update ticker interval based on new SNI category
				newInterval := m.getSNIRotationInterval(m.currentSNI)
				if newInterval < m.config.RotationInterval {
					newInterval = m.config.RotationInterval
				}
				m.rotationTicker.Reset(newInterval)
				log.Debug("Next rotation in %s", newInterval)
			}
		}
	}()
}

// stopRotation stops the rotation ticker
func (m *Manager) stopRotation() {
	if m.rotationCancel != nil {
		m.rotationCancel()
	}
	if m.rotationTicker != nil {
		m.rotationTicker.Stop()
	}
}

// GetState returns the current tunnel state
func (m *Manager) GetState() TunnelState {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.state
}

// IsConnected returns true if connected
func (m *Manager) IsConnected() bool {
	s := m.GetState()
	return s == StateConnected || s == StateRotating
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

	// Send immediate keepalive to kick off communication with server
	// Server is waiting for first frame after authentication
	m.sendKeepalive()

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
	}
	if m.keepaliveTicker != nil {
		m.keepaliveTicker.Stop()
	}
}

// sendKeepalive sends a keepalive packet (proper PING frame)
func (m *Manager) sendKeepalive() {
	// Check connection health - if no data received in 60 seconds, reconnect
	// This is more lenient than checking just for PONG, since any server response proves liveness
	if !m.lastPong.IsZero() && m.GetState() == StateConnected {
		silentDuration := time.Since(m.lastPong)
		maxSilence := 60 * time.Second // INCREASED: 60 seconds is more reasonable for real-world conditions
		if silentDuration > maxSilence {
			log.Warn("No data received in %s (max %s), triggering reconnect", silentDuration, maxSilence)
			go m.Reconnect(context.Background())
			return
		}
	}

	// Build proper PING frame: [StreamID:2][Type:1][Flags:1][Length:4]
	// StreamID=0 (control channel), Type=0x06 (PING), Flags=0, PayloadLen=0
	pingFrame := make([]byte, 8)
	// pingFrame[0], pingFrame[1] = 0, 0 (StreamID = 0)
	pingFrame[2] = 0x06 // FramePing
	// pingFrame[3] = 0 (Flags)
	// pingFrame[4:8] = 0 (PayloadLen = 0)

	if err := m.Send(pingFrame); err != nil {
		log.Warn("Keepalive send failed: %v", err)
	} else {
		m.lastKeepalive = time.Now()
	}
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
	status.Details["active_streams"] = len(m.streamConns)
	m.connMu.RLock()
	status.Details["draining_conns"] = len(m.drainingConns)
	m.connMu.RUnlock()
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
		result[i] = chars[int(time.Now().UnixNano()/int64(i+1))%len(chars)]
	}
	return string(result)
}
