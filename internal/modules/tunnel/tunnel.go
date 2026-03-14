package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"runtime/debug"
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
	"whispera/internal/modules/transport/domainfront"
	h2c_transport "whispera/internal/modules/transport/h2c"
	"whispera/internal/modules/transport/httpupgrade"
	"whispera/internal/modules/transport/meek"
	"whispera/internal/modules/transport/okwebrtc"
	quic_transport "whispera/internal/modules/transport/quic"
	"whispera/internal/modules/transport/shadowsocks"
	shadowtls_transport "whispera/internal/modules/transport/shadowtls"
	splithttp_transport "whispera/internal/modules/transport/splithttp"
	"whispera/internal/modules/transport/tgbot"
	"whispera/internal/modules/transport/torsocks"
	tuic_transport "whispera/internal/modules/transport/tuic"
	"whispera/internal/modules/transport/vkbot"
	"whispera/internal/modules/transport/vkwebrtc"
	ws_transport "whispera/internal/modules/transport/websocket"
	"whispera/internal/modules/transport/yacloud"
	"whispera/internal/modules/transport/yadisk"
	"whispera/internal/modules/transport/yatelemost"
	"whispera/internal/mux"
	"whispera/internal/obfuscation/russian"
	"nhooyr.io/websocket"
)

var log = logger.Module("tunnel")

func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC in %s: %v\n%s", name, r, debug.Stack())
			}
		}()
		fn()
	}()
}

func (m *Manager) safeGoLimited(name string, fn func()) bool {
	wrapped := func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC in %s: %v\n%s", name, r, debug.Stack())
			}
		}()
		fn()
	}
	if m.goroutineLimiter != nil {
		if !m.goroutineLimiter.Go(wrapped) {
			log.Warn("goroutine limit reached, dropping %s", name)
			return false
		}
		return true
	}
	go wrapped()
	return true
}

const (
	ModuleName    = "tunnel.manager"
	ModuleVersion = "1.0.0"

	FrameHeaderSize  = 8
	FrameTypeConnect = 0x01
	FrameTypeData    = 0x04
	FrameTypeClose   = 0x05
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 66048)
	},
}

type TunnelState int

const (
	StateDisconnected TunnelState = iota
	StateConnecting
	StateConnected
	StateReconnecting
	StateRotating
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

type Config struct {
	ServerAddr           string
	ServerAddrTCP        string
	Transport            string
	KeepaliveInterval    time.Duration
	ReconnectInterval    time.Duration
	ReconnectMaxDelay    time.Duration
	MaxReconnectAttempts int
	ConnectionTimeout    time.Duration
	EnableRotation       bool
	RotationInterval     time.Duration
	DrainingTimeout      time.Duration
	KillSwitchEnabled    bool
	KillSwitchAllowLAN   bool
	KillSwitchAllowDNS   bool

	EnableASNBypass    bool
	ASNBypassStrategy  asnbypass.Strategy
	TLSFingerprint     string
	DomainFrontHost    string
	ResidentialProxies []string
	EnableJA3Randomize bool

	EnablePhantom       bool
	PhantomSNI          string
	PhantomShortId      string
	PhantomServerPubKey string
	PhantomPSK          []byte

	RussianService    string
	BehavioralProfile string

	VKToken   string
	VKGroupID int64

	VKBotUserToken  string
	VKBotGroupToken string

	TGBotToken    string
	TGGroupChatID int64
	TGSessionID   string

	CDNWorkerURL string

	ServerList []string

	RekeyInterval time.Duration

	TransportConfig map[string]interface{}

	// CustomDialFn overrides the default transport dial when set.
	// Used for multi-hop: dial the next hop through an existing tunnel stream.
	CustomDialFn func(ctx context.Context) (net.Conn, error)
}

func DefaultConfig() *Config {
	return &Config{
		KeepaliveInterval:    15 * time.Second,
		ReconnectInterval:    5 * time.Second,
		ReconnectMaxDelay:    60 * time.Second,
		MaxReconnectAttempts: 0,
		ConnectionTimeout:    30 * time.Second,
		EnableRotation:       true,
		RotationInterval:     60 * time.Minute,
		DrainingTimeout:      90 * time.Minute,
	}
}

func (c *Config) Validate() error {

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

type managedConn struct {
	net.Conn
	session   *mux.Session
	id        string
	createdAt time.Time
	closing   chan struct{}
}

type Manager struct {
	*base.Module
	config *Config

	state         TunnelState
	stateMu       sync.RWMutex
	lastError     error
	activeConn    *managedConn
	activePool    []*managedConn
	drainingConns []*managedConn
	streamConns   map[uint16]*managedConn
	readCh        chan []byte

	streamChs   map[uint16]chan []byte
	streamChsMu sync.RWMutex

	connMu    sync.RWMutex
	sessionID uint32

	tunDevice interfaces.TUNDevice
	handshake interfaces.HandshakeHandler
	dataPlane interfaces.DataPlane
	crypto    interfaces.CryptoProvider

	keepaliveTicker *time.Ticker
	keepaliveCancel context.CancelFunc
	rotationTicker  *time.Ticker
	rotationCancel  context.CancelFunc
	rekeyTicker     *time.Ticker
	rekeyCancel     context.CancelFunc

	streamIdx         uint32
	reconnectAttempts uint32
	bytesUp           uint64
	bytesDown         uint64
	lastKeepalive     time.Time
	lastPong          time.Time
	connectedAt       time.Time

	onStateChange func(TunnelState)

	killSwitch *killswitch.KillSwitch

	obfuscator        interfaces.Obfuscator
	asnBypassDialer   *asnbypass.Dialer
	phantomAuth       *phantom.ClientAuth
	isTransportSecure bool

	russianSNIs  []string
	currentSNI   string
	lastRotation time.Time

	russianTunneler *russian.RussianTunneler

	cbMu          sync.Mutex
	cbFailures    int
	cbLastFailure time.Time
	cbState       string

	goroutineLimiter *base.GoroutineLimiter
}

func (m *Manager) getMuxConfig() *mux.Config {
	return &mux.Config{
		MaxFrameSize:         65535,
		MaxReceiveBuffer:     512 * 1024 * 1024,
		MaxStreamBuffer:      4 * 1024 * 1024,
		KeepAliveInterval:    10 * time.Second,
		KeepAliveTimeout:     60 * time.Second,
		MaxConcurrentStreams: 256,
	}
}

func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	m := &Manager{
		Module:           base.NewModule(ModuleName, ModuleVersion, []string{"handshake.handler"}),
		config:           cfg,
		state:            StateDisconnected,
		streamConns:      make(map[uint16]*managedConn),
		readCh:           make(chan []byte, 4096),
		streamChs:        make(map[uint16]chan []byte),
		goroutineLimiter: base.NewGoroutineLimiter(1024),
	}

	if cfg.EnableASNBypass || cfg.EnablePhantom {
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
			EnableJA3Randomization:  cfg.EnableJA3Randomize,
			EnableTLSFragmentation: true,
			TLSFragmentSize:        40,
			ConnectionBurstLimit:    5,
			ConnectionCooldown:      2 * time.Second,
			FailoverTimeout:        cfg.ConnectionTimeout,
			FallbackStrategies:     []asnbypass.Strategy{asnbypass.StrategyTLSMasquerade, asnbypass.StrategyDomainFronting},
		}

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

	if cfg.EnablePhantom {
		shortId := cfg.PhantomShortId
		if shortId == "" {
			shortId = generateRandomShortId()
			log.Info("Phantom: Auto-generated shortId: %s", shortId)
		}

		m.phantomAuth = phantom.NewClientAuth(&phantom.ClientConfig{
			ServerPublicKey: cfg.PhantomServerPubKey,
			ShortId:         shortId,
			PrivateKey:      cfg.PhantomPSK,
		})

		if m.asnBypassDialer != nil {
			m.asnBypassDialer.SetPhantomAuth(m.phantomAuth)
		}

		log.Info("Phantom protocol enabled (SNI: %s)", cfg.PhantomSNI)
	}

	rt := russian.NewRussianTunneler()
	m.russianTunneler = rt
	if cfg.RussianService != "" {
		if err := rt.SetActiveService(cfg.RussianService); err != nil {
			log.Warn("Failed to set active Russian service %s: %v", cfg.RussianService, err)
		} else {
			log.Info("Active Russian Service: %s", cfg.RussianService)
		}
	}

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

func (m *Manager) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := m.Module.Init(ctx, cfg); err != nil {
		return err
	}
	if tunnelCfg, ok := cfg.(*Config); ok {
		m.config = tunnelCfg
		if m.config.VKToken != "" || m.config.Transport == "vk" {
			log.Info("VK Transport detected: Disabling SNI Rotation (incompatible)")
			m.config.EnableRotation = false
		}
	}
	return nil
}

func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}
	m.SetHealthy(true, "tunnel manager running")
	m.PublishEvent(events.EventTypeModuleStarted, nil)
	log.Info("[TUNNEL] Starting Tunnel Manager (Build: Zero-Copy Final v3)...")

	safeGo("Reconnect", func() { m.Reconnect(context.Background()) })

	return nil
}

func (m *Manager) Stop() error {
	m.stopRotation()
	m.stopRekey()
	m.Disconnect()
	m.PublishEvent(events.EventTypeModuleStopped, nil)
	return m.Module.Stop()
}

func (m *Manager) PreWarm() {
	log.Info("[TUNNEL] Pre-warming connection in background...")
	safeGo("PreWarm", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := m.Connect(ctx); err != nil {
			log.Warn("[TUNNEL] Pre-warm failed: %v (will retry on explicit connect)", err)
		} else {
			log.Info("[TUNNEL] Pre-warm successful - connection ready for instant use")
		}
	})
}

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

func (m *Manager) SetObfuscator(o interfaces.Obfuscator) {
	m.obfuscator = o
	if o != nil {
		log.Info("Obfuscation enabled for tunnel traffic")
	}
}

func (m *Manager) Connect(ctx context.Context) error {
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

	m.Disconnect()

	if len(m.config.ServerList) > 0 {
		if best := m.pickFastestServer(ctx); best != "" {
			m.config.ServerAddrTCP = best
			m.config.ServerAddr = best
		}
	}

	return m.connectInternal(ctx, false)
}

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

	targetPoolSize := 4
	var connectedPool []*managedConn
	var poolMu sync.Mutex

	firstConnReady := make(chan *managedConn, 1)
	firstConnErr := make(chan error, targetPoolSize)

	log.Info("[%s] Spawning pool of %d connections (lazy mode)...", op, targetPoolSize)

	spawnConnection := func(idx int) {
		conn, err := m.dial(ctx)
		if err != nil {
			log.Warn("[%s] Failed to dial connection %d: %v", op, idx, err)
			select {
			case firstConnErr <- err:
			default:
			}
			return
		}

		if m.handshake != nil && !m.config.EnablePhantom {
			session, err := m.handshake.InitiateHandshake(ctx, conn, conn.RemoteAddr())
			if err != nil {
				log.Warn("[%s] Handshake failed for conn %d: %v", op, idx, err)
				conn.Close()
				select {
				case firstConnErr <- err:
				default:
				}
				return
			}
			if session != nil {
				poolMu.Lock()
				if len(connectedPool) == 0 {
					m.sessionID = session.ID()
				}
				poolMu.Unlock()
			}
		} else if m.config.EnablePhantom {
			poolMu.Lock()
			if len(connectedPool) == 0 {
				m.sessionID = uint32(time.Now().Unix() & 0xFFFFFFFF)
			}
			poolMu.Unlock()
		}

		log.Debug("[%s] Upgrading connection %d to SMUX...", op, idx)

		muxCfg := m.getMuxConfig()
		muxSess, err := mux.Client(conn, muxCfg)
		if err != nil {
			log.Warn("[%s] Failed to create SMUX session for conn %d: %v", op, idx, err)
			conn.Close()
			select {
			case firstConnErr <- err:
			default:
			}
			return
		}

		stream, err := muxSess.OpenStream()
		if err != nil {
			log.Warn("[%s] Failed to open SMUX stream for conn %d: %v", op, idx, err)
			muxSess.Close()
			select {
			case firstConnErr <- err:
			default:
			}
			return
		}

		mc := &managedConn{
			Conn:      stream,
			session:   muxSess,
			id:        fmt.Sprintf("pool-%d-%d", start.Unix(), idx),
			createdAt: time.Now(),
			closing:   make(chan struct{}),
		}

		poolMu.Lock()
		isFirst := len(connectedPool) == 0
		connectedPool = append(connectedPool, mc)
		poolMu.Unlock()

		safeGo("readLoop", func() { m.readLoop(mc) })

		if isFirst {
			select {
			case firstConnReady <- mc:
				log.Info("[%s] First connection ready! (Latency: %v)", op, time.Since(start))
			default:
			}
		}
	}

	go spawnConnection(0)

	var firstConn *managedConn
	errCount := 0
	timeout := time.After(m.config.ConnectionTimeout)

	select {
	case firstConn = <-firstConnReady:
		for i := 1; i < targetPoolSize; i++ {
			go spawnConnection(i)
		}
	case <-timeout:
		err := fmt.Errorf("connection timeout after %v", m.config.ConnectionTimeout)
		if !isRotation {
			m.setError(err)
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		poolMu.Lock()
		count := len(connectedPool)
		poolMu.Unlock()
		log.Info("[%s] Background pool status: %d/%d connections after 500ms", op, count, targetPoolSize)
	}()

	if firstConn == nil {
		for i := 0; i < targetPoolSize; i++ {
			select {
			case <-firstConnErr:
				errCount++
			default:
			}
		}
		if errCount == targetPoolSize {
			err := fmt.Errorf("failed to establish any connection in pool")
			if !isRotation {
				m.setError(err)
			}
			return err
		}
	}

	log.Info("[%s] Lazy connect complete. First connection ready in %v", op, time.Since(start))

	if m.killSwitch != nil && m.config.KillSwitchEnabled {
		m.enableKillSwitch(connectedPool[0].RemoteAddr())
	}

	m.connMu.Lock()
	if isRotation && m.activePool != nil {
		m.drainingConns = append(m.drainingConns, m.activePool...)
		log.Info("[%s] Old pool moved to draining (Total draining: %d)", op, len(m.drainingConns))
		for _, c := range m.activePool {
			go m.monitorDrainingConn(c)
		}
	}

	m.activePool = connectedPool
	m.activeConn = connectedPool[0]
	m.connMu.Unlock()

	if !isRotation {
		m.startKeepalive()
		m.startRotation()
		m.startRekey()
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

type dialCandidate struct {
	name   string
	secure bool
	fn     func(context.Context) (net.Conn, error)
}

func (m *Manager) dial(ctx context.Context) (net.Conn, error) {
	if m.config.CustomDialFn != nil {
		return m.config.CustomDialFn(ctx)
	}
	m.preparePhantomASN()
	candidates := m.buildCandidates()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no transport candidates configured")
	}
	return m.parallelDial(ctx, candidates)
}

func (m *Manager) preparePhantomASN() {
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
}

func (m *Manager) tcfg(key string) string {
	if m.config.TransportConfig == nil {
		return ""
	}
	if v, ok := m.config.TransportConfig[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (m *Manager) buildCandidates() []dialCandidate {
	var cc []dialCandidate
	t := m.config.Transport
	tc := m.config.TransportConfig
	auto := t == "auto" || t == ""

	var explicit map[string]bool
	if !auto && strings.Contains(t, ",") {
		explicit = make(map[string]bool)
		for _, part := range strings.Split(t, ",") {
			explicit[strings.TrimSpace(part)] = true
		}
	}

	only := func(name string) bool {
		if auto {
			return true
		}
		if explicit != nil {
			return explicit[name]
		}
		return t == name
	}

	if only("vkwebrtc") && m.config.VKToken != "" {
		cc = append(cc, dialCandidate{"vkwebrtc", true, m.dialVKWebRTC})
	}
	if only("okwebrtc") && m.tcfg("ok_token") != "" {
		cc = append(cc, dialCandidate{"okwebrtc", true, m.dialOKWebRTC})
	}
	if only("yatelemost") && m.tcfg("session_id") != "" && m.tcfg("conference_url") != "" {
		cc = append(cc, dialCandidate{"yatelemost", true, m.dialYaTelemost})
	}
	if only("yadisk") && m.tcfg("token") != "" {
		cc = append(cc, dialCandidate{"yadisk", true, m.dialYaDisk})
	}
	if only("yacloud") && m.tcfg("gateway_url") != "" {
		cc = append(cc, dialCandidate{"yacloud", true, m.dialYaCloud})
	}
	if only("vkbot") && m.config.VKBotUserToken != "" && m.config.VKGroupID != 0 {
		cc = append(cc, dialCandidate{"vkbot", true, m.dialVKBot})
	}
	if only("tgbot") && m.config.TGBotToken != "" && m.config.TGGroupChatID != 0 {
		cc = append(cc, dialCandidate{"tgbot", true, m.dialTGBot})
	}
	if only("cdnworker") && m.config.CDNWorkerURL != "" {
		cc = append(cc, dialCandidate{"cdnworker", true, m.dialCDNWorker})
	}
	_ = tc

	if t == "meek" && m.tcfg("url") != "" {
		cc = append(cc, dialCandidate{"meek", true, m.dialMeek})
	}
	if t == "torsocks" {
		cc = append(cc, dialCandidate{"torsocks", true, m.dialTorSOCKS})
	}
	if t == "domainfront" && m.tcfg("front_domain") != "" {
		cc = append(cc, dialCandidate{"domainfront", true, m.dialDomainFront})
	}

	circumvention := !auto && explicit == nil && (t == "meek" || t == "torsocks" || t == "domainfront")
	if m.russianTunneler != nil && !circumvention {
		svc := m.config.RussianService
		if svc == "" && auto {
			services := m.russianTunneler.GetAvailableServices()
			if len(services) > 0 {
				n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(services))))
				svc = services[n.Int64()]
				m.russianTunneler.SetActiveService(svc)
			}
		}
		if svc != "" {
			cc = append(cc, dialCandidate{"russian:" + svc, true, m.dialRussian})
		}
	}

	if m.asnBypassDialer != nil && (m.config.EnableASNBypass || m.config.EnablePhantom) {
		cc = append(cc, dialCandidate{"asn_bypass", true, m.dialASNBypass})
	}

	if t == "shadowtls" && m.tcfg("password") != "" && m.config.ServerAddrTCP != "" {
		cc = append(cc, dialCandidate{"shadowtls", true, m.dialShadowTLS})
	}
	if t == "shadowsocks" && m.tcfg("password") != "" && m.config.ServerAddrTCP != "" {
		cc = append(cc, dialCandidate{"shadowsocks", true, m.dialShadowsocks})
	}

	if only("tuic") {
		cc = append(cc, dialCandidate{"tuic", true, m.dialTUIC})
	}
	if only("quic") || (auto && t != "tuic") {
		cc = append(cc, dialCandidate{"quic", true, m.dialQUIC})
	}
	if m.config.ServerAddrTCP != "" {
		if only("ws") || only("websocket") {
			cc = append(cc, dialCandidate{"websocket", false, m.dialWebSocket})
		}
		if only("httpupgrade") {
			cc = append(cc, dialCandidate{"httpupgrade", false, m.dialHTTPUpgrade})
		}
		if only("splithttp") {
			cc = append(cc, dialCandidate{"splithttp", false, m.dialSplitHTTP})
		}
		if only("h2c") || auto {
			cc = append(cc, dialCandidate{"h2c", false, m.dialH2C})
		}
		if only("tcp") || auto {
			cc = append(cc, dialCandidate{"tcp", true, m.dialTCP})
		}
	}

	return cc
}

func (m *Manager) parallelDial(ctx context.Context, candidates []dialCandidate) (net.Conn, error) {
	if len(candidates) == 1 {
		conn, err := candidates[0].fn(ctx)
		if err == nil {
			m.isTransportSecure = candidates[0].secure
		}
		return conn, err
	}

	type result struct {
		conn   net.Conn
		secure bool
		name   string
		err    error
	}

	ch := make(chan result, len(candidates))
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	names := make([]string, len(candidates))
	for i, c := range candidates {
		names[i] = c.name
		c := c
		go func() {
			conn, err := c.fn(ctx2)
			ch <- result{conn, c.secure, c.name, err}
		}()
	}
	log.Info("[dial] racing %d transports: %s", len(candidates), strings.Join(names, ", "))

	var winner result
	var errs []string

	for range candidates {
		res := <-ch
		switch {
		case res.err == nil && winner.conn == nil:
			winner = res
			cancel()
			log.Info("[dial] %s won the race", res.name)
		case res.err == nil && res.conn != nil:
			res.conn.Close()
		case res.err != nil && res.err != context.Canceled && res.err.Error() != "context canceled":
			errs = append(errs, res.name+": "+res.err.Error())
		}
	}

	if winner.conn != nil {
		m.isTransportSecure = winner.secure
		return winner.conn, nil
	}
	return nil, fmt.Errorf("all transports failed: %s", strings.Join(errs, "; "))
}


func (m *Manager) dialVKWebRTC(ctx context.Context) (net.Conn, error) {
	vkCfg := &vkwebrtc.Config{
		VKToken:       m.config.VKToken,
		VKGroupID:     m.config.VKGroupID,
		ServerMode:    false,
		SignalingMode: "vk",
		ICEPolicy:     "relay",
	}
	tr, err := vkwebrtc.New(vkCfg)
	if err != nil {
		return nil, err
	}
	if err := tr.Start(); err != nil {
		return nil, err
	}
	conn, err := tr.Dial(ctx, m.config.ServerAddr)
	if err != nil {
		tr.Stop()
		return nil, err
	}
	return conn, nil
}

func (m *Manager) dialVKBot(ctx context.Context) (net.Conn, error) {
	tr, err := vkbot.New(&vkbot.Config{
		GroupID:    m.config.VKGroupID,
		UserToken:  m.config.VKBotUserToken,
		ServerMode: false,
	})
	if err != nil {
		return nil, err
	}
	if err := tr.Start(); err != nil {
		return nil, err
	}
	conn, err := tr.Dial(ctx, m.config.ServerAddr)
	if err != nil {
		tr.Stop()
		return nil, err
	}
	return conn, nil
}

func (m *Manager) dialTGBot(ctx context.Context) (net.Conn, error) {
	tr, err := tgbot.New(&tgbot.Config{
		MyBotToken:  m.config.TGBotToken,
		GroupChatID: m.config.TGGroupChatID,
		SessionID:   m.config.TGSessionID,
		ServerMode:  false,
	})
	if err != nil {
		return nil, err
	}
	if err := tr.Start(); err != nil {
		return nil, err
	}
	conn, err := tr.Dial(ctx, m.config.ServerAddr)
	if err != nil {
		tr.Stop()
		return nil, err
	}
	return conn, nil
}

func (m *Manager) dialCDNWorker(ctx context.Context) (net.Conn, error) {
	wsConn, _, err := websocket.Dial(ctx, m.config.CDNWorkerURL, &websocket.DialOptions{
		Subprotocols: []string{"whispera"},
	})
	if err != nil {
		return nil, fmt.Errorf("cdnworker: %w", err)
	}
	return websocket.NetConn(ctx, wsConn, websocket.MessageBinary), nil
}

func (m *Manager) dialRussian(ctx context.Context) (net.Conn, error) {
	st, err := m.russianTunneler.CreateTunnel(ctx, m.config.ServerAddr)
	if err != nil {
		return nil, err
	}
	return NewRussianConnAdapter(st), nil
}

func (m *Manager) dialASNBypass(ctx context.Context) (net.Conn, error) {
	conn, err := m.asnBypassDialer.DialContext(ctx, "tcp4", m.config.ServerAddr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}
	return conn, nil
}

func (m *Manager) dialQUIC(ctx context.Context) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", m.config.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("quic resolve: %w", err)
	}
	qTrans, err := quic_transport.New(&quic_transport.Config{
		ListenAddr:     ":0",
		MaxConns:       1,
		MaxIdleTimeout: m.config.KeepaliveInterval * 3,
	})
	if err != nil {
		return nil, err
	}
	return qTrans.Dial(ctx, udpAddr.String())
}

func (m *Manager) dialH2C(ctx context.Context) (net.Conn, error) {
	h2cTrans, err := h2c_transport.New(&h2c_transport.Config{
		ListenAddr: ":0",
		Path:       "/",
	})
	if err != nil {
		return nil, err
	}
	return h2cTrans.Dial(ctx, m.config.ServerAddrTCP)
}

func (m *Manager) dialTCP(ctx context.Context) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", m.config.ServerAddrTCP, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}
	return conn, nil
}

func (m *Manager) dialSplitHTTP(ctx context.Context) (net.Conn, error) {
	baseURL := "http://" + m.config.ServerAddrTCP
	tr, err := splithttp_transport.New(&splithttp_transport.Config{
		BaseURL: baseURL,
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddrTCP)
}

func (m *Manager) dialTUIC(ctx context.Context) (net.Conn, error) {
	tr, err := tuic_transport.New(&tuic_transport.Config{
		ServerAddr: m.config.ServerAddr,
		SNI:        m.config.PhantomSNI,
		UUID:              "00000000000000000000000000000000",
		CongestionControl: "bbr",
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialWebSocket(ctx context.Context) (net.Conn, error) {
	tr, err := ws_transport.New(&ws_transport.Config{
		ListenAddr: ":0",
		Path:       "/ws",
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddrTCP)
}

func (m *Manager) dialHTTPUpgrade(ctx context.Context) (net.Conn, error) {
	tr, err := httpupgrade.New(&httpupgrade.Config{
		Path: "/",
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddrTCP)
}

func (m *Manager) dialShadowTLS(ctx context.Context) (net.Conn, error) {
	tr, err := shadowtls_transport.New(&shadowtls_transport.Config{
		Password:     m.tcfg("password"),
		ShadowServer: m.config.ServerAddrTCP,
		SNI:          m.tcfg("sni"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddrTCP)
}

func (m *Manager) dialShadowsocks(ctx context.Context) (net.Conn, error) {
	method := m.tcfg("method")
	if method == "" {
		method = "aes-256-gcm"
	}
	tr, err := shadowsocks.New(&shadowsocks.Config{
		Password: m.tcfg("password"),
		Method:   shadowsocks.Method(method),
		Server:   m.config.ServerAddrTCP,
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddrTCP)
}

func (m *Manager) dialMeek(ctx context.Context) (net.Conn, error) {
	tr, err := meek.New(&meek.Config{
		URL:         m.tcfg("url"),
		FrontDomain: m.tcfg("front"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialTorSOCKS(ctx context.Context) (net.Conn, error) {
	torAddr := m.tcfg("tor_addr")
	if torAddr == "" {
		torAddr = "127.0.0.1:9050"
	}
	tr, err := torsocks.New(&torsocks.Config{TorAddr: torAddr})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialDomainFront(ctx context.Context) (net.Conn, error) {
	tr, err := domainfront.New(&domainfront.Config{
		FrontDomain:  m.tcfg("front_domain"),
		TargetDomain: m.tcfg("target_domain"),
		Path:         "/",
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialYaCloud(ctx context.Context) (net.Conn, error) {
	tr, err := yacloud.New(&yacloud.Config{
		GatewayURL: m.tcfg("gateway_url"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialYaDisk(ctx context.Context) (net.Conn, error) {
	tr, err := yadisk.New(&yadisk.Config{
		OAuthToken: m.tcfg("token"),
		SessionID:  m.tcfg("session_id"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialYaTelemost(ctx context.Context) (net.Conn, error) {
	tr, err := yatelemost.New(&yatelemost.Config{
		SessionID:     m.tcfg("session_id"),
		ConferenceURL: m.tcfg("conference_url"),
		ICEPolicy:     "relay",
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialOKWebRTC(ctx context.Context) (net.Conn, error) {
	tr, err := okwebrtc.New(&okwebrtc.Config{
		OKToken: m.tcfg("ok_token"),
		OKAppID: m.tcfg("ok_app_id"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) getCurrentSNI() string {
	m.connMu.RLock()
	defer m.connMu.RUnlock()

	if m.currentSNI != "" {
		return m.currentSNI
	}
	if m.config.PhantomSNI != "" {
		return m.config.PhantomSNI
	}
	if len(m.russianSNIs) > 0 {
		return m.russianSNIs[0]
	}
	return ""
}

func (m *Manager) selectNewSNI() string {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return m.selectNewSNILocked()
}

func (m *Manager) selectNewSNILocked() string {
	if len(m.russianSNIs) == 0 {
		m.currentSNI = m.config.PhantomSNI
		return m.currentSNI
	}

	idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(m.russianSNIs))))
	if err != nil {
		m.currentSNI = m.russianSNIs[0]
	} else {
		m.currentSNI = m.russianSNIs[idxBig.Int64()]
	}
	m.lastRotation = time.Now()

	nextInterval := m.getSNIRotationInterval(m.currentSNI)
	log.Info("[ROTATION EVENT] Selected new SNI: %s (Next rotation in %s)", m.currentSNI, nextInterval)

	return m.currentSNI
}

func (m *Manager) getRotationSNI() string {
	m.connMu.RLock()
	sni := m.currentSNI
	m.connMu.RUnlock()

	if sni != "" {
		return sni
	}

	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.currentSNI != "" {
		return m.currentSNI
	}

	return m.selectNewSNILocked()
}

func (m *Manager) getSNIRotationInterval(sni string) time.Duration {
	if sni == "" {
		return m.config.RotationInterval
	}

	if strings.Contains(sni, "ozon") ||
		strings.Contains(sni, "wildberries") ||
		strings.Contains(sni, "avito") ||
		strings.Contains(sni, "market") {
		return 6 * time.Hour
	}

	if strings.Contains(sni, "yandex") ||
		strings.Contains(sni, "ya.ru") ||
		strings.Contains(sni, "google") ||
		strings.Contains(sni, "mail.ru") ||
		strings.Contains(sni, "rambler") ||
		strings.Contains(sni, "bing") {
		return 4 * time.Hour
	}

	if strings.Contains(sni, "rutube") ||
		strings.Contains(sni, "vk.com") ||
		strings.Contains(sni, "vkvideo") ||
		strings.Contains(sni, "kion") ||
		strings.Contains(sni, "premier") ||
		strings.Contains(sni, "twitch") {
		return 24 * time.Hour
	}

	if strings.Contains(sni, "vk.com") ||
		strings.Contains(sni, "telegram") {
		return 6 * time.Hour
	}

	return 2 * time.Hour
}

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

func (m *Manager) Disconnect() {
	m.stopKeepalive()
	m.stopRotation()

	m.connMu.Lock()

	for _, c := range m.activePool {
		close(c.closing)
		c.Close()
	}
	m.activePool = nil
	m.activeConn = nil

	for _, c := range m.drainingConns {
		close(c.closing)
		c.Close()
	}
	m.drainingConns = nil
	m.streamConns = make(map[uint16]*managedConn)
	m.connMu.Unlock()

	if m.killSwitch != nil {
		m.killSwitch.Disable()
	}

	m.setState(StateDisconnected)
	m.PublishEvent("tunnel.disconnected", nil)
}

func (m *Manager) Reconnect(ctx context.Context) error {
	if !m.circuitBreakerAllow() {
		log.Warn("Circuit breaker OPEN - skipping reconnect attempt")
		return fmt.Errorf("circuit breaker open")
	}

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
			m.circuitBreakerFail()
			m.setError(err)
			return err
		}

		m.Disconnect()
		err := m.Connect(ctx)
		if err == nil {
			m.circuitBreakerSuccess()
			return nil
		}

		m.circuitBreakerFail()
		jitter := time.Duration(mrand.Int63n(int64(delay) / 4))
		time.Sleep(delay + jitter)
		delay = time.Duration(float64(delay) * 2)
		if delay > m.config.ReconnectMaxDelay {
			delay = m.config.ReconnectMaxDelay
		}
	}
}

const (
	cbThreshold = 5
	cbResetTime = 30 * time.Second
)

func (m *Manager) circuitBreakerAllow() bool {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()

	if m.cbState == "" {
		m.cbState = "closed"
	}

	switch m.cbState {
	case "open":
		if time.Since(m.cbLastFailure) > cbResetTime {
			m.cbState = "half-open"
			log.Info("Circuit breaker: HALF-OPEN (allowing one attempt)")
			return true
		}
		return false
	case "half-open":
		return true
	default:
		return true
	}
}

func (m *Manager) circuitBreakerFail() {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()

	m.cbFailures++
	m.cbLastFailure = time.Now()

	if m.cbState == "half-open" || m.cbFailures >= cbThreshold {
		m.cbState = "open"
		log.Warn("Circuit breaker: OPEN (failures: %d, will retry in %v)", m.cbFailures, cbResetTime)
	}
}

func (m *Manager) circuitBreakerSuccess() {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()

	m.cbFailures = 0
	m.cbState = "closed"
	log.Info("Circuit breaker: CLOSED (connection successful)")
}

func (m *Manager) RotateSNI() {
	oldSNI := m.currentSNI
	newSNI := m.selectNewSNI()
	log.Info("Initiating Seamless SNI Rotation to: %s", newSNI)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.connectInternal(ctx, true); err != nil {
		log.Error("SNI Rotation failed: %v - keeping existing connection", err)

		m.connMu.Lock()
		m.currentSNI = oldSNI
		m.connMu.Unlock()

		return
	}

	log.Info("SNI Rotation complete. Old connections will drain gracefully.")
}

func (m *Manager) readLoop(mc *managedConn) {
	defer mc.Close()

	var inputReader io.Reader = mc
	if m.obfuscator != nil && !m.isTransportSecure {
		inputReader = &deobfuscatingReader{r: mc, obf: m.obfuscator}
	}
	reader := bufio.NewReaderSize(inputReader, 262144)

	header := make([]byte, FrameHeaderSize)
	tlsDrainCount := 0
	consecutiveGarbage := 0
	const maxTLSDrain = 50

	lastDeadlineUpdate := time.Now()
	mc.SetReadDeadline(lastDeadlineUpdate.Add(m.config.KeepaliveInterval * 2))

	for {
		select {
		case <-mc.closing:
			return
		default:
		}

		if !m.isTransportSecure {
			peek, err := reader.Peek(5)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					lastDeadlineUpdate = time.Now()
					mc.SetReadDeadline(lastDeadlineUpdate.Add(m.config.KeepaliveInterval * 2))
					continue
				}
				m.handleReadError(mc, err)
				return
			}

			if tlsDrainCount < maxTLSDrain && peek[0] >= 0x14 && peek[0] <= 0x17 && peek[1] <= 0x04 {
				tlsLen := int(peek[3])<<8 | int(peek[4])
				log.Debug("Detected TLS data (type=0x%02x, ver=0x%02x, len=%d)", peek[0], peek[1], tlsLen)

				if _, err := reader.Discard(5); err != nil {
					m.handleReadError(mc, err)
					return
				}

				if tlsLen > 0 {
					isWrappedFrame := false

					if peek[0] == 0x17 {
						buf := make([]byte, tlsLen)
						if _, err := io.ReadFull(reader, buf); err != nil {
							m.handleReadError(mc, err)
							return
						}

						processBuf := buf
						for layer := 0; layer < 5; layer++ {
							if len(processBuf) >= FrameHeaderSize {
								pLen := binary.BigEndian.Uint32(processBuf[4:8])
								fType := processBuf[2]

								if fType <= 0x0A && int(pLen) <= 65535 && FrameHeaderSize+int(pLen) <= len(processBuf) {
									log.Debug("Unwrapped TLS ApplicationData containing valid Frame (Layer %d, StreamID=%d, Type=%d, Len=%d)",
										layer, binary.BigEndian.Uint16(processBuf[0:2]), fType, pLen)
									isWrappedFrame = true

									offset := 0
									for offset+FrameHeaderSize <= len(processBuf) {
										if offset+FrameHeaderSize > len(processBuf) {
											break
										}

										pLen := binary.BigEndian.Uint32(processBuf[offset+4 : offset+8])
										fType := processBuf[offset+2]
										frameTotal := FrameHeaderSize + int(pLen)

										if fType > 0x0A || offset+frameTotal > len(processBuf) {
											log.Warn("Invalid frame in TLS batch at offset %d (Type=%d, Len=%d)", offset, fType, pLen)
											break
										}

										if fType == 0x00 {
											log.Debug("Skipping Padding frame (Len=%d)", pLen)
											offset += frameTotal
											continue
										}

										frameData := make([]byte, frameTotal)
										copy(frameData, processBuf[offset:offset+frameTotal])

										m.UpdateActivity()

										select {
										case m.readCh <- frameData:
											atomic.AddUint64(&m.bytesDown, uint64(len(frameData)))
										case <-mc.closing:
											return
										}

										offset += frameTotal
									}

									tlsDrainCount = 0
									break
								}
							}

							if len(processBuf) > 5 && processBuf[0] == 0x17 && processBuf[1] == 0x03 {
								innerLen := int(processBuf[3])<<8 | int(processBuf[4])
								if innerLen+5 <= len(processBuf) {
									log.Debug("Detected nested TLS record inside AppData (Layer %d), unwrapping %d bytes...", layer, innerLen)
									processBuf = processBuf[5 : 5+innerLen]
									continue
								}
							}

						}

						if isWrappedFrame {
							consecutiveGarbage = 0
							continue
						}

						if len(buf) > 0 {
							headerPeek := buf
							if len(headerPeek) > 16 {
								headerPeek = headerPeek[:16]
							}
							log.Warn("Failed to unwrap TLS AppData (Len=%d). First 16 bytes: %x", len(buf), headerPeek)
						}
					}

					if !isWrappedFrame && peek[0] != 0x17 {
						if tlsLen > 65535 {
							tlsLen = 65535
						}
						if _, err := io.CopyN(io.Discard, reader, int64(tlsLen)); err != nil {
							m.handleReadError(mc, err)
							return
						}
					}

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
				continue
			}

		}
		consecutiveGarbage = 0
		tlsDrainCount = 0

		if time.Since(lastDeadlineUpdate) > 5*time.Second {
			lastDeadlineUpdate = time.Now()
			mc.SetReadDeadline(lastDeadlineUpdate.Add(m.config.KeepaliveInterval * 2))
		}

		if _, err := io.ReadFull(reader, header); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				lastDeadlineUpdate = time.Now()
				mc.SetReadDeadline(lastDeadlineUpdate.Add(m.config.KeepaliveInterval * 2))
				continue
			}
			m.handleReadError(mc, err)
			return
		}

		payloadLen := binary.BigEndian.Uint32(header[4:8])

		if payloadLen > 131072 {
			log.Warn("Frame too large (%d bytes), header: %x. Attempting RESYNC...", payloadLen, header)

			foundOffset := -1
			for i := 1; i <= FrameHeaderSize-3; i++ {
				if header[i] >= 0x14 && header[i] <= 0x17 && header[i+1] == 0x03 && header[i+2] <= 0x04 {
					foundOffset = i
					break
				}
			}

			if foundOffset != -1 {
				log.Warn("RESYNC: Found TLS header signature at offset %d inside invalid frame. Recovering...", foundOffset)

				tlsHeader := make([]byte, 5)
				available := FrameHeaderSize - foundOffset
				copy(tlsHeader, header[foundOffset:])

				if available < 5 {
					if _, err := io.ReadFull(reader, tlsHeader[available:]); err != nil {
						m.handleReadError(mc, err)
						return
					}
				}
				tlsLen := int(tlsHeader[3])<<8 | int(tlsHeader[4])
				log.Warn("RESYNC: Recovered TLS packet (len=%d). Draining...", tlsLen)

				payloadBytesInHeader := FrameHeaderSize - (foundOffset + 5)
				if payloadBytesInHeader < 0 {
					payloadBytesInHeader = 0
				}

				remainingToDrain := tlsLen - payloadBytesInHeader

				if remainingToDrain > 0 {
					if remainingToDrain > 65535 {
						remainingToDrain = 65535
					}
					if _, err := io.CopyN(io.Discard, reader, int64(remainingToDrain)); err != nil {
						m.handleReadError(mc, err)
						return
					}
				}

				tlsDrainCount++
				continue
			} else {
				log.Error("RESYNC failed: No embedded TLS header found. Closing connection.")
				return
			}
		}

		needed := FrameHeaderSize + int(payloadLen)
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

		if len(frameData) >= 3 && frameData[2] == 0x07 {
			m.lastPong = time.Now()
			log.Debug("Received PONG from server")
			continue
		}

		if len(frameData) >= 3 && frameData[2] == FrameTypeRekey {
			log.Info("[REKEY] Received rekey acknowledgement from server")
			m.lastPong = time.Now()
			continue
		}

		m.lastPong = time.Now()

		streamID := binary.BigEndian.Uint16(frameData[0:2])

		m.streamChsMu.RLock()
		ch, exists := m.streamChs[streamID]
		m.streamChsMu.RUnlock()

		if exists {
			select {
			case ch <- frameData:
				atomic.AddUint64(&m.bytesDown, uint64(len(frameData)))
				m.UpdateActivity()
			default:
				log.Warn("Stream %d buffer full, dropping frame", streamID)
			}
		} else {
			select {
			case m.readCh <- frameData:
				atomic.AddUint64(&m.bytesDown, uint64(len(frameData)))
				m.UpdateActivity()
			case <-mc.closing:
				return
			}
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

		if m.GetState() == StateConnected {
			go m.Reconnect(context.Background())
		}
	}
}

func (m *Manager) Receive(buf []byte) (int, error) {
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

	copy(buf, packet)

	if cap(packet) == 66048 {
		bufferPool.Put(packet)
	}

	n := len(packet)
	return n, nil
}

func (m *Manager) ReceivePacket() ([]byte, error) {
	packet, ok := <-m.readCh
	if !ok {
		return nil, fmt.Errorf("tunnel closed")
	}
	return packet, nil
}

func (m *Manager) Recycle(buf []byte) {
	bufferPool.Put(buf)
}

func (m *Manager) OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	m.connMu.RLock()
	pool := m.activePool
	m.connMu.RUnlock()

	if len(pool) == 0 {
		return nil, fmt.Errorf("not connected")
	}

	idx := atomic.AddUint32(&m.streamIdx, 1) % uint32(len(pool))
	mc := pool[idx]

	stream, err := mc.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	addrBytes := []byte(addr)
	header := make([]byte, 1+2+len(addrBytes)+2)
	header[0] = proto
	binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
	copy(header[3:], addrBytes)
	binary.BigEndian.PutUint16(header[3+len(addrBytes):], port)

	if _, err := stream.Write(header); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write connect header: %w", err)
	}

	resp := make([]byte, 1)
	if _, err := io.ReadFull(stream, resp); err != nil {
		stream.Close()
		return nil, fmt.Errorf("read connect response: %w", err)
	}
	if resp[0] != 0x00 {
		stream.Close()
		return nil, fmt.Errorf("relay refused connection")
	}

	return stream, nil
}

func (m *Manager) Send(data []byte) error {
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
		if delay > 0 && frameType != FrameTypeData {
			time.Sleep(delay)
		}
	}

	const maxRetries = 10
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		targetConn := m.activeConn

		if len(data) >= 8 {
			m.connMu.Lock()
			if frameType == FrameTypeConnect {
				if len(m.activePool) > 0 {
					idx := streamID % uint16(len(m.activePool))
					selectedConn := m.activePool[idx]
					m.streamConns[streamID] = selectedConn
					targetConn = selectedConn

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

			state := m.GetState()
			if state == StateReconnecting || state == StateRotating || state == StateConnecting {
				if frameType == FrameTypeData {
					return fmt.Errorf("not connected")
				}
				log.Debug("Send: waiting for reconnect (attempt %d/%d)", attempt+1, maxRetries)
				delay := m.getReconnectDelay()
				time.Sleep(delay)
				continue
			}
			return fmt.Errorf("not connected")
		}
		conn := targetConn
		m.connMu.RUnlock()

		total := len(data)
		n := 0
		var writeErr error
		var err error

		currentChunkSize := 65536
		const minChunkSize = 16384
		const maxChunkSize = 131072

		if total > currentChunkSize {
			start := 0
			for start < total {
				end := start + currentChunkSize
				if end > total {
					end = total
				}

				chunk := data[start:end]

				tStart := time.Now()
				wn, wErr := conn.Write(chunk)
				duration := time.Since(tStart)

				n += wn
				if wErr != nil {
					writeErr = wErr
					break
				}

				if duration < 2*time.Millisecond {
					if currentChunkSize < maxChunkSize {
						currentChunkSize = currentChunkSize * 3 / 2
						if currentChunkSize > maxChunkSize {
							currentChunkSize = maxChunkSize
						}
					}
				} else if duration > 100*time.Millisecond {
					if currentChunkSize > minChunkSize {
						currentChunkSize = currentChunkSize * 2 / 3
						if currentChunkSize < minChunkSize {
							currentChunkSize = minChunkSize
						}
					}
				}

				start += wn
			}
			err = writeErr
		} else {
			n, err = conn.Write(data)
		}
		if err != nil {
			lastErr = err

			errMsg := err.Error()
			isClosed := strings.Contains(errMsg, "closed") || strings.Contains(errMsg, "broken pipe") || strings.Contains(errMsg, "connection reset") || strings.Contains(errMsg, "EOF")

			if isClosed {
				if frameType == FrameTypeData {
					return err
				}

				state := m.GetState()

				if state == StateConnected {
					log.Warn("Send: connection unexpectedly closed/reset. Triggering Reconnect... (Err: %v)", err)
					m.handleReadError(conn, err)
				}

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

func (m *Manager) monitorDrainingConn(mc *managedConn) {
	time.Sleep(m.config.DrainingTimeout)

	m.connMu.Lock()
	defer m.connMu.Unlock()

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

func (m *Manager) startRotation() {
	m.stopRotation()
	if !m.config.EnableRotation {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.rotationCancel = cancel

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

func (m *Manager) stopRotation() {
	if m.rotationCancel != nil {
		m.rotationCancel()
	}
	if m.rotationTicker != nil {
		m.rotationTicker.Stop()
	}
}

func (m *Manager) GetState() TunnelState {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.state
}

func (m *Manager) IsConnected() bool {
	s := m.GetState()
	return s == StateConnected || s == StateRotating
}

func (m *Manager) GetSessionID() uint32 {
	return m.sessionID
}

func (m *Manager) OnStateChange(callback func(TunnelState)) {
	m.onStateChange = callback
}

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

func (m *Manager) setError(err error) {
	m.stateMu.Lock()
	m.state = StateError
	m.lastError = err
	m.stateMu.Unlock()
	m.SetHealthy(false, err.Error())
}

func (m *Manager) DialStream(ctx context.Context, network, addr string) (net.Conn, error) {
	if !m.IsConnected() {
		return nil, fmt.Errorf("tunnel not connected")
	}

	var streamID uint16
	for i := 0; i < 100; i++ {
		randBytes := make([]byte, 2)
		if _, err := rand.Read(randBytes); err != nil {
			return nil, err
		}
		candidate := binary.BigEndian.Uint16(randBytes)
		if candidate == 0 {
			continue
		}
		m.streamChsMu.RLock()
		_, exists := m.streamChs[candidate]
		m.streamChsMu.RUnlock()
		if !exists {
			streamID = candidate
			break
		}
	}
	if streamID == 0 {
		return nil, fmt.Errorf("failed to allocate stream ID")
	}

	ch := make(chan []byte, 1024)
	m.streamChsMu.Lock()
	m.streamChs[streamID] = ch
	m.streamChsMu.Unlock()

	var proto byte = 0x06
	if network == "udp" {
		proto = 0x11
	}

	host, portStr, _ := net.SplitHostPort(addr)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	connectPayload := make([]byte, 1+2+len(host)+2)
	connectPayload[0] = proto
	binary.BigEndian.PutUint16(connectPayload[1:3], uint16(len(host)))
	copy(connectPayload[3:], host)
	binary.BigEndian.PutUint16(connectPayload[3+len(host):], port)

	frame := make([]byte, FrameHeaderSize+len(connectPayload))
	binary.BigEndian.PutUint16(frame[0:2], streamID)
	frame[2] = FrameTypeConnect
	frame[3] = 0x00
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(connectPayload)))
	copy(frame[8:], connectPayload)

	if err := m.Send(frame); err != nil {
		m.streamChsMu.Lock()
		delete(m.streamChs, streamID)
		m.streamChsMu.Unlock()
		return nil, err
	}

	m.connMu.RLock()
	localAddr := m.activeConn.LocalAddr()
	remoteAddr := m.activeConn.RemoteAddr()
	m.connMu.RUnlock()

	return &StreamConn{
		streamID: streamID,
		manager:  m,
		readCh:   ch,
		local:    localAddr,
		remote:   remoteAddr,
	}, nil
}

type StreamConn struct {
	streamID uint16
	manager  *Manager
	readCh   chan []byte
	local    net.Addr
	remote   net.Addr
}

func (s *StreamConn) Read(b []byte) (n int, err error) {
	data, ok := <-s.readCh
	if !ok {
		return 0, io.EOF
	}
	if len(data) <= FrameHeaderSize {
		return 0, nil
	}
	payload := data[FrameHeaderSize:]
	copy(b, payload)
	return len(payload), nil
}

func (s *StreamConn) Write(b []byte) (n int, err error) {
	frame := make([]byte, FrameHeaderSize+len(b))
	binary.BigEndian.PutUint16(frame[0:2], s.streamID)
	frame[2] = 0x02
	frame[3] = 0x00
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(b)))
	copy(frame[8:], b)

	if err := s.manager.Send(frame); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *StreamConn) Close() error {
	s.manager.streamChsMu.Lock()
	delete(s.manager.streamChs, s.streamID)
	s.manager.streamChsMu.Unlock()

	frame := make([]byte, FrameHeaderSize)
	binary.BigEndian.PutUint16(frame[0:2], s.streamID)
	frame[2] = FrameTypeClose
	binary.BigEndian.PutUint32(frame[4:8], 0)

	return s.manager.Send(frame)
}

func (s *StreamConn) LocalAddr() net.Addr                { return s.local }
func (s *StreamConn) RemoteAddr() net.Addr               { return s.remote }
func (s *StreamConn) SetDeadline(t time.Time) error      { return nil }
func (s *StreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *StreamConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *Manager) startKeepalive() {
	m.stopKeepalive()
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

func (m *Manager) stopKeepalive() {
	if m.keepaliveCancel != nil {
		m.keepaliveCancel()
	}
	if m.keepaliveTicker != nil {
		m.keepaliveTicker.Stop()
	}
}

func (m *Manager) sendKeepalive() {
	if !m.lastPong.IsZero() && m.GetState() == StateConnected {
		silentDuration := time.Since(m.lastPong)
		maxSilence := 60 * time.Second
		if silentDuration > maxSilence {
			log.Warn("No data received in %s (max %s), triggering reconnect", silentDuration, maxSilence)
			go m.Reconnect(context.Background())
			return
		}
	}

	pingFrame := make([]byte, 8)
	pingFrame[2] = 0x06

	if err := m.Send(pingFrame); err != nil {
		log.Warn("Keepalive send failed: %v", err)
	} else {
		m.lastKeepalive = time.Now()
		m.lastPong = time.Now()
	}
}

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

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}

func generateRandomShortId() string {
	const chars = "0123456789abcdef"
	result := make([]byte, 8)
	for i := range result {
		result[i] = chars[int(time.Now().UnixNano()/int64(i+1))%len(chars)]
	}
	return string(result)
}

func (m *Manager) getReconnectDelay() time.Duration {
	attempts := atomic.LoadUint32(&m.reconnectAttempts)
	if attempts == 0 {
		return m.config.ReconnectInterval
	}
	delay := m.config.ReconnectInterval
	for i := uint32(0); i < attempts && i < 10; i++ {
		delay = time.Duration(float64(delay) * 2)
	}
	if delay > m.config.ReconnectMaxDelay {
		delay = m.config.ReconnectMaxDelay
	}
	jitter := time.Duration(mrand.Int63n(int64(delay) / 4))
	return delay + jitter
}

func probeLatency(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

func (m *Manager) pickFastestServer(ctx context.Context) string {
	if len(m.config.ServerList) == 0 {
		return ""
	}

	type result struct {
		addr    string
		latency time.Duration
	}

	ch := make(chan result, len(m.config.ServerList))

	for _, addr := range m.config.ServerList {
		addr := addr
		go func() {
			lat, err := probeLatency(ctx, addr, 200*time.Millisecond)
			if err != nil {
				log.Debug("[LATENCY] %s unreachable: %v", addr, err)
				ch <- result{addr: addr, latency: 1<<62 - 1}
				return
			}
			log.Info("[LATENCY] %s RTT=%v", addr, lat)
			ch <- result{addr: addr, latency: lat}
		}()
	}

	var best result
	best.latency = 1<<62 - 1
	for range m.config.ServerList {
		r := <-ch
		if r.latency < best.latency {
			best = r
		}
	}

	if best.latency == 1<<62-1 {
		log.Warn("[LATENCY] All servers unreachable during probe, using configured default")
		return ""
	}

	log.Info("[LATENCY] Fastest server: %s (RTT=%v)", best.addr, best.latency)
	return best.addr
}


const FrameTypeRekey = 0x08

func (m *Manager) startRekey() {
	if m.config.RekeyInterval <= 0 {
		return
	}
	m.stopRekey()

	ctx, cancel := context.WithCancel(context.Background())
	m.rekeyCancel = cancel
	m.rekeyTicker = time.NewTicker(m.config.RekeyInterval)

	safeGo("rekey", func() {
		defer m.rekeyTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.rekeyTicker.C:
				m.performRekey()
			}
		}
	})
	log.Info("[REKEY] Periodic rekeying started (interval=%v)", m.config.RekeyInterval)
}

func (m *Manager) stopRekey() {
	if m.rekeyCancel != nil {
		m.rekeyCancel()
		m.rekeyCancel = nil
	}
	if m.rekeyTicker != nil {
		m.rekeyTicker.Stop()
		m.rekeyTicker = nil
	}
}

func (m *Manager) performRekey() {
	if m.GetState() != StateConnected {
		return
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		log.Warn("[REKEY] Failed to generate seed: %v", err)
		return
	}

	frame := make([]byte, FrameHeaderSize+32)
	binary.BigEndian.PutUint16(frame[0:2], 0)
	frame[2] = FrameTypeRekey
	frame[3] = 0x00
	binary.BigEndian.PutUint32(frame[4:8], 32)
	copy(frame[FrameHeaderSize:], seed)

	if err := m.Send(frame); err != nil {
		log.Warn("[REKEY] Failed to send rekey frame: %v", err)
		return
	}
	log.Info("[REKEY] Sent rekey frame, initiating transport rotation (seed=%x...)", seed[:4])

	go func() {
		time.Sleep(500 * time.Millisecond)
		m.rotateTransport()
	}()
}

func (m *Manager) rotateTransport() {
	m.connMu.RLock()
	poolSize := len(m.activePool)
	m.connMu.RUnlock()

	if poolSize == 0 {
		return
	}

	log.Info("[REKEY] Rotating %d transport connections for PFS", poolSize)

	m.setState(StateReconnecting)
	m.Reconnect(context.Background())
}
