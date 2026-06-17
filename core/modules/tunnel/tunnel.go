package tunnel

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"whispera/common/buf"
	"whispera/common/log"
	"whispera/common/mux"
	"whispera/common/runtime/base"
	"whispera/common/runtime/events"
	"whispera/common/runtime/interfaces"
	asnbypass "whispera/core/asn_bypass"
	"whispera/core/modules/killswitch"
	"whispera/core/protocol"
	"whispera/neural"
	"whispera/neural/evasion"
)

var log = logger.Module("tunnel")

var _ interfaces.Module = (*Manager)(nil)

type ackStripConn struct {
	net.Conn
	stream    net.Conn
	once      sync.Once
	ackErr    error
	onClose   func()
	closeOnce sync.Once
}

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

const (
	ModuleName    = "tunnel.manager"
	ModuleVersion = "1.0.0"

	FrameHeaderSize  = 8
	FrameTypeConnect = 0x01
	FrameTypeData    = 0x04
	FrameTypeClose   = 0x05
	FrameTypeRekey   = 0x08
)

func isConnResetOrBroken(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		msg := opErr.Err.Error()
		return strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset")
	}
	return false
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

type ChameleonOptions struct {
	EnableChameleon   bool
	ChameleonAddr     string
	ChameleonSNI      string
	ChameleonSecret   []byte
	ChameleonCertPin  string
	ChameleonQUICAddr string
	ChameleonMux      int
}

type MLOptions struct {
	MLServerURL     string
	MLTLSSkipVerify bool
	MLToken         string
	SNIModelDir     string
	SNIDomainsURL   string
}

type Config struct {
	ServerAddr           string
	ServerAddrTCP        string
	Transport            string
	TransportWhitelist   []string
	TransportBlacklist   []string
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

	ChameleonOptions
	MLOptions

	BehavioralProfile string

	ServerList []string

	Regions         map[string][]string
	PreferredRegion string

	RekeyInterval time.Duration

	TransportConfig map[string]interface{}

	ForceObfuscation bool

	CustomDialFn func(ctx context.Context) (net.Conn, error)

	DesyncConfig *evasion.DesyncConfig
	CustomSNI    string
	NoSNI        bool
	RateLimitKB  int

	EnableIPSpoof  bool
	SpoofSourceIPs []string

	TLSFragmentSize int

	ForceSNI string

	QualityThresholdRTT     time.Duration
	QualityMissedKeepalives int

	PaddingMaxSize int
}

func DefaultConfig() *Config {
	return &Config{
		KeepaliveInterval:    15 * time.Second,
		ReconnectInterval:    2 * time.Second,
		ReconnectMaxDelay:    30 * time.Second,
		MaxReconnectAttempts: 0,
		ConnectionTimeout:    90 * time.Second,
		EnableRotation:       true,
		RotationInterval:     60 * time.Minute,
		DrainingTimeout:      90 * time.Minute,
		ForceObfuscation:     true,
	}
}

func (c *Config) Validate() error {
	if c.KeepaliveInterval <= 0 {
		c.KeepaliveInterval = 10 * time.Second
	}
	if c.ReconnectInterval <= 0 {
		c.ReconnectInterval = 2 * time.Second
	}
	if c.ReconnectMaxDelay <= 0 {
		c.ReconnectMaxDelay = 30 * time.Second
	}
	if c.ConnectionTimeout <= 0 {
		c.ConnectionTimeout = 90 * time.Second
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
	session     *mux.Session
	id          string
	createdAt   time.Time
	maxAge      time.Duration
	maxUploadB  int64
	uploadBytes int64
	closing     chan struct{}
	closeOnce   sync.Once

	lastSampledBytes atomic.Uint64
	lastSampleNs     atomic.Int64
	rateMbpsX100     atomic.Int64
}

const (
	streamShardCount = 16
	streamShardMask  = streamShardCount - 1
)

type streamShard struct {
	mu sync.RWMutex
	m  map[uint16]chan *buf.Buffer
}

func (m *Manager) streamLoad(streamID uint16) (chan *buf.Buffer, bool) {
	s := &m.streamShards[streamID&streamShardMask]
	s.mu.RLock()
	ch, ok := s.m[streamID]
	s.mu.RUnlock()
	return ch, ok
}

func (m *Manager) streamDelete(streamID uint16) {
	s := &m.streamShards[streamID&streamShardMask]
	s.mu.Lock()
	delete(s.m, streamID)
	s.mu.Unlock()
}

func (m *Manager) initStreamShards() {
	for i := range m.streamShards {
		m.streamShards[i].m = make(map[uint16]chan *buf.Buffer)
	}
}

type Manager struct {
	*base.Module
	config *Config

	sm            *tunnelStateMachine
	cb            *circuitBreaker
	activeConn    *managedConn
	activePool    []*managedConn
	drainingConns []*managedConn
	streamConns   map[uint16]*managedConn
	readCh        chan *buf.Buffer

	streamShards [streamShardCount]streamShard

	connMu    sync.RWMutex
	sessionID uint32

	tunDevice interfaces.TUNDevice
	handshake interfaces.HandshakeHandler
	dataPlane interfaces.DataPlane
	crypto    interfaces.CryptoProvider

	keepaliveCancel context.CancelFunc
	rotationTicker  *time.Ticker
	rotationCancel  context.CancelFunc
	rekeyTicker     *time.Ticker
	rekeyCancel     context.CancelFunc

	reconnectAttempts uint32
	reconnecting      int32
	bytesUp           uint64
	bytesDown         uint64
	lastKeepalive     time.Time
	lastPong          time.Time
	connectedAt       time.Time

	reconnectDone chan struct{}

	onStateChange func(TunnelState)

	killSwitch *killswitch.KillSwitch

	obfuscator        interfaces.Obfuscator
	asnBypassDialer   *asnbypass.Dialer
	isTransportSecure bool

	transportSecureOverride int32
	forceObfuscation        int32

	russianSNIs     []string
	russianSNIsMu   sync.RWMutex
	currentSNI      string
	lastRotation    time.Time
	sniAgent        *neural.RLSNIAgent
	connAgent       *neural.RLConnAgent
	connAgentStop   chan struct{}
	rateSamplerStop chan struct{}
	gpLastDn        uint64
	gpLastUp        uint64
	gpLastSample    time.Time
	scaleAccBytes   uint64
	scaleLastEval   time.Time
	scaleMu         sync.Mutex
	chScaleOpening  int32
	gameLn          gameLane
	transportAgent  *neural.RLTransportAgent
	kaAgent         *neural.RLKeepaliveAgent
	boAgent         *neural.RLBackoffAgent
	jitterAgent     *neural.RLJitterAgent
	serverAgent     *neural.RLServerAgent
	chunkAgent      *neural.RLChunkAgent
	tlsAgent        *neural.RLTLSAgent
	tspuDetector    *neural.TSPUDetector

	boFailCount     int32
	boLastSuccessAt int64
	boLastErrType   int32
	tlsErrStreak    int32

	goroutineLimiter *base.GoroutineLimiter

	rateLimitKB     int32
	tlsFragmentSize int32

	spoofIPs []string
	spoofIdx uint64

	fedSyncOnce sync.Once

	lastGoodMu         sync.RWMutex
	lastGoodSNI        string
	lastGoodTransport  string
	lastGoodServerAddr string

	qualityRTTEWMA int64
	missedKAs      int32
	netCtxOnce     sync.Once
	pubIP          atomic.Value
	asnVal         atomic.Value
	ccVal          atomic.Value
	blockAvoid     atomic.Value

	chameleonSessionCache any
}

func (m *Manager) getMuxConfig() *mux.Config {
	base := 8 + mrand.Intn(7)

	frameSize := 65535
	if m.chunkAgent != nil {
		rttMs := float64(atomic.LoadInt64(&m.qualityRTTEWMA)) / 1e6
		upBytes := float64(atomic.LoadUint64(&m.bytesUp))
		dnBytes := float64(atomic.LoadUint64(&m.bytesDown))
		frameSize = m.chunkAgent.Decide(neural.ChunkView{
			RTTMs:      rttMs,
			BytesUpSec: upBytes / 60.0,
			BytesDnSec: dnBytes / 60.0,
		})
	}

	return &mux.Config{
		MaxFrameSize:         frameSize,
		MaxReceiveBuffer:     1 << 28,
		MaxStreamBuffer:      1 << 26,
		KeepAliveInterval:    time.Duration(base) * time.Second,
		KeepAliveTimeout:     24 * time.Hour,
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

	var forceObfs int32 = 1
	if !cfg.ForceObfuscation {
		forceObfs = 0
	}

	m := &Manager{
		Module:                base.NewModule(ModuleName, ModuleVersion, []string{"handshake.handler"}),
		config:                cfg,
		streamConns:           make(map[uint16]*managedConn),
		readCh:                make(chan *buf.Buffer, 4096),
		goroutineLimiter:      base.NewGoroutineLimiter(1024),
		reconnectDone:         make(chan struct{}),
		forceObfuscation:      forceObfs,
		chameleonSessionCache: protocol.NewSessionCache(128),
	}
	m.cb = newCircuitBreaker()
	m.sm = newTunnelStateMachine(m.onStateTransition)
	m.initStreamShards()
	close(m.reconnectDone)

	if cfg.EnableASNBypass || cfg.ForceSNI != "" {
		frontDomain := cfg.DomainFrontHost
		enableSNIMask := false

		if cfg.ForceSNI != "" {
			frontDomain = cfg.ForceSNI
			enableSNIMask = true
		}

		asnConfig := &asnbypass.Config{
			Strategy:               cfg.ASNBypassStrategy,
			TLSFingerprint:         cfg.TLSFingerprint,
			FrontDomain:            frontDomain,
			EnableSNIMask:          enableSNIMask,
			ResidentialProxies:     cfg.ResidentialProxies,
			EnableJA3Randomization: cfg.EnableJA3Randomize,
			EnableTLSFragmentation: true,
			TLSFragmentSize: func() int {
				if cfg.TLSFragmentSize > 0 {
					return cfg.TLSFragmentSize
				}
				return 40
			}(),
			ConnectionBurstLimit: 5,
			ConnectionCooldown:   2 * time.Second,
			FailoverTimeout:      cfg.ConnectionTimeout,
			FallbackStrategies:   []asnbypass.Strategy{asnbypass.StrategyTLSMasquerade, asnbypass.StrategyDomainFronting},
		}

		m.asnBypassDialer = asnbypass.NewDialer(asnConfig)
	}

	if cfg.KillSwitchEnabled {
		ksConfig := &killswitch.Config{
			Enabled:      cfg.KillSwitchEnabled,
			AllowLAN:     cfg.KillSwitchAllowLAN,
			AllowDNS:     cfg.KillSwitchAllowDNS,
			PersistRules: false,
		}

		if ks, err := killswitch.New(ksConfig); err == nil {
			m.killSwitch = ks
			ks.OnStateChange(func(state killswitch.State) {
				m.PublishEvent("killswitch.state_changed", map[string]interface{}{
					"state": state.String(),
				})
			})
		}
	}

	m.connAgent = neural.NewRLConnAgent(cfg.SNIModelDir)
	m.kaAgent = neural.NewRLKeepaliveAgent(cfg.SNIModelDir)
	m.boAgent = neural.NewRLBackoffAgent(cfg.SNIModelDir)
	m.jitterAgent = neural.NewRLJitterAgent(cfg.SNIModelDir)
	m.serverAgent = neural.NewRLServerAgent(cfg.SNIModelDir)
	m.chunkAgent = neural.NewRLChunkAgent(cfg.SNIModelDir)
	m.tlsAgent = neural.NewRLTLSAgent(cfg.SNIModelDir)
	m.tspuDetector = neural.NewTSPUDetector()

	go m.runWeightSnapshotLoop()

	if cfg.CustomSNI != "" {
		if cfg.TransportConfig == nil {
			cfg.TransportConfig = make(map[string]interface{})
		}
		if _, exists := cfg.TransportConfig["sni"]; !exists {
			cfg.TransportConfig["sni"] = cfg.CustomSNI
		}
	}

	if cfg.RateLimitKB > 0 {
		atomic.StoreInt32(&m.rateLimitKB, int32(cfg.RateLimitKB))
	}

	if cfg.EnableIPSpoof && len(cfg.SpoofSourceIPs) > 0 {
		m.spoofIPs = cfg.SpoofSourceIPs
	}

	return m, nil
}

func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}
	m.SetHealthy(true, "tunnel manager running")
	m.PublishEvent(events.EventTypeModuleStarted, nil)

	safeGo("Reconnect", func() { m.Reconnect(m.Context()) })

	return nil
}

func (m *Manager) Stop() error {
	m.stopRekey()
	m.Disconnect()
	m.PublishEvent(events.EventTypeModuleStopped, nil)
	return m.Module.Stop()
}

func (m *Manager) PreWarm() {
	safeGo("PreWarm", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_ = m.Connect(ctx)
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

func (m *Manager) Connect(ctx context.Context) error {
	if _, blocked := m.sm.CompareAndSet(StateConnecting, StateConnecting, StateConnected); blocked {
		return nil
	}

	m.Disconnect()

	if len(m.config.ServerList) > 0 {
		if best := m.pickServer(ctx); best != "" {
			m.config.ServerAddrTCP = best
			m.config.ServerAddr = best
		}
	}

	if m.config.MLServerURL != "" {
		m.mlStartFederatedSync(ctx)
		m.mlStartTransportWatchdog(ctx)
		if rec, conf := m.mlRecommendTransport(); rec != "" && conf >= 0.55 {
			m.config.Transport = rec
		}
	}

	return m.connectInternal(ctx, false)
}

func (m *Manager) connectInternal(ctx context.Context, isRotation bool) error {
	if !isRotation {
		m.setState(StateConnecting)
	} else {
		m.setState(StateRotating)
	}

	targetPoolSize := 2
	if m.config.EnableChameleon {
		targetPoolSize = 1
	}
	var connectedPool []*managedConn
	var poolMu sync.Mutex
	firstConnReady := make(chan *managedConn, 1)
	firstConnErr := make(chan error, targetPoolSize)

	spawnConnection := func(idx int) {
		mc, err := m.dialManagedConn(ctx, fmt.Sprintf("pool-%d-%d", time.Now().Unix(), idx))
		if err != nil {
			select {
			case firstConnErr <- err:
			default:
			}
			return
		}

		poolMu.Lock()
		isFirst := len(connectedPool) == 0
		connectedPool = append(connectedPool, mc)
		poolMu.Unlock()

		safeGo("readLoop", func() { m.readLoop(mc) })

		if isFirst {
			select {
			case firstConnReady <- mc:
			default:
			}
			return
		}

		m.connMu.Lock()
		if !slices.Contains(m.activePool, mc) {
			m.activePool = append(m.activePool, mc)
		}
		m.connMu.Unlock()
	}

	for i := 0; i < targetPoolSize; i++ {
		idx := i
		go func() {
			if idx > 0 && m.config.EnableChameleon {
				time.Sleep(time.Duration(mrand.Intn(40)) * time.Millisecond)
			}
			spawnConnection(idx)
		}()
	}

	var firstConn *managedConn
	errCount := 0
	timeout := time.After(m.config.ConnectionTimeout)

	select {
	case firstConn = <-firstConnReady:
	case <-timeout:
		err := fmt.Errorf("connection timeout after %v", m.config.ConnectionTimeout)
		if !isRotation {
			m.setError(err)
		} else {
			m.setState(StateConnected)
		}
		return err
	case <-ctx.Done():
		if isRotation {
			m.setState(StateConnected)
		}
		return ctx.Err()
	}

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

	if m.killSwitch != nil && m.config.KillSwitchEnabled {
		m.enableKillSwitch(connectedPool[0].RemoteAddr())
	}

	m.connMu.Lock()
	if isRotation && m.activePool != nil {
		m.drainingConns = append(m.drainingConns, m.activePool...)
		for _, c := range m.activePool {
			go m.monitorDrainingConn(c)
		}
	}

	m.activePool = connectedPool
	m.activeConn = connectedPool[0]
	m.connMu.Unlock()

	for _, mc := range connectedPool {
		neural.FlowRegistry.RegisterConn(mc.LocalAddr(), mc.RemoteAddr(), neural.FlowTunnel)
	}

	if !isRotation {
		m.startKeepalive()
		m.startRekey()
		m.startConnAgent()
		m.startConnRateSampler()
		m.connectedAt = time.Now()
		m.lastPong = time.Now()
		m.setState(StateConnected)

		m.connMu.RLock()
		sniSnapshot := m.currentSNI
		m.connMu.RUnlock()
		m.lastGoodMu.Lock()
		m.lastGoodSNI = sniSnapshot
		m.lastGoodTransport = m.config.Transport
		m.lastGoodServerAddr = m.config.ServerAddr
		m.lastGoodMu.Unlock()

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
	}

	return nil
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

func (mc *managedConn) Close() error {
	mc.closeOnce.Do(func() {
		close(mc.closing)
		if mc.session != nil {
			mc.session.Close()
		}
		if mc.Conn != nil {
			mc.Conn.Close()
		}
	})
	return nil
}

func (m *Manager) removeDeadConn(mc *managedConn) {
	m.connMu.Lock()
	for i, c := range m.activePool {
		if c == mc {
			m.activePool = append(m.activePool[:i], m.activePool[i+1:]...)
			break
		}
	}
	for sid, c := range m.streamConns {
		if c == mc {
			delete(m.streamConns, sid)
		}
	}
	if m.activeConn == mc {
		if len(m.activePool) > 0 {
			m.activeConn = m.activePool[0]
		} else {
			m.activeConn = nil
		}
	}
	m.connMu.Unlock()
}

func (m *Manager) Disconnect() {
	m.stopKeepalive()
	m.stopConnAgent()
	m.stopConnRateSampler()

	m.connMu.Lock()

	for _, c := range m.activePool {
		c.Close()
	}
	m.activePool = nil
	m.activeConn = nil

	for _, c := range m.drainingConns {
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
	if ctx == nil {
		ctx = context.Background()
	}
	if !atomic.CompareAndSwapInt32(&m.reconnecting, 0, 1) {
		m.connMu.RLock()
		done := m.reconnectDone
		m.connMu.RUnlock()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}

	newDone := make(chan struct{})
	m.connMu.Lock()
	m.reconnectDone = newDone
	m.connMu.Unlock()

	defer func() {
		close(newDone)
		atomic.StoreInt32(&m.reconnecting, 0)
	}()

	if !m.circuitBreakerAllow() {
		return fmt.Errorf("circuit breaker open")
	}

	m.setState(StateReconnecting)
	delay := m.config.ReconnectInterval
	attempts := 0

	const fallbackAfterAttempts = 3
	originalTransport := m.config.Transport
	transportFallbackActivated := false

	m.lastGoodMu.RLock()
	zeroRTTSNI := m.lastGoodSNI
	zeroRTTTransport := m.lastGoodTransport
	m.lastGoodMu.RUnlock()

	for {
		attempts++
		atomic.StoreUint32(&m.reconnectAttempts, uint32(attempts))

		select {
		case <-ctx.Done():
			if transportFallbackActivated {
				m.config.Transport = originalTransport
			}
			return ctx.Err()
		default:
		}

		if m.config.MaxReconnectAttempts > 0 && attempts > m.config.MaxReconnectAttempts {
			err := fmt.Errorf("max reconnect attempts exceeded")
			m.circuitBreakerFail()
			m.setError(err)
			if transportFallbackActivated {
				m.config.Transport = originalTransport
			}
			return err
		}

		if attempts == fallbackAfterAttempts+1 &&
			originalTransport != "" && originalTransport != "auto" &&
			!transportFallbackActivated {
			transportFallbackActivated = true
			m.config.Transport = "auto"
		}

		m.Disconnect()

		m.connMu.Lock()
		if attempts == 1 && zeroRTTSNI != "" {
			m.currentSNI = zeroRTTSNI
			if zeroRTTTransport != "" {
				m.config.Transport = zeroRTTTransport
			}
		} else {
			m.currentSNI = ""
		}
		m.connMu.Unlock()

		dialStart := time.Now()
		usedTransport := m.config.Transport
		var err error
		if attempts == 1 && zeroRTTSNI != "" {
			err = m.connectInternal(ctx, false)
		} else {
			err = m.Connect(ctx)
		}
		dialLatency := float64(time.Since(dialStart).Milliseconds())
		if err == nil {
			m.mlSendFeedback(usedTransport, true, dialLatency)
			if m.sniAgent != nil {
				m.sniAgent.RecordOutcome(true, dialLatency)
			}
			if m.boAgent != nil {
				m.boAgent.RecordOutcome(true)
			}
			if m.serverAgent != nil {
				m.serverAgent.RecordOutcome(true, dialLatency)
			}
			atomic.StoreInt32(&m.boFailCount, 0)
			atomic.StoreInt64(&m.boLastSuccessAt, time.Now().Unix())
			m.circuitBreakerSuccess()
			if transportFallbackActivated {
				m.config.Transport = originalTransport
			}
			return nil
		}

		m.mlSendFeedback(usedTransport, false, dialLatency)
		if m.sniAgent != nil {
			m.sniAgent.RecordOutcome(false, dialLatency)
			if m.sniAgent.ShouldRotate() {
				go m.RotateSNI()
			}
		}
		if m.tspuDetector != nil {
			errStr := err.Error()
			dialDur := time.Duration(dialLatency) * time.Millisecond
			if strings.Contains(errStr, "reset") {
				m.tspuDetector.RecordRST(m.currentSNI, dialDur)
			}
			if dpiType, conf := m.tspuDetector.DetectTSPU(); dpiType != neural.DPITypeNone && conf >= 0.65 {
				if cm := neural.TSPUCountermeasure(dpiType); cm != "" && cm != m.config.Transport {
					m.config.Transport = cm
				}
			}
		}
		failCount := atomic.AddInt32(&m.boFailCount, 1)
		if m.boAgent != nil {
			m.boAgent.RecordOutcome(false)
		}
		if m.serverAgent != nil {
			m.serverAgent.RecordOutcome(false, dialLatency)
		}
		m.circuitBreakerFail()

		var backoffDelay time.Duration
		if m.boAgent != nil {
			errStr := ""
			lastSuc := atomic.LoadInt64(&m.boLastSuccessAt)
			secSince := 0.0
			if lastSuc > 0 {
				secSince = float64(time.Now().Unix() - lastSuc)
			}
			backoffDelay = m.boAgent.Decide(neural.BackoffView{
				ConsecutiveFails:    int(failCount),
				LastErrType:         neural.ClassifyBackoffErr(errStr),
				TimeSinceSuccessSec: secSince,
			})
		} else {
			backoffDelay = delay
			delay = time.Duration(float64(delay) * 2)
			if delay > m.config.ReconnectMaxDelay {
				delay = m.config.ReconnectMaxDelay
			}
		}

		select {
		case <-ctx.Done():
			if transportFallbackActivated {
				m.config.Transport = originalTransport
			}
			return ctx.Err()
		case <-time.After(backoffDelay):
		}
	}
}

func (m *Manager) circuitBreakerAllow() bool { return m.cb.Allow() }
func (m *Manager) circuitBreakerFail()       { m.cb.Fail() }
func (m *Manager) circuitBreakerSuccess()    { m.cb.Success() }

func (m *Manager) readLoop(mc *managedConn) {
	defer func() {
		m.removeDeadConn(mc)
		mc.Close()
	}()

	var inputReader io.Reader = mc
	if m.obfuscator != nil && !m.isTransportSecure && atomic.LoadInt32(&m.transportSecureOverride) == 0 {
		inputReader = &deobfuscatingReader{r: mc, obf: m.obfuscator}
	}
	reader := bufio.NewReaderSize(inputReader, 262144)

	var headerArr [FrameHeaderSize]byte
	header := headerArr[:]
	tlsDrainCount := 0
	consecutiveGarbage := 0
	const maxTLSDrain = 50

	mc.SetReadDeadline(time.Now().Add(m.config.KeepaliveInterval * 2))

	for {
		select {
		case <-mc.closing:
			return
		default:
		}

		if !m.isTransportSecure || atomic.LoadInt32(&m.forceObfuscation) != 0 {
			peek, err := reader.Peek(5)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					mc.SetReadDeadline(time.Now().Add(m.config.KeepaliveInterval * 2))
					continue
				}
				m.handleReadError(mc, err)
				return
			}

			if tlsDrainCount < maxTLSDrain && peek[0] >= 0x14 && peek[0] <= 0x17 && peek[1] <= 0x04 {
				tlsLen := int(peek[3])<<8 | int(peek[4])

				if _, err := reader.Discard(5); err != nil {
					m.handleReadError(mc, err)
					return
				}

				if tlsLen > 0 {
					isWrappedFrame := false

					if peek[0] == 0x17 {
						tlsPayload := make([]byte, tlsLen)
						if _, err := io.ReadFull(reader, tlsPayload); err != nil {
							m.handleReadError(mc, err)
							return
						}

						processBuf := tlsPayload
						for layer := 0; layer < 5; layer++ {
							if len(processBuf) >= FrameHeaderSize {
								pLen := binary.BigEndian.Uint32(processBuf[4:8])
								fType := processBuf[2]

								if fType <= 0x0A && int(pLen) <= 65535 && FrameHeaderSize+int(pLen) <= len(processBuf) {
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
											break
										}

										if fType == 0x00 {
											offset += frameTotal
											continue
										}

										frameData := processBuf[offset : offset+frameTotal]

										m.UpdateActivity()

										b := buf.NewSize(len(frameData))
										b.Write(frameData)
										select {
										case m.readCh <- b:
											atomic.AddUint64(&m.bytesDown, uint64(len(frameData)))
										case <-mc.closing:
											b.Release()
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
									processBuf = processBuf[5 : 5+innerLen]
									continue
								}
							}
						}

						if isWrappedFrame {
							consecutiveGarbage = 0
							continue
						}

						if len(tlsPayload) > 0 {
							headerPeek := tlsPayload
							if len(headerPeek) > 16 {
								headerPeek = headerPeek[:16]
							}
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
							go m.Reconnect(m.Context())
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

		if _, err := io.ReadFull(reader, header); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				mc.SetReadDeadline(time.Now().Add(m.config.KeepaliveInterval * 2))
				continue
			}
			m.handleReadError(mc, err)
			return
		}

		payloadLen := binary.BigEndian.Uint32(header[4:8])

		if payloadLen > 131072 {
			foundOffset := -1
			for i := 1; i <= FrameHeaderSize-3; i++ {
				if header[i] >= 0x14 && header[i] <= 0x17 && header[i+1] == 0x03 && header[i+2] <= 0x04 {
					foundOffset = i
					break
				}
			}

			if foundOffset != -1 {
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
		b := buf.NewSize(needed)
		frameData := b.Extend(needed)

		copy(frameData, header)

		if payloadLen > 0 {
			if _, err := io.ReadFull(reader, frameData[FrameHeaderSize:]); err != nil {
				b.Release()
				m.handleReadError(mc, err)
				return
			}
		}

		if len(frameData) >= 3 && frameData[2] == 0x07 {
			now := time.Now()
			m.lastPong = now
			var rttMs float64
			if !m.lastKeepalive.IsZero() {
				rtt := now.Sub(m.lastKeepalive)
				m.updateQualityRTT(rtt)
				rttMs = float64(rtt.Milliseconds())
			}
			atomic.StoreInt32(&m.missedKAs, 0)
			if m.kaAgent != nil || m.jitterAgent != nil {
				quality := math.Max(0, 1.0-rttMs/500.0)
				if m.kaAgent != nil {
					m.kaAgent.RecordOutcome(quality)
				}
				if m.jitterAgent != nil {
					m.jitterAgent.RecordOutcome(quality)
				}
			}
			b.Release()
			continue
		}

		if len(frameData) >= 3 && frameData[2] == FrameTypeRekey {
			m.lastPong = time.Now()
			b.Release()
			continue
		}

		m.lastPong = time.Now()

		streamID := binary.BigEndian.Uint16(frameData[0:2])

		ch, exists := m.streamLoad(streamID)

		if exists {
			select {
			case ch <- b:
				atomic.AddUint64(&m.bytesDown, uint64(len(frameData)))
				m.feedScale(len(frameData))
				m.UpdateActivity()
			default:
				b.Release()
			}
		} else {
			select {
			case m.readCh <- b:
				atomic.AddUint64(&m.bytesDown, uint64(len(frameData)))
				m.feedScale(len(frameData))
				m.UpdateActivity()
			case <-mc.closing:
				b.Release()
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
		m.sm.SetError(err)
		if m.GetState() == StateConnected {
			go m.Reconnect(m.Context())
		}
	}
}

func (m *Manager) Receive(dst []byte) (int, error) {
	packet, ok := <-m.readCh
	if !ok {
		return 0, fmt.Errorf("tunnel closed")
	}
	data := packet.Bytes()
	if len(data) > len(dst) {
		log.Error("Receive buffer too small for packet (%d > %d)", len(data), len(dst))
		packet.Release()
		return 0, fmt.Errorf("buffer too small")
	}
	n := copy(dst, data)
	packet.Release()
	return n, nil
}

func (m *Manager) OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	for {
		m.connMu.RLock()
		pool := m.activePool
		done := m.reconnectDone
		m.connMu.RUnlock()

		if len(pool) > 0 {
			break
		}

		if atomic.LoadInt32(&m.reconnecting) == 0 {
			return nil, fmt.Errorf("not connected")
		}

		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.connMu.RLock()
	pool := m.activePool
	m.connMu.RUnlock()

	if len(pool) == 0 {
		return nil, fmt.Errorf("not connected")
	}

	var sess *mux.Session
	var onClose func()
	if proto == protoUDP && m.config.EnableChameleon {
		if gs, gerr := m.gameSession(ctx); gerr == nil {
			sess, onClose = gs, m.gameStreamClosed
		}
	}
	if sess == nil {
		healthy := m.healthyPool(pool)
		if len(healthy) == 0 {
			healthy = pool
		}
		mc := healthy[0]
		if len(healthy) > 1 {
			minStreams := mc.session.NumStreams()
			for i := 1; i < len(healthy); i++ {
				n := healthy[i].session.NumStreams()
				if n < minStreams {
					minStreams = n
					mc = healthy[i]
				}
			}
		}
		sess = mc.session
	}

	stream, err := sess.OpenStream()
	if err != nil {
		if onClose != nil {
			onClose()
		}
		return nil, fmt.Errorf("open stream: %w", err)
	}
	m.lastPong = time.Now()

	var proxyStream net.Conn = stream

	addrBytes := []byte(addr)
	header := make([]byte, 1+2+len(addrBytes)+2)
	header[0] = proto
	binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
	copy(header[3:], addrBytes)
	binary.BigEndian.PutUint16(header[3+len(addrBytes):], port)

	if _, err := proxyStream.Write(header); err != nil {
		stream.Close()
		if onClose != nil {
			onClose()
		}
		return nil, fmt.Errorf("write connect header: %w", err)
	}

	return &ackStripConn{Conn: proxyStream, stream: stream, onClose: onClose}, nil
}

func (c *ackStripConn) Read(b []byte) (int, error) {
	c.once.Do(func() {
		c.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		var ack [1]byte
		if _, err := io.ReadFull(c.Conn, ack[:]); err != nil {
			c.ackErr = fmt.Errorf("read connect response: %w", err)
			return
		}
		c.Conn.SetReadDeadline(time.Time{})
		if ack[0] != 0x00 {
			c.ackErr = fmt.Errorf("relay refused connection")
		}
	})
	if c.ackErr != nil {
		return 0, c.ackErr
	}
	return c.Conn.Read(b)
}

func (c *ackStripConn) Close() error {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
		if c.stream != nil && c.stream != c.Conn {
			c.stream.Close()
		}
	})
	return c.Conn.Close()
}

func (m *Manager) Send(data []byte) error {
	if len(data) > 0 {
		neural.GlobalFlowObserver.RecordPacket(len(data))
	}
	if limitKB := atomic.LoadInt32(&m.rateLimitKB); limitKB > 0 && len(data) > 0 {
		limitBPS := int64(limitKB) * 1024
		sleepNs := int64(len(data)) * int64(time.Second) / limitBPS
		if sleepNs > 0 {
			time.Sleep(time.Duration(sleepNs))
		}
	}

	var streamID uint16
	var frameType uint8

	if len(data) >= 8 {
		streamID = binary.BigEndian.Uint16(data[0:2])
		frameType = data[2]
	}

	if m.obfuscator != nil && !m.isTransportSecure && atomic.LoadInt32(&m.transportSecureOverride) == 0 && frameType != FrameTypeData {
		obfuscated, delay, err := m.obfuscator.Process(data, interfaces.DirectionOutbound)
		if err != nil {
			return fmt.Errorf("outbound obfuscation failed: %w", err)
		}
		if obfuscated != nil {
			data = obfuscated
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	const maxRetries = 10
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		var targetConn *managedConn

		var conn *managedConn
		if frameType == FrameTypeConnect || frameType == FrameTypeClose {
			m.connMu.Lock()
			targetConn = m.activeConn
			if frameType == FrameTypeConnect {
				if len(m.activePool) > 0 {
					idx := streamID % uint16(len(m.activePool))
					selected := m.activePool[idx]
					if selected != nil {
						m.streamConns[streamID] = selected
						targetConn = selected
					} else {
						m.streamConns[streamID] = m.activeConn
					}
				} else if m.activeConn != nil {
					m.streamConns[streamID] = m.activeConn
				}
			} else {
				if c, ok := m.streamConns[streamID]; ok {
					targetConn = c
				}
				delete(m.streamConns, streamID)
			}
			conn = targetConn
			m.connMu.Unlock()
		} else {
			m.connMu.RLock()
			if c, ok := m.streamConns[streamID]; ok {
				conn = c
			} else {
				conn = m.activeConn
			}
			m.connMu.RUnlock()
		}

		if conn == nil {
			state := m.GetState()
			if state == StateReconnecting || state == StateRotating || state == StateConnecting {
				if frameType == FrameTypeData {
					return fmt.Errorf("not connected")
				}
				delay := m.getReconnectDelay()
				time.Sleep(delay)
				continue
			}
			return fmt.Errorf("not connected")
		}

		n, err := conn.Write(data)
		if err != nil {
			lastErr = err

			isClosed := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || isConnResetOrBroken(err)

			if isClosed {
				if frameType == FrameTypeData {
					return err
				}

				state := m.GetState()

				if state == StateConnected {
					m.handleReadError(conn, err)
				}

				state = m.GetState()
				if state == StateReconnecting || state == StateRotating || state == StateConnecting {
					time.Sleep(500 * time.Millisecond)
					continue
				}
			}
			return err
		}

		atomic.AddUint64(&m.bytesUp, uint64(n))
		m.feedScale(n)
		m.UpdateActivity()
		return nil
	}

	return fmt.Errorf("send failed after %d retries: %w", maxRetries, lastErr)
}

func (m *Manager) monitorDrainingConn(mc *managedConn) {
	const pollInterval = 5 * time.Second
	const minGrace = 30 * time.Second

	hardDeadline := time.Now().Add(m.config.DrainingTimeout)
	graceUntil := time.Now().Add(minGrace)

	for {
		now := time.Now()
		if now.After(hardDeadline) {
			break
		}

		if now.After(graceUntil) {
			active := 0
			for _, c := range m.streamConns {
				if c == mc {
					active++
				}
			}
			if active == 0 {
				break
			}
		}

		select {
		case <-mc.closing:
			goto closeNow
		case <-time.After(pollInterval):
			return
		}
	}

closeNow:
	m.connMu.Lock()
	for i, c := range m.drainingConns {
		if c == mc {
			m.drainingConns = append(m.drainingConns[:i], m.drainingConns[i+1:]...)
			break
		}
	}
	for sid, c := range m.streamConns {
		if c == mc {
			delete(m.streamConns, sid)
		}
	}
	m.connMu.Unlock()

	mc.Close()
}

func (m *Manager) startConnRateSampler() {
	if !m.config.EnableChameleon {
		return
	}
	m.stopConnRateSampler()
	stop := make(chan struct{})
	m.rateSamplerStop = stop
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			m.sampleConnRates()
		}
	}()
}

func (m *Manager) stopConnRateSampler() {
	if m.rateSamplerStop != nil {
		select {
		case <-m.rateSamplerStop:
		default:
			close(m.rateSamplerStop)
		}
		m.rateSamplerStop = nil
	}
}

func (m *Manager) sampleConnRates() {
	m.connMu.RLock()
	pool := append([]*managedConn(nil), m.activePool...)
	m.connMu.RUnlock()

	nowNs := time.Now().UnixNano()
	for _, mc := range pool {
		if mc == nil || mc.session == nil {
			continue
		}
		_, _, rx, tx := mc.session.Stats()
		bytes := rx + tx
		prevBytes := mc.lastSampledBytes.Load()
		prevNs := mc.lastSampleNs.Load()
		mc.lastSampledBytes.Store(bytes)
		mc.lastSampleNs.Store(nowNs)
		if prevNs == 0 {
			continue
		}
		elapsedNs := nowNs - prevNs
		if elapsedNs <= 0 {
			continue
		}
		delta := int64(bytes) - int64(prevBytes)
		if delta < 0 {
			delta = 0
		}
		mbps := float64(delta) * 8 / (float64(elapsedNs) / 1e9) / 1e6
		mc.rateMbpsX100.Store(int64(mbps * 100))
	}
}

func (m *Manager) healthyPool(pool []*managedConn) []*managedConn {
	if len(pool) <= 1 {
		return pool
	}
	rates := make([]int64, 0, len(pool))
	for _, mc := range pool {
		r := mc.rateMbpsX100.Load()
		if r > 0 {
			rates = append(rates, r)
		}
	}
	if len(rates) == 0 {
		return pool
	}
	sortInt64(rates)
	median := rates[len(rates)/2]
	threshold := median * 30 / 100
	if threshold < 200 {
		threshold = 200
	}

	healthy := make([]*managedConn, 0, len(pool))
	for _, mc := range pool {
		r := mc.rateMbpsX100.Load()
		if r == 0 || r >= threshold {
			healthy = append(healthy, mc)
		}
	}
	return healthy
}

func sortInt64(a []int64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

func (m *Manager) startConnAgent() {
	m.stopConnAgent()
	if m.connAgent == nil {
		return
	}
	if m.config.EnableChameleon {
		return
	}
	stop := make(chan struct{})
	m.connAgentStop = stop
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()
}

func (m *Manager) stopConnAgent() {
	if m.connAgentStop != nil {
		select {
		case <-m.connAgentStop:
		default:
			close(m.connAgentStop)
		}
		m.connAgentStop = nil
	}
}

const (
	chScaleGrowPerConn   = 1.0 * 1024 * 1024
	chScaleShrinkPerConn = 256 * 1024
	chScaleMaxConns      = 256
	scaleEvalBytes       = 2 * 1024 * 1024
	browserConnBudget    = 2
	chGameLaneReserve    = 1
	gameIdleTimeout      = 15 * time.Second
	protoTCP             = 0x06
	protoUDP             = 0x11
)

func (m *Manager) chameleonDial() (func(context.Context) (net.Conn, error), bool) {
	if !m.config.EnableChameleon || len(m.config.ChameleonSecret) == 0 {
		return nil, false
	}
	addr := m.config.ChameleonAddr
	if addr == "" {
		addr = m.config.ServerAddr
	}
	sni := m.config.ChameleonSNI
	var sniList []string
	if sni == "" || net.ParseIP(sni) != nil {
		sni = ""
		sniList = asnbypass.WhitelistSNIPool()
	}
	var tcpDialer func(context.Context, string, string) (net.Conn, error)
	if m.asnBypassDialer != nil {
		tcpDialer = m.asnBypassDialer.DialTCP
	}
	cCfg := &protocol.ClientConfig{
		ServerAddr:    addr,
		ServerName:    sni,
		ServerNames:   sniList,
		SharedSecret:  m.config.ChameleonSecret,
		ServerCertPin: m.config.ChameleonCertPin,
		SessionCache:  m.chameleonSessionCache,
		TCPDialer:     tcpDialer,
		EnableQUIC:    m.config.ChameleonQUICAddr != "",
		QUICAddr:      m.config.ChameleonQUICAddr,
	}
	return func(ctx context.Context) (net.Conn, error) {
		return protocol.Client(ctx, cCfg)
	}, true
}

func (m *Manager) gameDial() func(context.Context) (net.Conn, error) {
	if d, ok := m.chameleonDial(); ok {
		return d
	}
	return nil
}

type gameLane struct {
	mu   sync.Mutex
	sess *mux.Session
	conn net.Conn
	refs int
	idle *time.Timer
}

func (m *Manager) gameSession(ctx context.Context) (*mux.Session, error) {
	dial := m.gameDial()
	if dial == nil {
		return nil, fmt.Errorf("game lane: no chameleon dial")
	}
	g := &m.gameLn
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.idle != nil {
		g.idle.Stop()
		g.idle = nil
	}
	if g.sess != nil && !g.sess.IsClosed() {
		g.refs++
		return g.sess, nil
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	sess, err := mux.Client(conn, m.getMuxConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}
	g.conn = conn
	g.sess = sess
	g.refs = 1
	return sess, nil
}

func (m *Manager) gameLaneActive() bool {
	g := &m.gameLn
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.refs > 0
}

func (m *Manager) gameStreamClosed() {
	g := &m.gameLn
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refs > 0 {
		g.refs--
	}
	if g.refs == 0 && g.sess != nil && g.idle == nil {
		g.idle = time.AfterFunc(gameIdleTimeout, func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.idle = nil
			if g.refs == 0 && g.sess != nil {
				g.sess.Close()
				if g.conn != nil {
					g.conn.Close()
				}
				g.sess = nil
				g.conn = nil
			}
		})
	}
}

func (m *Manager) feedScale(n int) {
	if n <= 0 || !m.config.EnableChameleon {
		return
	}
	sum := atomic.AddUint64(&m.scaleAccBytes, uint64(n))
	if sum >= scaleEvalBytes && atomic.CompareAndSwapUint64(&m.scaleAccBytes, sum, 0) {
		m.evalScale()
	}
}

func (m *Manager) evalScale() {
	m.scaleMu.Lock()
	now := time.Now()
	last := m.scaleLastEval
	m.scaleLastEval = now
	m.scaleMu.Unlock()
	if last.IsZero() {
		return
	}
	dt := now.Sub(last).Seconds()
	if dt <= 0 {
		return
	}
	rate := float64(scaleEvalBytes) / dt

	m.connMu.RLock()
	poolSize := len(m.activePool)
	m.connMu.RUnlock()
	if poolSize == 0 {
		return
	}
	base := m.config.ChameleonMux
	if base < 1 {
		base = 16
	}

	perConn := rate / float64(poolSize)

	switch {
	case perConn >= chScaleGrowPerConn:
		if atomic.LoadInt32(&m.chScaleOpening) != 0 {
			return
		}
		grow := poolSize / 4
		if grow < 1 {
			grow = 1
		}

		atomic.StoreInt32(&m.chScaleOpening, int32(grow))
		for i := 0; i < grow; i++ {
			safeGo("chScaleOpen", func() {
				defer atomic.AddInt32(&m.chScaleOpening, -1)
				_, cancel := context.WithTimeout(context.Background(), m.config.ConnectionTimeout)
				defer cancel()
			})
		}
	case perConn < chScaleShrinkPerConn && poolSize > base:
		if m.closeIdlePoolConn(base) {
		}
	}
}

func (m *Manager) closeIdlePoolConn(base int) bool {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	if len(m.activePool) <= base {
		return false
	}
	inUse := make(map[*managedConn]int, len(m.streamConns))
	for _, c := range m.streamConns {
		inUse[c]++
	}
	for i := len(m.activePool) - 1; i >= 0; i-- {
		c := m.activePool[i]
		if c == m.activeConn || inUse[c] > 0 {
			continue
		}
		m.activePool = append(m.activePool[:i], m.activePool[i+1:]...)
		m.drainingConns = append(m.drainingConns, c)
		go m.monitorDrainingConn(c)
		return true
	}
	return false
}

func (m *Manager) GetState() TunnelState { return m.sm.Get() }

func (m *Manager) IsConnected() bool { return m.sm.IsConnected() }

func (m *Manager) GetSessionID() uint32 { return m.sessionID }

func (m *Manager) OnStateChange(callback func(TunnelState)) { m.onStateChange = callback }

func (m *Manager) setState(state TunnelState) { m.sm.Set(state) }

func (m *Manager) setError(err error) {
	m.sm.SetError(err)
	m.SetHealthy(false, err.Error())
}

func (m *Manager) onStateTransition(old, new TunnelState) {
	if m.onStateChange != nil {
		m.onStateChange(new)
	}
	m.PublishEvent("tunnel.state_changed", map[string]interface{}{
		"old_state": old.String(),
		"new_state": new.String(),
	})
	if m.obfuscator != nil {
		type connActiveSet interface{ SetConnectionActive(bool) }
		if setter, ok := m.obfuscator.(connActiveSet); ok {
			setter.SetConnectionActive(new == StateConnected)
		}
	}
}

func (m *Manager) DialStream(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial stream: invalid addr %q: %w", addr, err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port == 0 {
		return nil, fmt.Errorf("dial stream: invalid port in %q", addr)
	}

	proto := byte(protoTCP)
	if network == "udp" {
		proto = protoUDP
	}

	return m.OpenStream(ctx, proto, host, port)
}

type StreamConn struct {
	streamID  uint16
	manager   *Manager
	readCh    chan *buf.Buffer
	readBuf   []byte
	done      chan struct{}
	closeOnce sync.Once
	local     net.Addr
	remote    net.Addr
}

func (s *StreamConn) Read(b []byte) (n int, err error) {
	if len(s.readBuf) > 0 {
		n = copy(b, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}
	select {
	case frame, ok := <-s.readCh:
		if !ok {
			return 0, io.EOF
		}
		data := frame.Bytes()
		if len(data) <= FrameHeaderSize {
			frame.Release()
			return 0, nil
		}
		payload := data[FrameHeaderSize:]
		n = copy(b, payload)
		if n < len(payload) {
			s.readBuf = append(s.readBuf[:0], payload[n:]...)
		}
		frame.Release()
		return n, nil
	case <-s.done:
		return 0, io.EOF
	}
}

func (s *StreamConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	frameLen := FrameHeaderSize + len(b)
	fb := buf.NewSize(frameLen)
	frame := fb.Extend(frameLen)
	binary.BigEndian.PutUint16(frame[0:2], s.streamID)
	frame[2] = 0x02
	frame[3] = 0x00
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(b)))
	copy(frame[8:], b)
	sendErr := s.manager.Send(frame)
	fb.Release()
	if sendErr != nil {
		return 0, sendErr
	}
	return len(b), nil
}

func (s *StreamConn) Close() error {
	s.closeOnce.Do(func() {
		s.manager.streamDelete(s.streamID)
		close(s.done)
	})

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

	go func() {
		for {
			rttMs := float64(atomic.LoadInt64(&m.qualityRTTEWMA)) / 1e6
			missed := int(atomic.LoadInt32(&m.missedKAs))
			kaView := neural.KeepaliveView{RTTMs: rttMs, MissedKAs: missed}

			base := m.config.KeepaliveInterval
			if m.kaAgent != nil {
				base = m.kaAgent.Decide(kaView)
			}

			jitterFrac := 0.30
			if m.jitterAgent != nil {
				jitterFrac = m.jitterAgent.Decide(neural.JitterView{
					RTTMs: rttMs, MissedKAs: missed,
				})
			}

			jitter := time.Duration(float64(base) * jitterFrac * (2*mrand.Float64() - 1))
			timer := time.NewTimer(base + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				m.sendKeepalive()
			}
		}
	}()
}

func (m *Manager) stopKeepalive() {
	if m.keepaliveCancel != nil {
		m.keepaliveCancel()
	}
}

func (m *Manager) sendKeepalive() {
	if !m.lastPong.IsZero() && m.GetState() == StateConnected {
		silentDuration := time.Since(m.lastPong)
		maxSilence := 90 * time.Second
		if silentDuration > maxSilence {
			go m.Reconnect(m.Context())
			return
		}

		if !m.lastKeepalive.IsZero() && m.lastPong.Before(m.lastKeepalive) {
			missed := atomic.AddInt32(&m.missedKAs, 1)
			if m.kaAgent != nil {
				m.kaAgent.RecordOutcome(0)
			}
			if m.jitterAgent != nil {
				m.jitterAgent.RecordOutcome(0)
			}
			threshold := m.config.QualityMissedKeepalives
			if threshold > 0 && int(missed) >= threshold {
				atomic.StoreInt32(&m.missedKAs, 0)
				go m.Reconnect(m.Context())
				return
			}
		}

		halfInterval := m.config.KeepaliveInterval / 2
		if halfInterval > 0 && silentDuration < halfInterval {
			m.lastKeepalive = time.Now()
			atomic.StoreInt32(&m.missedKAs, 0)
			return
		}
	}

	pingFrame := make([]byte, 8)
	pingFrame[2] = 0x06

	sendTimeout := m.config.KeepaliveInterval
	if sendTimeout <= 0 {
		sendTimeout = 30 * time.Second
	}
	done := make(chan error, 1)
	go func() { done <- m.Send(pingFrame) }()

	select {
	case err := <-done:
		if err != nil {
			if m.GetState() == StateConnected {
				go m.Reconnect(m.Context())
			}
		} else {
			m.lastKeepalive = time.Now()
		}
	case <-time.After(sendTimeout):
		if m.GetState() == StateConnected {
			go m.Reconnect(m.Context())
		}
	}
}
