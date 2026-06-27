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
	"whispera/core/killswitch"
	"whispera/neural"
)

var log = logger.Module("tunnel")

var _ interfaces.Module = (*Manager)(nil)

type ackStripConn struct {
	net.Conn
	stream    net.Conn
	once      sync.Once
	ackErr    error
	onClose   func()
	onAckFail func()
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

type WhisperaOptions struct {
	EnableWhispera   bool
	WhisperaAddr     string
	WhisperaSNI      string
	WhisperaSecret   []byte
	WhisperaCertPin  string
	WhisperaQUICAddr string
	WhisperaMux      int

	EnableGRPC     bool
	GRPCAddr       string
	GRPCServerName string
	GRPCUseTLS     bool

	EnableYaDisk     bool
	YaDiskOAuthToken string
	YaDiskSessionID  string
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
	PSK                  []byte
	DisableNeural        bool
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

	WhisperaOptions
	MLOptions

	BehavioralProfile string

	ServerList []string

	Regions         map[string][]string
	PreferredRegion string

	RekeyInterval time.Duration

	TransportConfig map[string]interface{}

	ForceObfuscation bool

	CustomDialFn func(ctx context.Context) (net.Conn, error)

	CustomSNI   string
	NoSNI       bool
	RateLimitKB int

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

	keepalive *keepaliveController
	rotation  *rotationManager

	reconnectAttempts uint32
	reconnecting      int32
	bytesUp           uint64
	bytesDown         uint64
	lastKeepalive     int64
	lastPong          int64
	connectedAt       time.Time

	reconnectDone chan struct{}

	onStateChange func(TunnelState)

	killSwitch killSwitchController

	obfuscator        interfaces.Obfuscator
	asnBypassDialer   tcpBypassDialer
	isTransportSecure bool

	poolHealth *poolHealthSampler
	rtLane     *rtLaneManager
	ml         *mlOrchestrator

	boFailCount     int32
	boLastSuccessAt int64
	boLastErrType   int32
	tlsErrStreak    int32

	goroutineLimiter *base.GoroutineLimiter

	connCfg connConfig

	lastGoodMu         sync.RWMutex
	lastGoodSNI        string
	lastGoodTransport  string
	lastGoodServerAddr string

	qualityRTTEWMA int64
	missedKAs      int32
}

func (m *Manager) getMuxConfig() *mux.Config {
	base := 8 + mrand.Intn(7)

	frameSize := 65535
	if m.ml.chunkAgent != nil {
		rttMs := float64(atomic.LoadInt64(&m.qualityRTTEWMA)) / 1e6
		upBytes := float64(atomic.LoadUint64(&m.bytesUp))
		dnBytes := float64(atomic.LoadUint64(&m.bytesDown))
		frameSize = m.ml.chunkAgent.Decide(neural.ChunkView{
			RTTMs:      rttMs,
			BytesUpSec: upBytes / 60.0,
			BytesDnSec: dnBytes / 60.0,
		})
	}

	recvBuf, streamBuf := muxBufferBudget()
	return &mux.Config{
		MaxFrameSize:         frameSize,
		MaxReceiveBuffer:     recvBuf,
		MaxStreamBuffer:      streamBuf,
		KeepAliveInterval:    time.Duration(base) * time.Second,
		KeepAliveTimeout:     24 * time.Hour,
		MaxConcurrentStreams: 256,
	}
}

func muxBufferBudget() (recv, stream int) {
	lim := debug.SetMemoryLimit(-1)
	if lim <= 0 || lim >= math.MaxInt64/2 {
		return 1 << 25, 1 << 23
	}
	recv = int(lim / 8)
	if recv > 1<<26 {
		recv = 1 << 26
	}
	if recv < 1<<22 {
		recv = 1 << 22
	}
	return recv, recv / 4
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
		Module:           base.NewModule(ModuleName, ModuleVersion, []string{"handshake.handler"}),
		config:           cfg,
		streamConns:      make(map[uint16]*managedConn),
		readCh:           make(chan *buf.Buffer, 4096),
		goroutineLimiter: base.NewGoroutineLimiter(1024),
		reconnectDone:    make(chan struct{}),
	}
	m.connCfg.forceObfuscation.Store(forceObfs)
	m.keepalive = newKeepaliveController(m)
	m.rotation = newRotationManager(m)
	m.poolHealth = newPoolHealthSampler(m)
	m.rtLane = newRTLaneManager(m)
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

	m.ml = newMLOrchestrator(m, cfg.SNIModelDir, !cfg.DisableNeural)

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
		m.connCfg.SetRateLimitKB(cfg.RateLimitKB)
	}

	if cfg.EnableIPSpoof && len(cfg.SpoofSourceIPs) > 0 {
		m.connCfg.SetSpoofIPs(cfg.SpoofSourceIPs)
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

	return m.connectInternal(ctx, false)
}

func (m *Manager) connectInternal(ctx context.Context, isRotation bool) error {
	if !isRotation {
		m.setState(StateConnecting)
	} else {
		m.setState(StateRotating)
	}

	targetPoolSize := 2
	if m.config.EnableWhispera {
		targetPoolSize = 1
	}
	var connectedPool []*managedConn
	var poolMu sync.Mutex
	firstConnReady := make(chan *managedConn, 1)
	firstConnErr := make(chan error, targetPoolSize)

	spawnConnection := func(idx int) {
		dialCtx, dialCancel := context.WithTimeout(ctx, m.config.ConnectionTimeout)
		defer dialCancel()
		mc, err := m.dialManagedConn(dialCtx, fmt.Sprintf("pool-%d-%d", time.Now().Unix(), idx))
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
			if idx > 0 && m.config.EnableWhispera {
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
		m.startConnRateSampler()
		m.connectedAt = time.Now()
		atomic.StoreInt64(&m.lastPong, time.Now().UnixNano())
		m.setState(StateConnected)

		m.connMu.RLock()
		sniSnapshot := m.rotation.currentSNI
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
			m.rotation.currentSNI = zeroRTTSNI
			if zeroRTTTransport != "" {
				m.config.Transport = zeroRTTTransport
			}
		} else {
			m.rotation.currentSNI = ""
		}
		m.connMu.Unlock()

		dialStart := time.Now()
		var err error
		if attempts == 1 && zeroRTTSNI != "" {
			err = m.connectInternal(ctx, false)
		} else {
			err = m.Connect(ctx)
		}
		dialLatency := float64(time.Since(dialStart).Milliseconds())
		if err == nil {
			if m.ml.boAgent != nil {
				m.ml.boAgent.RecordOutcome(true)
			}
			if m.ml.serverAgent != nil {
				m.ml.serverAgent.RecordOutcome(true, dialLatency)
			}
			atomic.StoreInt32(&m.boFailCount, 0)
			atomic.StoreInt64(&m.boLastSuccessAt, time.Now().Unix())
			m.circuitBreakerSuccess()
			if transportFallbackActivated {
				m.config.Transport = originalTransport
			}
			return nil
		}

		if m.ml.tspuDetector != nil {
			errStr := err.Error()
			dialDur := time.Duration(dialLatency) * time.Millisecond
			if strings.Contains(errStr, "reset") {
				m.ml.tspuDetector.RecordRST(m.rotation.currentSNI, dialDur)
			}
			if dpiType, conf := m.ml.tspuDetector.DetectTSPU(); dpiType != neural.DPITypeNone && conf >= 0.65 {
				if cm := neural.TSPUCountermeasure(dpiType); cm != "" && cm != m.config.Transport {
					m.config.Transport = cm
				}
			}
		}
		failCount := atomic.AddInt32(&m.boFailCount, 1)
		if m.ml.boAgent != nil {
			m.ml.boAgent.RecordOutcome(false)
		}
		if m.ml.serverAgent != nil {
			m.ml.serverAgent.RecordOutcome(false, dialLatency)
		}
		m.circuitBreakerFail()

		var backoffDelay time.Duration
		if m.ml.boAgent != nil {
			errStr := ""
			lastSuc := atomic.LoadInt64(&m.boLastSuccessAt)
			secSince := 0.0
			if lastSuc > 0 {
				secSince = float64(time.Now().Unix() - lastSuc)
			}
			backoffDelay = m.ml.boAgent.Decide(neural.BackoffView{
				ConsecutiveFails:    int(failCount),
				LastErrType:         neural.ClassifyBackoffErr(errStr),
				TimeSinceSuccessSec: secSince,
			})
		} else {
			backoffDelay = delay
		}
		delay = time.Duration(float64(delay) * 2)
		if delay > m.config.ReconnectMaxDelay {
			delay = m.config.ReconnectMaxDelay
		}
		if backoffDelay < delay {
			backoffDelay = delay
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
	if m.obfuscator != nil && !m.isTransportSecure && m.connCfg.TransportSecureOverride() == 0 {
		inputReader = &deobfuscatingReader{r: mc, obf: m.obfuscator}
	}
	reader := bufio.NewReaderSize(inputReader, 262144)

	var headerArr [FrameHeaderSize]byte
	header := headerArr[:]
	tlsDrainCount := 0
	consecutiveGarbage := 0
	const maxTLSDrain = 50


	for {
		select {
		case <-mc.closing:
			return
		default:
		}

		if !m.isTransportSecure || m.connCfg.ForceObfuscation() != 0 {
			peek, err := reader.Peek(5)
			if err != nil {
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
				m.handleReadError(mc, fmt.Errorf("resync failed: no embedded TLS header found"))
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
			atomic.StoreInt64(&m.lastPong, now.UnixNano())
			var rttMs float64
			if ka := atomic.LoadInt64(&m.lastKeepalive); ka != 0 {
				rtt := now.Sub(time.Unix(0, ka))
				m.updateQualityRTT(rtt)
				rttMs = float64(rtt.Milliseconds())
			}
			atomic.StoreInt32(&m.missedKAs, 0)
			if m.ml.kaAgent != nil || m.ml.jitterAgent != nil {
				quality := math.Max(0, 1.0-rttMs/500.0)
				if m.ml.kaAgent != nil {
					m.ml.kaAgent.RecordOutcome(quality)
				}
				if m.ml.jitterAgent != nil {
					m.ml.jitterAgent.RecordOutcome(quality)
				}
			}
			b.Release()
			continue
		}

		if len(frameData) >= 3 && frameData[2] == FrameTypeRekey {
			atomic.StoreInt64(&m.lastPong, time.Now().UnixNano())
			b.Release()
			continue
		}

		atomic.StoreInt64(&m.lastPong, time.Now().UnixNano())

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
		log.Warn("active connection read error (%v) — forcing reconnect", err)
		m.sm.SetError(err)
		go m.Reconnect(m.Context())
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
	var mcForFail *managedConn
	if proto == protoUDP && m.config.EnableWhispera {
		if gs, gerr := m.rtSession(ctx); gerr == nil {
			sess, onClose = gs, m.rtStreamClosed
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
		mcForFail = mc

		const openStreamFreshnessWindow = 5 * time.Second
		const openStreamProbeTimeout = 3 * time.Second
		lastPong := atomic.LoadInt64(&m.lastPong)
		if lastPong == 0 || time.Since(time.Unix(0, lastPong)) > openStreamFreshnessWindow {
			alive := false
			for attempt := 0; attempt < 2 && !alive; attempt++ {
				alive = m.keepalive.probeNow(openStreamProbeTimeout)
			}
			if !alive {
				if onClose != nil {
					onClose()
				}
				m.forceReconnectFromStreamFailure(mc, "liveness probe timed out")
				return nil, fmt.Errorf("tunnel unresponsive")
			}
		}
	}

	stream, err := sess.OpenStream()
	if err != nil {
		if onClose != nil {
			onClose()
		}
		if mcForFail != nil {
			m.forceReconnectFromStreamFailure(mcForFail, "open stream: "+err.Error())
		}
		return nil, fmt.Errorf("open stream: %w", err)
	}

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
		if mcForFail != nil {
			m.forceReconnectFromStreamFailure(mcForFail, "write connect header: "+err.Error())
		}
		return nil, fmt.Errorf("write connect header: %w", err)
	}

	return &ackStripConn{
		Conn:    proxyStream,
		stream:  stream,
		onClose: onClose,
		onAckFail: func() {
			if mcForFail != nil {
				m.forceReconnectFromStreamFailure(mcForFail, "connect ack timeout")
			}
		},
	}, nil
}

func (m *Manager) forceReconnectFromStreamFailure(mc *managedConn, reason string) {
	m.connMu.RLock()
	isActive := (mc == m.activeConn)
	m.connMu.RUnlock()
	if isActive && m.GetState() == StateConnected {
		log.Warn("stream failure (%s) — forcing reconnect", reason)
		m.sm.SetError(fmt.Errorf("stream failure: %s", reason))
		go m.Reconnect(m.Context())
	}
}

const (
	rtStreamAliveMarker byte = 0x02
	rtConnectOK         byte = 0x00
)

const (
	streamAliveWait = 1 * time.Second
	connectAckWait  = 17 * time.Second
)

func (c *ackStripConn) Read(b []byte) (int, error) {
	c.once.Do(func() {
		c.Conn.SetReadDeadline(time.Now().Add(streamAliveWait))
		var marker [1]byte
		if _, err := io.ReadFull(c.Conn, marker[:]); err != nil {
			c.ackErr = fmt.Errorf("read stream-alive marker: %w", err)
			if c.onAckFail != nil {
				c.onAckFail()
			}
			return
		}

		c.Conn.SetReadDeadline(time.Now().Add(connectAckWait))
		var ack [1]byte
		if _, err := io.ReadFull(c.Conn, ack[:]); err != nil {
			c.ackErr = fmt.Errorf("read connect response: %w", err)
			return
		}
		c.Conn.SetReadDeadline(time.Time{})
		if ack[0] != rtConnectOK {
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
	if limitKB := m.connCfg.rateLimitKB.Load(); limitKB > 0 && len(data) > 0 {
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

	if m.obfuscator != nil && !m.isTransportSecure && m.connCfg.TransportSecureOverride() == 0 && frameType != FrameTypeData {
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
			m.connMu.RLock()
			for _, c := range m.streamConns {
				if c == mc {
					active++
				}
			}
			m.connMu.RUnlock()
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

func (m *Manager) startConnRateSampler() { m.poolHealth.start() }

func (m *Manager) stopConnRateSampler() { m.poolHealth.stop() }

func (m *Manager) healthyPool(pool []*managedConn) []*managedConn { return m.poolHealth.healthy(pool) }

const (
	chScaleShrinkPerConn = 256 * 1024
	scaleEvalBytes       = 2 * 1024 * 1024
	browserConnBudget    = 2
	chRTLaneReserve      = 1
	rtIdleTimeout        = 15 * time.Second
	protoTCP             = 0x06
	protoUDP             = 0x11
)

func (m *Manager) rtDial() func(context.Context) (net.Conn, error) { return m.rtLane.dial() }

func (m *Manager) rtSession(ctx context.Context) (*mux.Session, error) {
	return m.rtLane.session(ctx)
}

func (m *Manager) rtLaneActive() bool { return m.rtLane.active() }

func (m *Manager) rtStreamClosed() { m.rtLane.streamClosed() }

func (m *Manager) feedScale(n int) { m.rtLane.feedScale(n) }

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

func (m *Manager) startKeepalive() { m.keepalive.start() }

func (m *Manager) stopKeepalive() { m.keepalive.stop() }
