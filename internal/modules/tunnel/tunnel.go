package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
	"whispera/internal/core/base"
	whisperdns "whispera/internal/dns"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"
	"whispera/internal/modules/killswitch"
	"whispera/internal/modules/phantom"
	"whispera/internal/modules/transport"
	asnbypass "whispera/internal/modules/transport/asn_bypass"
	"whispera/internal/modules/transport/chameleon"
	"whispera/internal/modules/transport/domainfront"
	grpc_transport "whispera/internal/modules/transport/grpc"
	h2c_transport "whispera/internal/modules/transport/h2c"
	"whispera/internal/modules/transport/httpupgrade"
	"whispera/internal/modules/transport/meek"
	"whispera/internal/modules/transport/mirage"
	"whispera/internal/modules/transport/mtproto"
	"whispera/internal/modules/transport/obfs4"
	"whispera/internal/modules/transport/okwebrtc"
	quic_transport "whispera/internal/modules/transport/quic"
	"whispera/internal/modules/transport/shadowsocks"
	shadowtls_transport "whispera/internal/modules/transport/shadowtls"
	splithttp_transport "whispera/internal/modules/transport/splithttp"
	"whispera/internal/modules/transport/tgbot"
	"whispera/internal/modules/transport/snowflake"
	"whispera/internal/modules/transport/torsocks"
	tuic_transport "whispera/internal/modules/transport/tuic"
	"whispera/internal/modules/transport/vkbot"
	"whispera/internal/modules/transport/vkwebrtc"
	ws_transport "whispera/internal/modules/transport/websocket"
	"whispera/internal/modules/transport/yacloud"
	"whispera/internal/modules/transport/yadisk"
	"whispera/internal/modules/transport/yatelemost"
	"whispera/internal/mux"
	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/obfuscation/marionette"
	mlpkg "whispera/internal/obfuscation/ml"
	"whispera/internal/obfuscation/russian"
)

var log = logger.Module("tunnel")

var dohResolver = whisperdns.NewResolver(whisperdns.DefaultConfig())

func dohDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 10 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				ips, err := dohResolver.Resolve(ctx, strings.Split(address, ":")[0])
				if err != nil || len(ips) == 0 {
					return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
				}
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, ips[0].String()+":53")
			},
		},
	}
}

var mlHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
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
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 66048)
	},
}

func isConnResetOrBroken(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		msg := opErr.Err.Error()
		return strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset")
	}
	return false
}

func isHandshakeError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "handshake") ||
		strings.Contains(s, "tls") ||
		strings.Contains(s, "certificate") ||
		strings.Contains(s, "x509")
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "timeout") ||
		strings.Contains(s, "deadline exceeded") ||
		strings.Contains(s, "i/o timeout")
}

// ClassifyConnError returns a concise, human-readable reason for a connection
// failure — suitable for display in client logs or UI.
func ClassifyConnError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return "сервер недоступен (порт закрыт)"
	case strings.Contains(s, "no route to host"), strings.Contains(s, "network unreachable"):
		return "нет маршрута до сервера"
	case strings.Contains(s, "connection reset"):
		return "соединение сброшено (DPI или firewall)"
	case strings.Contains(s, "broken pipe"):
		return "соединение оборвалось"
	case strings.Contains(s, "timeout"), strings.Contains(s, "i/o timeout"):
		return "превышено время ожидания"
	case strings.Contains(s, "handshake"):
		return "ошибка TLS-рукопожатия (возможно DPI)"
	case strings.Contains(s, "certificate"), strings.Contains(s, "x509"):
		return "ошибка сертификата"
	case strings.Contains(s, "EOF"):
		return "соединение закрыто сервером"
	case strings.Contains(s, "context canceled"):
		return "отменено"
	case strings.Contains(s, "context deadline exceeded"):
		return "превышен дедлайн подключения"
	case strings.Contains(s, "too many open files"):
		return "достигнут лимит файловых дескрипторов"
	default:
		return s
	}
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

	EnablePhantom       bool
	PhantomSNI          string
	PhantomShortId      string
	PhantomServerPubKey string
	PhantomPSK          []byte

	// Chameleon — invisible HTTPS transport with GRU traffic shaping.
	// Enabled by default when SharedSecret is non-empty and no other transport is forced.
	EnableChameleon   bool
	ChameleonAddr     string // host:port of chameleon server (defaults to ServerAddr)
	ChameleonSNI      string // TLS SNI (defaults to ChameleonAddr host)
	ChameleonSecret   []byte // 32-byte pre-shared secret derived from user key

	EnableChatFSM        bool
	ChatFSMCoverInterval time.Duration

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

	// Regions maps region codes (ru/eu/us/cn) to server address lists.
	// When PreferredRegion is set (non-empty, non-"auto"), only that region's
	// servers are considered during latency probing.
	Regions         map[string][]string
	PreferredRegion string

	RekeyInterval time.Duration

	TransportConfig map[string]interface{}

	ForceObfuscation bool

	CustomDialFn func(ctx context.Context) (net.Conn, error)

	DesyncConfig    *evasion.DesyncConfig
	FlowTableConfig *evasion.FlowTableConfig

	MLServerURL string

	MLToken string

	// SNIModelDir — путь для сохранения rl_sni_policy.json. Пустая строка = не сохранять.
	SNIModelDir string
	// SNIDomainsURL — URL plain-text списка доменов (один на строку) для авто-обновления SNI-пула каждые 24ч.
	SNIDomainsURL string

	CustomSNI string
	NoSNI     bool
	BridgeAddr  string
	RateLimitKB int

	EnableIPSpoof  bool
	SpoofSourceIPs []string

	TLSFragmentSize int

	// ForceSNI overrides the SNI sent in the TLS ClientHello for all transports,
	// regardless of phantom or ASN-bypass settings.
	// Takes priority over PhantomSNI and DomainFrontHost.
	ForceSNI string

	// Connection quality failover thresholds.
	// QualityThresholdRTT: trigger reconnect when EWMA RTT exceeds this (0 = disabled).
	QualityThresholdRTT time.Duration
	// QualityMissedKeepalives: trigger reconnect after N consecutive pongs missed (0 = disabled).
	QualityMissedKeepalives int
}

func DefaultConfig() *Config {
	return &Config{
		KeepaliveInterval:    15 * time.Second,
		ReconnectInterval:    5 * time.Second,
		ReconnectMaxDelay:    60 * time.Second,
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
		c.ReconnectInterval = 5 * time.Second
	}
	if c.ReconnectMaxDelay <= 0 {
		c.ReconnectMaxDelay = 60 * time.Second
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
	session      *mux.Session
	id           string
	createdAt    time.Time
	maxAge       time.Duration // rotate after this duration (45-120s for Chameleon)
	maxUploadB   int64         // rotate after this many bytes uploaded (0 = disabled)
	uploadBytes  int64         // atomic: bytes written to this connection
	closing      chan struct{}
	closeOnce    sync.Once
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

	keepaliveCancel context.CancelFunc
	rotationTicker  *time.Ticker
	rotationCancel  context.CancelFunc
	rekeyTicker     *time.Ticker
	rekeyCancel     context.CancelFunc

	streamIdx         uint32
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
	phantomAuth       *phantom.ClientAuth
	isTransportSecure bool

	transportSecureOverride int32
	forceObfuscation        int32

	russianSNIs   []string
	russianSNIsMu sync.RWMutex
	currentSNI    string
	lastRotation  time.Time
	sniAgent           *mlpkg.RLSNIAgent
	connAgent          *mlpkg.RLConnAgent
	connAgentStop      chan struct{}
	transportAgent     *mlpkg.RLTransportAgent
	kaAgent            *mlpkg.RLKeepaliveAgent
	boAgent            *mlpkg.RLBackoffAgent
	jitterAgent        *mlpkg.RLJitterAgent
	serverAgent        *mlpkg.RLServerAgent
	chunkAgent         *mlpkg.RLChunkAgent
	tlsAgent           *mlpkg.RLTLSAgent
	tspuDetector       *mlpkg.TSPUDetector

	// для backoff-агента
	boFailCount     int32 // atomic: consecutive reconnect failures
	boLastSuccessAt int64 // atomic: unix seconds of last successful connect
	boLastErrType   int32 // atomic: BackoffErrType
	// для tls-агента
	tlsErrStreak int32 // atomic: consecutive TLS handshake failures

	russianTunneler *russian.RussianTunneler

	cbMu          sync.Mutex
	cbFailures    int
	cbLastFailure time.Time
	cbState       string

	goroutineLimiter *base.GoroutineLimiter

	rateLimitKB     int32
	tlsFragmentSize int32

	spoofIPs    []string
	spoofIdx    uint64

	fedSyncOnce sync.Once

	// last-good cache for 0-RTT reconnect fast path
	lastGoodMu         sync.RWMutex
	lastGoodSNI        string
	lastGoodTransport  string
	lastGoodServerAddr string

	// connection quality metrics
	qualityRTTEWMA int64 // atomic, nanoseconds; EWMA of ping→pong RTT
	missedKAs      int32 // atomic; consecutive keepalives with no pong response

	chameleonSessionCache any
}

func (m *Manager) getMuxConfig() *mux.Config {
	base := 30 + mrand.Intn(61)

	frameSize := 65535
	if m.chunkAgent != nil {
		rttMs := float64(atomic.LoadInt64(&m.qualityRTTEWMA)) / 1e6
		upBytes := float64(atomic.LoadUint64(&m.bytesUp))
		dnBytes := float64(atomic.LoadUint64(&m.bytesDown))
		frameSize = m.chunkAgent.Decide(mlpkg.ChunkView{
			RTTMs:      rttMs,
			BytesUpSec: upBytes / 60.0, // грубая оценка: всего байт / 60с
			BytesDnSec: dnBytes / 60.0,
		})
	}

	return &mux.Config{
		MaxFrameSize:         frameSize,
		MaxReceiveBuffer:     512 * 1024 * 1024,
		MaxStreamBuffer:      2 * 1024 * 1024,
		KeepAliveInterval:    time.Duration(base) * time.Second,
		KeepAliveTimeout:     90 * time.Second,
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
		state:                 StateDisconnected,
		streamConns:           make(map[uint16]*managedConn),
		readCh:                make(chan []byte, 4096),
		streamChs:             make(map[uint16]chan []byte),
		goroutineLimiter:      base.NewGoroutineLimiter(1024),
		reconnectDone:         make(chan struct{}),
		forceObfuscation:      forceObfs,
		chameleonSessionCache: chameleon.NewSessionCache(16),
	}
	close(m.reconnectDone)

	if cfg.EnableASNBypass || cfg.EnablePhantom || cfg.ForceSNI != "" {
		frontDomain := cfg.DomainFrontHost
		enableSNIMask := false

		if cfg.EnablePhantom && cfg.PhantomSNI != "" {
			frontDomain = cfg.PhantomSNI
			enableSNIMask = true
		}
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
			ConnectionBurstLimit:   5,
			ConnectionCooldown:     2 * time.Second,
			FailoverTimeout:        cfg.ConnectionTimeout,
			FallbackStrategies:     []asnbypass.Strategy{asnbypass.StrategyTLSMasquerade, asnbypass.StrategyDomainFronting},
		}

		if cfg.EnablePhantom {
			asnConfig.Strategy = asnbypass.StrategyTLSMasquerade
			asnConfig.FallbackStrategies = nil
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

	// RL SNI агент — учится какие домены работают лучше в данном регионе/ISP.
	sniPool := m.russianSNIs
	if len(sniPool) == 0 {
		sniPool = defaultSNIPool
	}
	m.sniAgent = mlpkg.NewRLSNIAgent(cfg.SNIModelDir, sniPool)
	log.Info("RL SNI agent initialized (pool=%d, eps=%.2f)", len(sniPool), m.sniAgent.Epsilon())
	if cfg.SNIDomainsURL != "" {
		m.sniAgent.StartAutoFetch(cfg.SNIDomainsURL)
		log.Info("RL SNI agent auto-fetch started: %s", cfg.SNIDomainsURL)
	}

	m.connAgent = mlpkg.NewRLConnAgent()
	log.Info("RL Conn agent initialized")

	m.transportAgent = mlpkg.NewRLTransportAgent(cfg.SNIModelDir, nil)
	log.Info("RL Transport agent initialized (eps=%.2f)", m.transportAgent.Epsilon())

	m.kaAgent = mlpkg.NewRLKeepaliveAgent()
	m.boAgent = mlpkg.NewRLBackoffAgent()
	m.jitterAgent = mlpkg.NewRLJitterAgent()
	m.serverAgent = mlpkg.NewRLServerAgent()
	m.chunkAgent = mlpkg.NewRLChunkAgent()
	m.tlsAgent = mlpkg.NewRLTLSAgent()
	m.tspuDetector = mlpkg.NewTSPUDetector()
	log.Info("RL agents initialized: keepalive, backoff, jitter, server, chunk, tls, tspu")

	// Периодически экспортируем веса в глобальный снапшот.
	// Сервер отдаёт его через /api/ml/weights; клиент тянет при первом подключении.
	go m.runWeightSnapshotLoop()

	if cfg.CustomSNI != "" {
		if cfg.TransportConfig == nil {
			cfg.TransportConfig = make(map[string]interface{})
		}
		if _, exists := cfg.TransportConfig["sni"]; !exists {
			cfg.TransportConfig["sni"] = cfg.CustomSNI
		}
	}

	if cfg.BridgeAddr != "" && cfg.CustomDialFn == nil {
		bridgeAddr := cfg.BridgeAddr
		serverAddr := cfg.ServerAddr
		cfg.CustomDialFn = func(ctx context.Context) (net.Conn, error) {
			d := &net.Dialer{}
			conn, err := d.DialContext(ctx, "tcp", bridgeAddr)
			if err != nil {
				return nil, fmt.Errorf("bridge dial %s: %w", bridgeAddr, err)
			}
			req := "CONNECT " + serverAddr + " HTTP/1.1\r\nHost: " + serverAddr + "\r\n\r\n"
			if _, err = conn.Write([]byte(req)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("bridge CONNECT write: %w", err)
			}
			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("bridge CONNECT read: %w", err)
			}
			if n < 12 || string(buf[9:12]) != "200" {
				conn.Close()
				return nil, fmt.Errorf("bridge rejected CONNECT: %s", string(buf[:n]))
			}
			return conn, nil
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

	safeGo("Reconnect", func() { m.Reconnect(m.Context()) })

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
		if best := m.pickServer(ctx); best != "" {
			m.config.ServerAddrTCP = best
			m.config.ServerAddr = best
		}
	}

	if m.config.MLServerURL != "" {
		m.mlStartFederatedSync(ctx)
		m.mlStartTransportWatchdog(ctx)
		if rec, conf := m.mlRecommendTransport(ctx); rec != "" && conf >= 0.55 {
			m.config.Transport = rec
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

	targetPoolSize := 2
	var connectedPool []*managedConn
	var poolMu sync.Mutex

	firstConnReady := make(chan *managedConn, 1)
	firstConnErr := make(chan error, targetPoolSize)

	log.Info("[%s] Spawning pool of %d connections (lazy mode)...", op, targetPoolSize)

	spawnConnection := func(idx int) {
		mc, err := m.dialManagedConn(ctx, fmt.Sprintf("pool-%d-%d", start.Unix(), idx))
		if err != nil {
			log.Warn("[%s] Failed to dial connection %d: %v", op, idx, err)
			select {
			case firstConnErr <- err:
			default:
			}
			return
		}

		poolMu.Lock()
		isFirst := len(connectedPool) == 0
		if isFirst && m.handshake != nil {
			// sessionID уже установлен внутри dialManagedConn при handshake
		}
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

	for i := 0; i < targetPoolSize; i++ {
		go spawnConnection(i)
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
			// Rotation timed out — old connection is still active; restore state.
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
		m.startConnAgent()
		m.connectedAt = time.Now()
		m.lastPong = time.Now()
		m.setState(StateConnected)

		// Cache last-good params for 0-RTT reconnect fast path.
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
		log.Info("[%s] Rotation complete.", op)
	}

	return nil
}

type dialCandidate struct {
	name   string
	secure bool
	fn     func(context.Context) (net.Conn, error)
}

func (m *Manager) spoofDialer() *net.Dialer {
	if len(m.spoofIPs) == 0 {
		return dohDialer()
	}
	idx := atomic.AddUint64(&m.spoofIdx, 1) % uint64(len(m.spoofIPs))
	localIP := m.spoofIPs[idx]
	if !strings.Contains(localIP, ":") {
		localIP = localIP + ":0"
	}
	localAddr, err := net.ResolveTCPAddr("tcp", localIP)
	if err != nil {
		return dohDialer()
	}
	return &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   10 * time.Second,
		Resolver:  dohDialer().Resolver,
	}
}

// dialManagedConn набирает одно полностью готовое соединение (dial → desync → handshake → mux)
// и возвращает готовый *managedConn. Используется как в connectInternal, так и в openPoolConn.
func (m *Manager) dialManagedConn(ctx context.Context, id string) (*managedConn, error) {
	// TLS-агент выбирает fingerprint профиль до dial.
	if m.tlsAgent != nil && m.asnBypassDialer != nil {
		tlsErrors := int(atomic.LoadInt32(&m.tlsErrStreak))
		profile := m.tlsAgent.Decide(mlpkg.TLSView{
			ConsecutiveTLSErrors: tlsErrors,
			TransportName:        m.config.Transport,
			IsPhantom:            m.config.EnablePhantom,
		})
		if profile != "" {
			m.config.TLSFingerprint = profile
		}
	}

	conn, err := m.dial(ctx)
	if err != nil {
		if m.tlsAgent != nil && isHandshakeError(err) {
			atomic.AddInt32(&m.tlsErrStreak, 1)
			m.tlsAgent.RecordOutcome(false)
		}
		return nil, err
	}

	conn = evasion.NewDesyncConn(conn, m.config.DesyncConfig)

	if m.handshake != nil && !m.config.EnablePhantom && !m.config.EnableChameleon {
		sess, err := m.handshake.InitiateHandshake(ctx, conn, conn.RemoteAddr())
		if err != nil {
			conn.Close()
			if m.tlsAgent != nil {
				atomic.AddInt32(&m.tlsErrStreak, 1)
				m.tlsAgent.RecordOutcome(false)
			}
			return nil, fmt.Errorf("handshake: %w", err)
		}
		if sess != nil {
			atomic.StoreUint32(&m.sessionID, sess.ID())
		}
	} else if m.config.EnablePhantom {
		atomic.StoreUint32(&m.sessionID, uint32(time.Now().Unix()&0xFFFFFFFF))
	}

	// Handshake прошёл успешно — сбрасываем счётчик TLS ошибок.
	if m.tlsAgent != nil {
		atomic.StoreInt32(&m.tlsErrStreak, 0)
		m.tlsAgent.RecordOutcome(true)
	}

	paddedConn := mux.NewPaddedConn(conn, 128)
	log.Warn("[dialManagedConn:%s] mux.Client starting", id)
	muxSess, err := mux.Client(paddedConn, m.getMuxConfig())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mux: %w", err)
	}
	log.Warn("[dialManagedConn:%s] mux.Client OK, opening control stream", id)

	stream, err := muxSess.OpenStream()
	if err != nil {
		muxSess.Close()
		return nil, fmt.Errorf("open stream: %w", err)
	}
	log.Warn("[dialManagedConn:%s] control stream opened, managedConn ready", id)

	var controlStream net.Conn = stream
	if m.config.EnablePhantom && !m.config.EnableChameleon {
		controlStream = transport.WrapStreamTLS(stream)
	}

	var maxAge time.Duration
	var maxUploadB int64
	if m.config.EnableChameleon {
		// Time-based rotation: each H2 POST lives 10-20 minutes.
		// Real H2 connections are long-lived; 45-120s was causing reconnect
		// gaps every minute which stalled new stream setup.
		maxAge = time.Duration(10+mrand.Intn(11)) * time.Minute
		// Volume-based rotation: disabled — time-based maxAge is sufficient for PFS.
		// Previous 20-100 MB limit rotated every 0.3-1.6s at 500 Mbps, causing
		// constant connection churn.
		maxUploadB = 0
	}

	return &managedConn{
		Conn:        controlStream,
		session:     muxSess,
		id:          id,
		createdAt:   time.Now(),
		maxAge:      maxAge,
		maxUploadB:  maxUploadB,
		closing:     make(chan struct{}),
	}, nil
}

func (m *Manager) dial(ctx context.Context) (net.Conn, error) {
	if m.config.CustomDialFn != nil {
		return m.config.CustomDialFn(ctx)
	}

	// Chameleon is the preferred transport when enabled — invisible HTTPS with GRU shaping.
	if m.config.EnableChameleon && len(m.config.ChameleonSecret) > 0 {
		addr := m.config.ChameleonAddr
		if addr == "" {
			addr = m.config.ServerAddr
		}
		sni := m.config.ChameleonSNI
		if sni == "" {
			host, _, _ := net.SplitHostPort(addr)
			if host == "" {
				host = addr
			}
			sni = host
		}
		conn, err := chameleon.Client(ctx, &chameleon.Config{
			ServerAddr:   addr,
			ServerName:   sni,
			SharedSecret: m.config.ChameleonSecret,
			SessionCache: m.chameleonSessionCache,
		})
		if err == nil {
			return conn, nil
		}
		log.Warn("chameleon dial failed (%v), falling back to standard transports", err)
	}

	m.preparePhantomASN()
	candidates := m.buildCandidates()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no transport candidates configured")
	}

	dialer := func(dctx context.Context) (net.Conn, error) {
		return m.parallelDial(dctx, candidates)
	}

	if cfg := m.config.FlowTableConfig; cfg != nil && cfg.Enabled {
		return evasion.DialWithFlowTableBypass(ctx, dialer, cfg)
	}

	return dialer(ctx)
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
	if only("mirage") && m.tcfg("secret") != "" {
		cc = append(cc, dialCandidate{"mirage", true, m.dialMirage})
	}
	if only("mtproto") && m.tcfg("mtproto_secret") != "" {
		cc = append(cc, dialCandidate{"mtproto", true, m.dialMTProto})
	}
	if only("snowflake") {
		cc = append(cc, dialCandidate{"snowflake", true, m.dialSnowflake})
	}
	if only("obfs4") && m.tcfg("obfs4_node_id") != "" && m.tcfg("obfs4_public_key") != "" {
		cc = append(cc, dialCandidate{"obfs4", true, m.dialObfs4})
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
		if only("grpc") {
			cc = append(cc, dialCandidate{"grpc", false, m.dialGRPC})
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
		phantomViaASN := m.asnBypassDialer != nil && m.config.EnablePhantom
		if only("tcp") || auto || (m.config.EnablePhantom && !phantomViaASN) {
			cc = append(cc, dialCandidate{"tcp", true, m.dialTCP})
		}
	}

	cc = m.applyTransportPolicy(cc)

	// Сообщаем транспортному агенту какие транспорты реально доступны.
	if m.transportAgent != nil && len(cc) > 0 {
		names := make([]string, len(cc))
		for i, c := range cc {
			names[i] = c.name
		}
		m.transportAgent.SetActivePool(names)
	}

	return cc
}

func (m *Manager) applyTransportPolicy(cc []dialCandidate) []dialCandidate {
	if len(m.config.TransportWhitelist) == 0 && len(m.config.TransportBlacklist) == 0 {
		return cc
	}
	whitelist := make(map[string]bool, len(m.config.TransportWhitelist))
	for _, n := range m.config.TransportWhitelist {
		whitelist[strings.TrimSpace(n)] = true
	}
	blacklist := make(map[string]bool, len(m.config.TransportBlacklist))
	for _, n := range m.config.TransportBlacklist {
		blacklist[strings.TrimSpace(n)] = true
	}
	out := cc[:0]
	for _, c := range cc {
		base := c.name
		if i := strings.IndexByte(base, ':'); i > 0 {
			base = base[:i]
		}
		if len(whitelist) > 0 && !whitelist[base] {
			continue
		}
		if blacklist[base] {
			continue
		}
		out = append(out, c)
	}
	return out
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
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(20 * time.Second)
	}
	return conn, nil
}

func (m *Manager) dialQUIC(ctx context.Context) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", m.config.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("quic resolve: %w", err)
	}
	sni := m.getRotationSNI()
	alpn := m.tcfg("quic_alpn")
	if alpn == "" {
		alpn = "h3"
	}
	qTrans, err := quic_transport.New(&quic_transport.Config{
		ListenAddr:     ":0",
		MaxConns:       1,
		MaxIdleTimeout: m.config.KeepaliveInterval * 3,
		ALPN:           alpn,
		ServerName:     sni,
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
	conn, err := h2cTrans.Dial(ctx, m.config.ServerAddrTCP)
	if err != nil {
		return nil, err
	}
	if m.config.EnablePhantom && m.phantomAuth != nil {
		sni := m.getRotationSNI()
		if err := m.phantomAuth.WrapConn(conn, sni); err != nil {
			conn.Close()
			return nil, fmt.Errorf("phantom wrap h2c: %w", err)
		}
	}
	return m.wrapChatFSM(conn), nil
}

func (m *Manager) dialTCP(ctx context.Context) (net.Conn, error) {
	conn, err := m.spoofDialer().DialContext(ctx, "tcp4", m.config.ServerAddrTCP)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		// OS-level keepalives keep NAT mappings alive on mobile (15-30 min NAT timeout).
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(20 * time.Second)
	}
	if m.config.EnablePhantom && m.phantomAuth != nil {
		sni := m.getRotationSNI()
		if err := m.phantomAuth.WrapConn(conn, sni); err != nil {
			conn.Close()
			return nil, fmt.Errorf("phantom wrap: %w", err)
		}
	}
	return m.wrapChatFSM(conn), nil
}

func (m *Manager) wrapChatFSM(conn net.Conn) net.Conn {
	if !m.config.EnableChatFSM {
		return conn
	}
	interval := m.config.ChatFSMCoverInterval
	if interval <= 0 {
		interval = 8 * time.Second
	}
	var chatID [4]byte
	_, _ = rand.Read(chatID[:])
	return marionette.NewChatFSMConn(conn, binary.BigEndian.Uint32(chatID[:]), interval)
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
		ServerAddr:        m.config.ServerAddr,
		SNI:               m.config.PhantomSNI,
		UUID:              "00000000000000000000000000000000",
		CongestionControl: "bbr",
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialWebSocket(ctx context.Context) (net.Conn, error) {
	path := m.tcfg("ws_path")
	if path == "" {
		path = "/ws"
	}
	host := m.tcfg("ws_host") // optional CDN-fronting Host header
	subproto := m.tcfg("ws_subprotocol")
	if subproto == "" {
		subproto = "" // no subprotocol = harder to fingerprint than "whispera"
	}
	useTLS := m.tcfg("ws_tls") == "true" || m.tcfg("ws_tls") == "1"

	target := m.config.ServerAddrTCP
	if host != "" {
		// CDN fronting: connect to target (CDN IP) but send Host: host
		target = m.config.ServerAddrTCP
	}

	tr, err := ws_transport.New(&ws_transport.Config{
		ListenAddr:  ":0",
		Path:        path,
		Subprotocol: subproto,
		HostOverride: host,
		UseTLS:      useTLS,
		ServerName:  m.tcfg("ws_sni"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, target)
}

func (m *Manager) dialGRPC(ctx context.Context) (net.Conn, error) {
	serverName := m.tcfg("grpc_sni")
	if serverName == "" {
		serverName = m.tcfg("sni")
	}
	useTLS := m.tcfg("grpc_tls") != "false" // TLS on by default

	tr, err := grpc_transport.New(&grpc_transport.Config{
		ListenAddr:  ":0",
		ServiceName: m.tcfg("grpc_service"),
		UseTLS:      useTLS,
		ServerName:  serverName,
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
	mode := m.tcfg("front_mode")
	if mode == "" {
		mode = "websocket"
	}
	wsPath := m.tcfg("front_ws_path")
	if wsPath == "" {
		wsPath = "/ws"
	}
	tr, err := domainfront.New(&domainfront.Config{
		FrontDomain:  m.tcfg("front_domain"),
		TargetDomain: m.tcfg("target_domain"),
		Mode:         mode,
		WSPath:       wsPath,
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

func (m *Manager) dialMirage(ctx context.Context) (net.Conn, error) {
	host, portStr, _ := net.SplitHostPort(m.config.ServerAddr)
	port := 443
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}
	tr, err := mirage.New(&mirage.Config{
		Secret:       m.tcfg("secret"),
		TargetServer: host,
		TargetPort:   port,
		SNI:          m.tcfg("mirage_sni"),
		Fingerprint:  m.tcfg("mirage_fingerprint"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialMTProto(ctx context.Context) (net.Conn, error) {
	tr, err := mtproto.New(&mtproto.Config{
		Secret:      m.tcfg("mtproto_secret"),
		EnableFakeTLS: m.tcfg("mtproto_faketls") != "false",
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialSnowflake(ctx context.Context) (net.Conn, error) {
	cfg := snowflake.DefaultConfig()
	if v := m.tcfg("snowflake_broker"); v != "" {
		cfg.BrokerURL = v
	}
	if v := m.tcfg("snowflake_stun"); v != "" {
		cfg.STUNServer = v
	}
	if v := m.tcfg("snowflake_front"); v != "" {
		cfg.FrontDomain = v
	}
	tr, err := snowflake.New(cfg)
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) dialObfs4(ctx context.Context) (net.Conn, error) {
	tr, err := obfs4.New(&obfs4.Config{
		NodeID:    m.tcfg("obfs4_node_id"),
		PublicKey: m.tcfg("obfs4_public_key"),
	})
	if err != nil {
		return nil, err
	}
	return tr.Dial(ctx, m.config.ServerAddr)
}

func (m *Manager) selectNewSNI() string {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	return m.selectNewSNILocked()
}

var defaultSNIPool = []string{
	"kion.ru",
	"rutube.ru",
	"vk.com",
	"ok.ru",
	"dzen.ru",
	"music.yandex.ru",
	"cloud.mail.ru",
	"premier.one",
	"wink.ru",
	"ivi.ru",
	"start.ru",
	"more.tv",
}

func (m *Manager) selectNewSNILocked() string {
	pool := m.russianSNIs
	if len(pool) == 0 {
		pool = defaultSNIPool
	}
	if len(pool) == 0 {
		m.currentSNI = m.config.PhantomSNI
		return m.currentSNI
	}

	if m.sniAgent != nil {
		// Строим состояние: без реального RTT на этом этапе используем нули,
		// агент всё равно учится на реальных результатах через RecordOutcome.
		state := m.sniAgent.EncodeState(0, 0, 0, false, 0)
		domain, _ := m.sniAgent.Select(state)
		if domain != "" {
			m.currentSNI = domain
			m.lastRotation = time.Now()
			log.Info("[ROTATION EVENT] RL SNI agent selected: %s (eps=%.2f)",
				m.currentSNI, m.sniAgent.Epsilon())
			return m.currentSNI
		}
	}

	// Fallback: crypto/rand (если агент не инициализирован)
	idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	if err != nil {
		m.currentSNI = pool[0]
	} else {
		m.currentSNI = pool[idxBig.Int64()]
	}
	m.lastRotation = time.Now()
	log.Info("[ROTATION EVENT] Selected new SNI: %s (fallback crypto/rand)", m.currentSNI)
	return m.currentSNI
}

func (m *Manager) getRotationSNI() string {
	if m.config.NoSNI {
		return ""
	}

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
	m.stopConnAgent()

	m.connMu.Lock()

	for _, c := range m.activePool {
		c.closeOnce.Do(func() { close(c.closing) })
		c.session.Close()
		c.Close()
	}
	m.activePool = nil
	m.activeConn = nil

	for _, c := range m.drainingConns {
		c.closeOnce.Do(func() { close(c.closing) })
		c.session.Close()
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
		log.Warn("Circuit breaker OPEN - skipping reconnect attempt")
		return fmt.Errorf("circuit breaker open")
	}

	m.setState(StateReconnecting)
	delay := m.config.ReconnectInterval
	attempts := 0

	const fallbackAfterAttempts = 3
	originalTransport := m.config.Transport
	transportFallbackActivated := false

	// Snapshot last-good params before the loop modifies config.
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
			log.Warn("Transport fallback: %d failures on '%s', switching to auto (racing all transports)",
				fallbackAfterAttempts, originalTransport)
		}

		m.Disconnect()

		m.connMu.Lock()
		if attempts == 1 && zeroRTTSNI != "" {
			// 0-RTT fast path: reuse last-good SNI and transport, skip ML round-trip.
			m.currentSNI = zeroRTTSNI
			if zeroRTTTransport != "" {
				m.config.Transport = zeroRTTTransport
			}
			log.Info("0-RTT reconnect: using last-good SNI=%s transport=%s", zeroRTTSNI, zeroRTTTransport)
		} else {
			m.currentSNI = ""
		}
		m.connMu.Unlock()

		dialStart := time.Now()
		usedTransport := m.config.Transport
		var err error
		if attempts == 1 && zeroRTTSNI != "" {
			// Fast path: bypass ML recommendations and server racing.
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
				log.Info("Transport fallback: connection restored, reverting to '%s'", originalTransport)
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
		if m.tspuDetector != nil && err != nil {
			errStr := err.Error()
			dialDur := time.Duration(dialLatency) * time.Millisecond
			if strings.Contains(errStr, "reset") {
				m.tspuDetector.RecordRST(m.currentSNI, dialDur)
			} else if isTimeoutError(err) {
				// Timeout after a full dial attempt — probe TCP to check for zombie-TCP.
				// Run async so we don't add latency to the retry loop.
				sni := m.currentSNI
				addr := m.config.ServerAddr
				detector := m.tspuDetector
				go func() {
					tcpStart := time.Now()
					probeCtx, probeCancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer probeCancel()
					c, tcpErr := (&net.Dialer{}).DialContext(probeCtx, "tcp", addr)
					tcpDur := time.Since(tcpStart)
					if tcpErr == nil {
						c.Close()
						// TCP succeeded → DPI passes L4 but drops TLS payload → zombie-TCP.
						detector.RecordZombieTCP(sni, tcpDur, dialDur)
					}
				}()
			}
			// After recording, check if we should switch transport based on TSPU pattern.
			if dpiType, conf := m.tspuDetector.DetectTSPU(); dpiType != mlpkg.DPITypeNone && conf >= 0.65 {
				if cm := mlpkg.TSPUCountermeasure(dpiType); cm != "" && cm != m.config.Transport {
					log.Warn("[TSPU] %s detected (conf=%.2f) → switching transport: %s → %s",
						mlpkg.DPITypeName(dpiType), conf, m.config.Transport, cm)
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
		log.Warn("Reconnect attempt %d failed (transport=%s): %s", attempts, m.config.Transport, ClassifyConnError(err))
		m.circuitBreakerFail()

		// Backoff-агент выбирает задержку; fallback на exponential backoff если агент не готов.
		var backoffDelay time.Duration
		if m.boAgent != nil {
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			lastSuc := atomic.LoadInt64(&m.boLastSuccessAt)
			secSince := 0.0
			if lastSuc > 0 {
				secSince = float64(time.Now().Unix() - lastSuc)
			}
			backoffDelay = m.boAgent.Decide(mlpkg.BackoffView{
				ConsecutiveFails:    int(failCount),
				LastErrType:         mlpkg.ClassifyBackoffErr(errStr),
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
	oldTransport := m.config.Transport
	newSNI := m.selectNewSNI()
	log.Info("Initiating Seamless SNI Rotation to: %s", newSNI)

	if m.config.MLServerURL != "" {
		if rec, conf := m.mlRecommendTransport(m.Context()); rec != "" && conf >= 0.55 && rec != oldTransport {
			log.Info("[ML-Rotate] Transport switch during SNI rotation: %s → %s (confidence=%.2f)", oldTransport, rec, conf)
			m.config.Transport = rec
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.connectInternal(ctx, true); err != nil {
		log.Error("SNI Rotation failed: %v - keeping existing connection", err)

		m.connMu.Lock()
		m.currentSNI = oldSNI
		m.connMu.Unlock()
		m.config.Transport = oldTransport
		// connectInternal sets StateRotating before dialing; restore on failure.
		m.setState(StateConnected)

		if m.config.MLServerURL != "" {
			go m.mlSendFeedback(m.config.Transport, false, 0)
		}
		return
	}

	if m.config.MLServerURL != "" {
		go m.mlSendFeedback(m.config.Transport, true, 0)
	}
	log.Info("SNI Rotation complete. Old connections will drain gracefully.")
}

func (m *Manager) readLoop(mc *managedConn) {
	defer mc.Close()

	var inputReader io.Reader = mc
	if m.obfuscator != nil && atomic.LoadInt32(&m.transportSecureOverride) == 0 {
		inputReader = &deobfuscatingReader{r: mc, obf: m.obfuscator}
	}
	reader := bufio.NewReaderSize(inputReader, 262144)

	var headerArr [FrameHeaderSize]byte
	header := headerArr[:]
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

		if !m.isTransportSecure || atomic.LoadInt32(&m.forceObfuscation) != 0 {
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

										frameData := processBuf[offset : offset+frameTotal]

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
			now := time.Now()
			m.lastPong = now
			var rttMs float64
			if !m.lastKeepalive.IsZero() {
				rtt := now.Sub(m.lastKeepalive)
				m.updateQualityRTT(rtt)
				rttMs = float64(rtt.Milliseconds())
			}
			atomic.StoreInt32(&m.missedKAs, 0)
			log.Debug("Received PONG from server (RTT=%v)", time.Since(m.lastKeepalive))
			// Положительный сигнал агентам keepalive и jitter.
			if m.kaAgent != nil || m.jitterAgent != nil {
				quality := math.Max(0, 1.0-rttMs/500.0)
				if m.kaAgent != nil {
					m.kaAgent.RecordOutcome(quality)
				}
				if m.jitterAgent != nil {
					m.jitterAgent.RecordOutcome(quality)
				}
			}
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
			go m.Reconnect(m.Context())
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
	log.Warn("[OpenStream] called: %s:%d (proto=0x%02x)", addr, port, proto)
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

	idx := atomic.AddUint32(&m.streamIdx, 1) % uint32(len(pool))
	mc := pool[idx]

	stream, err := mc.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	m.lastPong = time.Now()

	var proxyStream net.Conn = stream
	if m.config.EnablePhantom && !m.config.EnableChameleon {
		proxyStream = transport.WrapStreamTLS(stream)
	}

	addrBytes := []byte(addr)
	header := make([]byte, 1+2+len(addrBytes)+2)
	header[0] = proto
	binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
	copy(header[3:], addrBytes)
	binary.BigEndian.PutUint16(header[3+len(addrBytes):], port)

	if _, err := proxyStream.Write(header); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write connect header: %w", err)
	}

	resp := make([]byte, 1)
	if _, err := io.ReadFull(proxyStream, resp); err != nil {
		stream.Close()
		return nil, fmt.Errorf("read connect response: %w", err)
	}
	if resp[0] != 0x00 {
		stream.Close()
		return nil, fmt.Errorf("relay refused connection")
	}

	return proxyStream, nil
}

func (m *Manager) Send(data []byte) error {
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

	if m.obfuscator != nil && atomic.LoadInt32(&m.transportSecureOverride) == 0 && frameType != FrameTypeData {
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

		m.connMu.Lock()
		targetConn = m.activeConn
		if len(data) >= 8 {
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
		}
		conn := targetConn
		m.connMu.Unlock()

		if conn == nil {
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

		total := len(data)
		n := 0
		var writeErr error
		var err error

		currentChunkSize := 65536
		const minChunkSize = 16384
		const maxChunkSize = 131072

		if total > currentChunkSize {
			start := 0
			chunkIdx := 0
			for start < total {
				end := start + currentChunkSize
				if end > total {
					end = total
				}

				chunk := data[start:end]

				measure := chunkIdx&3 == 0
				var tStart time.Time
				if measure {
					tStart = time.Now()
				}
				wn, wErr := conn.Write(chunk)

				n += wn
				if wErr != nil {
					writeErr = wErr
					break
				}

				if measure {
					duration := time.Since(tStart)
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
				}

				start += wn
				chunkIdx++
			}
			err = writeErr
		} else {
			n, err = conn.Write(data)
		}
		if err != nil {
			lastErr = err

			isClosed := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || isConnResetOrBroken(err)

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
	const pollInterval = 5 * time.Second
	const minGrace = 30 * time.Second

	hardDeadline := time.Now().Add(m.config.DrainingTimeout)
	graceUntil := time.Now().Add(minGrace)

	reason := "Timeout"
	for {
		now := time.Now()
		if now.After(hardDeadline) {
			break
		}

		if now.After(graceUntil) {
			m.connMu.RLock()
			active := 0
			for _, c := range m.streamConns {
				if c == mc {
					active++
				}
			}
			m.connMu.RUnlock()
			if active == 0 {
				reason = "Idle"
				break
			}
		}

		select {
		case <-mc.closing:
			reason = "RemoteClose"
			goto closeNow
		case <-time.After(pollInterval):
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

	mc.closeOnce.Do(func() { close(mc.closing) })
	mc.session.Close() // closes yamux session → underlying H2 POST → RST_STREAM on server
	mc.Close()
	log.Info("Draining connection closed (%s)", reason)
}

func (m *Manager) startRotation() {
	m.stopRotation()
	if !m.config.EnableRotation {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.rotationCancel = cancel

	// Safety-net: если нейросеть не даёт сигнал долго, всё равно ротируем.
	const safetyInterval = 6 * time.Hour
	log.Info("Starting SNI rotation watchdog (safety interval: %s, RL-agent controls active rotation)", safetyInterval)
	m.rotationTicker = time.NewTicker(safetyInterval)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.rotationTicker.C:
				log.Info("SNI safety-net rotation triggered (no agent signal for %s)", safetyInterval)
				m.RotateSNI()
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

// startConnAgent запускает цикл управления пулом соединений через RL-агента.
// Тикает каждые 15 секунд. Останавливается через stopConnAgent или когда
// пользователь явно вызвал Disconnect() (activePool == nil).
func (m *Manager) startConnAgent() {
	m.stopConnAgent()
	if m.connAgent == nil {
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
				m.connAgentTick()
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

func (m *Manager) connAgentTick() {
	// Агент работает только пока пользователь подключён.
	// Если Disconnect() был вызван явно — activePool == nil, не вмешиваемся.
	if !m.IsConnected() {
		return
	}

	const preWarmBefore = 90 * time.Second

	m.connMu.RLock()
	poolSize := len(m.activePool)
	needsRotation := false
	for _, c := range m.activePool {
		if c.maxAge > 0 && time.Since(c.createdAt) >= c.maxAge-preWarmBefore {
			needsRotation = true
			break
		}
		if c.maxUploadB > 0 {
			_, _, _, tx := c.session.Stats()
			if int64(tx) >= c.maxUploadB {
				needsRotation = true
				break
			}
		}
	}
	m.connMu.RUnlock()

	if poolSize == 0 {
		// Пользователь явно закрыл все соединения — агент не открывает новые.
		return
	}

	if needsRotation {
		log.Info("[connAgent] Chameleon connection reached max age, rotating")
		ctx, cancel := context.WithTimeout(context.Background(), m.config.ConnectionTimeout)
		defer cancel()
		if err := m.connectInternal(ctx, true); err != nil {
			log.Warn("[connAgent] Rotation failed: %v", err)
		}
		return
	}

	rttNs := atomic.LoadInt64(&m.qualityRTTEWMA)
	rttMs := float64(rttNs) / 1e6
	missedKAs := int(atomic.LoadInt32(&m.missedKAs))

	m.cbMu.Lock()
	cbFail := m.cbFailures
	m.cbMu.Unlock()

	errorRate := 0.0
	if cbFail > 0 {
		errorRate = math.Min(float64(cbFail)/10.0, 1.0)
	}

	view := mlpkg.ConnPoolView{
		Size:       poolSize,
		RTTMs:      rttMs,
		ErrorRate:  errorRate,
		MissedKAs:  missedKAs,
		CBFailures: cbFail,
	}

	action := m.connAgent.Decide(view)

	switch action {
	case mlpkg.ConnActionOpen:
		log.Info("[CONN-AGENT] OPEN: adding connection to pool (current=%d)", poolSize)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), m.config.ConnectionTimeout)
			defer cancel()
			if err := m.openPoolConn(ctx); err != nil {
				log.Warn("[CONN-AGENT] OPEN failed: %v", err)
				m.connAgent.RecordOutcome(0.0)
			} else {
				quality := m.connQuality()
				m.connAgent.RecordOutcome(quality)
			}
		}()

	case mlpkg.ConnActionCloseWorst:
		log.Info("[CONN-AGENT] CLOSE_WORST: removing connection from pool (current=%d)", poolSize)
		closed := m.closeWorstPoolConn()
		if closed {
			m.connAgent.RecordOutcome(m.connQuality())
		} else {
			m.connAgent.RecordOutcome(m.connQuality())
		}

	default: // ConnActionKeep
		m.connAgent.RecordOutcome(m.connQuality())
	}
}

// connQuality возвращает текущее качество пула (0-1) для reward агента.
func (m *Manager) connQuality() float64 {
	rttNs := atomic.LoadInt64(&m.qualityRTTEWMA)
	rttMs := float64(rttNs) / 1e6
	rttScore := 1.0 - math.Min(rttMs/500.0, 1.0)

	missed := float64(atomic.LoadInt32(&m.missedKAs))
	kaScore := 1.0 - math.Min(missed/5.0, 1.0)

	quality := (rttScore + kaScore) / 2.0

	// chunk-агент получает обратную связь с каждым тиком connAgentTick.
	if m.chunkAgent != nil {
		upBytes := float64(atomic.LoadUint64(&m.bytesUp))
		dnBytes := float64(atomic.LoadUint64(&m.bytesDown))
		m.chunkAgent.RecordOutcome(quality)
		_ = upBytes
		_ = dnBytes
	}

	return quality
}

// openPoolConn устанавливает одно дополнительное соединение и добавляет его в activePool.
func (m *Manager) openPoolConn(ctx context.Context) error {
	id := fmt.Sprintf("agent-%d", time.Now().UnixNano())
	mc, err := m.dialManagedConn(ctx, id)
	if err != nil {
		return err
	}
	safeGo("readLoop", func() { m.readLoop(mc) })
	m.connMu.Lock()
	m.activePool = append(m.activePool, mc)
	m.connMu.Unlock()
	log.Info("[CONN-AGENT] Pool expanded to %d connections", len(m.activePool))
	return nil
}

// closeWorstPoolConn закрывает самое старое соединение в пуле.
// Возвращает false если pool.Size <= 1 (constraint: ≥1 соединение).
func (m *Manager) closeWorstPoolConn() bool {
	m.connMu.Lock()
	defer m.connMu.Unlock()

	if len(m.activePool) <= 1 {
		return false
	}

	// Worst = самое старое (наибольший возраст → индекс 0 т.к. slice упорядочен по времени добавления).
	worst := m.activePool[0]
	m.activePool = m.activePool[1:]

	// Если это было activeConn — переключаем на следующий.
	if m.activeConn == worst {
		m.activeConn = m.activePool[0]
	}

	m.drainingConns = append(m.drainingConns, worst)
	go m.monitorDrainingConn(worst)

	log.Info("[CONN-AGENT] Pool shrunk to %d connections (closed oldest conn)", len(m.activePool))
	return true
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
	log.Warn("[setState] %v", state)
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
		if m.obfuscator != nil {
			type connActiveSet interface{ SetConnectionActive(bool) }
			if setter, ok := m.obfuscator.(connActiveSet); ok {
				setter.SetConnectionActive(state == StateConnected)
			}
		}
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

	ch := make(chan []byte, 4096)
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
		done:     make(chan struct{}),
		local:    localAddr,
		remote:   remoteAddr,
	}, nil
}

type StreamConn struct {
	streamID  uint16
	manager   *Manager
	readCh    chan []byte
	done      chan struct{}
	closeOnce sync.Once
	local     net.Addr
	remote    net.Addr
}

func (s *StreamConn) Read(b []byte) (n int, err error) {
	select {
	case data, ok := <-s.readCh:
		if !ok {
			return 0, io.EOF
		}
		if len(data) <= FrameHeaderSize {
			return 0, nil
		}
		payload := data[FrameHeaderSize:]
		copy(b, payload)
		return len(payload), nil
	case <-s.done:
		return 0, io.EOF
	}
}

// maxStreamChunk bounds the payload size per tunnel frame. Keeping chunks
// small enough to fit the outer transport MTU avoids IP fragmentation and
// reduces the DPI fingerprint of oversized whispera frames.
const maxStreamChunk = 1300

func (s *StreamConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	total := 0
	for total < len(b) {
		end := total + maxStreamChunk
		if end > len(b) {
			end = len(b)
		}
		chunk := b[total:end]

		frameLen := FrameHeaderSize + len(chunk)
		frame := bufferPool.Get().([]byte)
		if cap(frame) < frameLen {
			frame = make([]byte, frameLen)
		} else {
			frame = frame[:frameLen]
		}

		binary.BigEndian.PutUint16(frame[0:2], s.streamID)
		frame[2] = 0x02
		frame[3] = 0x00
		binary.BigEndian.PutUint32(frame[4:8], uint32(len(chunk)))
		copy(frame[8:], chunk)

		sendErr := s.manager.Send(frame)
		bufferPool.Put(frame[:cap(frame)])
		if sendErr != nil {
			return total, sendErr
		}
		total = end
	}
	return total, nil
}

func (s *StreamConn) Close() error {
	s.closeOnce.Do(func() {
		s.manager.streamChsMu.Lock()
		delete(s.manager.streamChs, s.streamID)
		s.manager.streamChsMu.Unlock()
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
			kaView := mlpkg.KeepaliveView{RTTMs: rttMs, MissedKAs: missed}

			base := m.config.KeepaliveInterval
			if m.kaAgent != nil {
				base = m.kaAgent.Decide(kaView)
			}

			jitterFrac := 0.30 // default ±30%
			if m.jitterAgent != nil {
				jitterFrac = m.jitterAgent.Decide(mlpkg.JitterView{
					RTTMs: rttMs, MissedKAs: missed,
				})
			}

			jitter := time.Duration(float64(base)*jitterFrac*(2*mrand.Float64()-1))
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
		// 90s: enough for a slow network burst, short enough to detect dead NAT
		// mappings before the user notices prolonged outage.
		maxSilence := 90 * time.Second
		if silentDuration > maxSilence {
			log.Warn("No data received in %s (max %s), triggering reconnect", silentDuration, maxSilence)
			go m.Reconnect(m.Context())
			return
		}

		// Count consecutive keepalives that got no pong.
		if !m.lastKeepalive.IsZero() && m.lastPong.Before(m.lastKeepalive) {
			missed := atomic.AddInt32(&m.missedKAs, 1)
			// Отрицательный сигнал агентам keepalive и jitter.
			if m.kaAgent != nil {
				m.kaAgent.RecordOutcome(0)
			}
			if m.jitterAgent != nil {
				m.jitterAgent.RecordOutcome(0)
			}
			threshold := m.config.QualityMissedKeepalives
			if threshold > 0 && int(missed) >= threshold {
				log.Warn("Quality failover: %d consecutive keepalives unanswered, reconnecting", missed)
				atomic.StoreInt32(&m.missedKAs, 0)
				go m.Reconnect(m.Context())
				return
			}
		}

		// If data is actively flowing from the server, the connection is clearly
		// alive — no need to send an explicit ping that would compete with
		// streaming traffic (YouTube, etc.) in the shared yamux write channel.
		halfInterval := m.config.KeepaliveInterval / 2
		if halfInterval > 0 && silentDuration < halfInterval {
			m.lastKeepalive = time.Now()
			atomic.StoreInt32(&m.missedKAs, 0)
			return
		}
	}

	pingFrame := make([]byte, 8)
	pingFrame[2] = 0x06

	// Send in a separate goroutine so a blocked write (dead NAT, full TCP buffer)
	// doesn't stall the keepalive loop and prevent maxSilence from firing.
	sendTimeout := m.config.KeepaliveInterval
	if sendTimeout <= 0 {
		sendTimeout = 30 * time.Second
	}
	done := make(chan error, 1)
	go func() { done <- m.Send(pingFrame) }()

	select {
	case err := <-done:
		if err != nil {
			log.Warn("Keepalive send failed: %v", err)
			if m.GetState() == StateConnected {
				go m.Reconnect(m.Context())
			}
		} else {
			m.lastKeepalive = time.Now()
		}
	case <-time.After(sendTimeout):
		log.Warn("Keepalive send blocked >%s, triggering reconnect", sendTimeout)
		if m.GetState() == StateConnected {
			go m.Reconnect(m.Context())
		}
	}
}

// updateQualityRTT updates the EWMA RTT and triggers failover if above threshold.
func (m *Manager) updateQualityRTT(rtt time.Duration) {
	const alpha = 0.2 // EWMA smoothing factor — weight of new sample
	old := atomic.LoadInt64(&m.qualityRTTEWMA)
	var newEWMA int64
	if old == 0 {
		newEWMA = int64(rtt)
	} else {
		newEWMA = int64(float64(old)*(1-alpha) + float64(rtt)*alpha)
	}
	atomic.StoreInt64(&m.qualityRTTEWMA, newEWMA)

	threshold := m.config.QualityThresholdRTT
	if threshold > 0 && time.Duration(newEWMA) > threshold {
		log.Warn("Quality failover: avg RTT=%v > threshold=%v, triggering reconnect",
			time.Duration(newEWMA), threshold)
		go m.Reconnect(m.Context())
	}
}

// GetQualityMetrics returns current connection quality measurements.
func (m *Manager) GetQualityMetrics() (avgRTT time.Duration, missedKeepalives int) {
	return time.Duration(atomic.LoadInt64(&m.qualityRTTEWMA)),
		int(atomic.LoadInt32(&m.missedKAs))
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
	if rtt := time.Duration(atomic.LoadInt64(&m.qualityRTTEWMA)); rtt > 0 {
		status.Details["quality_rtt_ms"] = rtt.Milliseconds()
		status.Details["quality_missed_kas"] = atomic.LoadInt32(&m.missedKAs)
	}
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

func (m *Manager) mlRecommendTransport(ctx context.Context) (transport string, confidence float64) {
	if m.transportAgent == nil {
		return "", 0
	}
	rttMs := float64(atomic.LoadInt64(&m.qualityRTTEWMA)) / 1e6
	missed := float64(atomic.LoadInt32(&m.missedKAs))
	state := m.transportAgent.EncodeState(
		[4]float64{rttMs, rttMs, rttMs, rttMs},
		0,
		math.Min(missed/5.0, 1.0),
		false,
		0,
		time.Now().Hour(),
		0,
	)
	tr, _ := m.transportAgent.Select(state)
	if tr == "" {
		return "", 0
	}
	return tr, 1.0
}

func (m *Manager) mlSendFeedback(transport string, success bool, latencyMs float64) {
	if transport == "" || m.transportAgent == nil {
		return
	}
	m.transportAgent.RecordOutcome(success, latencyMs)
	if !success && m.transportAgent.ShouldRotate() {
		go m.rotateTransport()
	}
}

func (m *Manager) mlStartTransportWatchdog(ctx context.Context) {
	if m.transportAgent == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rec, _ := m.mlRecommendTransport(ctx)
				if rec == "" || rec == m.config.Transport {
					continue
				}
				log.Info("[RL-Transport] Watchdog: switching %s → %s (eps=%.2f)",
					m.config.Transport, rec, m.transportAgent.Epsilon())
				m.config.Transport = rec
				m.rotateTransport()
			}
		}
	}()
}

func (m *Manager) mlStartFederatedSync(ctx context.Context) {
	if m.config.MLServerURL == "" {
		return
	}
	m.fedSyncOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			m.mlFederatedSync(ctx)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					m.mlFederatedSync(ctx)
				}
			}
		}()
	})
}

func (m *Manager) mlFederatedSync(ctx context.Context) {
	base := m.config.MLServerURL
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}

	dlCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, base+"/federated/download", nil)
	if err != nil {
		return
	}
	if m.config.MLToken != "" {
		req.Header.Set("Authorization", "Bearer "+m.config.MLToken)
	}
	resp, err := mlHTTPClient.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		log.Debug("ML federated: downloaded global delta")
	} else if resp != nil {
		resp.Body.Close()
	}

	ulCtx, ulCancel := context.WithTimeout(ctx, 10*time.Second)
	defer ulCancel()
	uploadBody, _ := json.Marshal(map[string]string{"client_id": "go-client", "data": ""})
	ulReq, err := http.NewRequestWithContext(ulCtx, http.MethodPost,
		base+"/federated/upload", bytes.NewReader(uploadBody))
	if err != nil {
		return
	}
	ulReq.Header.Set("Content-Type", "application/json")
	if m.config.MLToken != "" {
		ulReq.Header.Set("Authorization", "Bearer "+m.config.MLToken)
	}
	ulResp, err := mlHTTPClient.Do(ulReq)
	if err == nil {
		ulResp.Body.Close()
		log.Debug("ML federated: uploaded local delta")
	}
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

// pickServer использует serverAgent для выбора сервера если доступно,
// иначе fallback на pickFastestServer (чистый latency probe).
func (m *Manager) pickServer(ctx context.Context) string {
	candidates := m.regionCandidates()
	if len(candidates) == 0 {
		return ""
	}

	// Зондируем все серверы параллельно.
	type probeResult struct {
		addr    string
		latency time.Duration
	}
	ch := make(chan probeResult, len(candidates))
	for _, addr := range candidates {
		addr := addr
		go func() {
			lat, err := probeLatency(ctx, addr, 200*time.Millisecond)
			if err != nil {
				ch <- probeResult{addr: addr, latency: math.MaxInt64}
				return
			}
			log.Info("[LATENCY] %s RTT=%v", addr, lat)
			ch <- probeResult{addr: addr, latency: lat}
		}()
	}
	probes := make([]mlpkg.ServerProbe, len(candidates))
	for i := range candidates {
		r := <-ch
		probes[i] = mlpkg.ServerProbe{Addr: r.addr, Latency: r.latency}
	}

	// serverAgent выбирает сервер с учётом исторических данных.
	if m.serverAgent != nil {
		if chosen := m.serverAgent.Decide(probes); chosen != "" {
			return chosen
		}
	}

	// Fallback: возвращаем сервер с минимальным RTT.
	best := probes[0]
	for _, p := range probes[1:] {
		if p.Latency < best.Latency {
			best = p
		}
	}
	if best.Latency == math.MaxInt64 {
		log.Warn("[LATENCY] All servers unreachable during probe, using configured default")
		return ""
	}
	log.Info("[LATENCY] Fastest server: %s (RTT=%v)", best.Addr, best.Latency)
	return best.Addr
}

// regionCandidates returns the servers to probe based on PreferredRegion.
// "auto" or "" → all servers from ServerList + all regions.
// specific region → that region's servers only (falls back to ServerList if empty).
func (m *Manager) regionCandidates() []string {
	region := m.config.PreferredRegion
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	if region != "" && region != "auto" {
		if servers, ok := m.config.Regions[region]; ok && len(servers) > 0 {
			for _, s := range servers {
				add(s)
			}
			return out
		}
		log.Warn("[LATENCY] Region %q has no servers, falling back to all", region)
	}

	// auto or unknown region: use all known servers
	for _, s := range m.config.ServerList {
		add(s)
	}
	for _, servers := range m.config.Regions {
		for _, s := range servers {
			add(s)
		}
	}
	return out
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

	oldTransport := m.config.Transport
	if m.config.MLServerURL != "" {
		if rec, conf := m.mlRecommendTransport(m.Context()); rec != "" && conf >= 0.55 {
			if rec != oldTransport {
				log.Info("[REKEY] ML recommends transport switch: %s → %s (confidence=%.2f)", oldTransport, rec, conf)
				m.config.Transport = rec
			}
		}
	}

	log.Info("[REKEY] Rotating %d transport connections for PFS (transport=%s)", poolSize, m.config.Transport)

	m.setState(StateReconnecting)
	m.Reconnect(m.Context())

	if m.config.MLServerURL != "" {
		go func() {
			time.Sleep(5 * time.Second)
			m.connMu.RLock()
			success := len(m.activePool) > 0
			m.connMu.RUnlock()
			m.mlSendFeedback(m.config.Transport, success, 0)
			if !success && m.config.Transport != oldTransport {
				log.Warn("[REKEY] ML transport %s failed, reverting to %s", m.config.Transport, oldTransport)
				m.config.Transport = oldTransport
				m.Reconnect(m.Context())
			}
		}()
	}
}

func (m *Manager) Stats() (bytesUp, bytesDown uint64) {
	return atomic.LoadUint64(&m.bytesUp), atomic.LoadUint64(&m.bytesDown)
}

func (m *Manager) GetTransport() string {
	return m.config.Transport
}

func (m *Manager) SetTransport(transport string) {
	m.config.Transport = transport
}

func (m *Manager) AddRussianSNI(sni string) {
	if sni == "" {
		return
	}
	m.russianSNIsMu.Lock()
	defer m.russianSNIsMu.Unlock()
	for _, existing := range m.russianSNIs {
		if existing == sni {
			return
		}
	}
	m.russianSNIs = append(m.russianSNIs, sni)
}

func (m *Manager) GetRussianSNIs() []string {
	m.russianSNIsMu.RLock()
	defer m.russianSNIsMu.RUnlock()
	out := make([]string, len(m.russianSNIs))
	copy(out, m.russianSNIs)
	return out
}

func (m *Manager) SetSpoofIPs(ips []string) {
	m.connMu.Lock()
	m.spoofIPs = ips
	m.connMu.Unlock()
}

func (m *Manager) SetRateLimit(kbps int) {
	atomic.StoreInt32(&m.rateLimitKB, int32(kbps))
}

func (m *Manager) GetRateLimit() int {
	return int(atomic.LoadInt32(&m.rateLimitKB))
}

func (m *Manager) SetTLSFragmentSize(size int) {
	if size < 0 {
		size = 0
	}
	atomic.StoreInt32(&m.tlsFragmentSize, int32(size))
	if m.config != nil {
		m.config.TLSFragmentSize = size
	}
}

func (m *Manager) GetTLSFragmentSize() int {
	return int(atomic.LoadInt32(&m.tlsFragmentSize))
}

func (m *Manager) SetForceObfuscation(enabled bool) {
	if enabled {
		atomic.StoreInt32(&m.transportSecureOverride, 0)
		atomic.StoreInt32(&m.forceObfuscation, 1)
	} else {
		atomic.StoreInt32(&m.transportSecureOverride, 1)
		atomic.StoreInt32(&m.forceObfuscation, 0)
	}
}

func (m *Manager) IsForceObfuscation() bool {
	return atomic.LoadInt32(&m.transportSecureOverride) == 0
}

func (m *Manager) SetBehavioralProfile(profile string) error {
	if m.obfuscator == nil {
		return fmt.Errorf("obfuscator not initialized")
	}
	if profile == "" {
		return nil
	}
	return m.obfuscator.SetProfile(profile)
}

// runWeightSnapshotLoop pushes a weight snapshot to the global store every 5 minutes.
// This lets the server's /api/ml/weights endpoint always return fresh weights.
func (m *Manager) runWeightSnapshotLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	// Push once immediately so the endpoint has data right away.
	mlpkg.SetGlobalSnapshot(m.ExportMLWeights())
	for range ticker.C {
		mlpkg.SetGlobalSnapshot(m.ExportMLWeights())
	}
}

// ExportMLWeights snapshots q-net weights from all RL agents.
// Called by the server to build the /api/ml/weights response.
func (m *Manager) ExportMLWeights() *mlpkg.WeightSnapshot {
	snap := &mlpkg.WeightSnapshot{}
	if m.transportAgent != nil {
		snap.Transport = m.transportAgent.ExportWeights()
	}
	if m.sniAgent != nil {
		snap.SNI = m.sniAgent.ExportWeights()
	}
	if m.kaAgent != nil {
		snap.Keepalive = m.kaAgent.ExportWeights()
	}
	if m.jitterAgent != nil {
		snap.Jitter = m.jitterAgent.ExportWeights()
	}
	if m.chunkAgent != nil {
		snap.Chunk = m.chunkAgent.ExportWeights()
	}
	if m.connAgent != nil {
		snap.Conn = m.connAgent.ExportWeights()
	}
	if m.boAgent != nil {
		snap.Backoff = m.boAgent.ExportWeights()
	}
	if m.serverAgent != nil {
		snap.Server = m.serverAgent.ExportWeights()
	}
	if m.tlsAgent != nil {
		snap.TLS = m.tlsAgent.ExportWeights()
	}
	return snap
}

// ImportMLWeights loads a snapshot into all matching RL agents (warm start).
// Called by the client after receiving weights from the server.
func (m *Manager) ImportMLWeights(snap *mlpkg.WeightSnapshot) {
	if snap == nil {
		return
	}
	if m.transportAgent != nil && len(snap.Transport) > 0 {
		m.transportAgent.ImportWeights(snap.Transport)
	}
	if m.sniAgent != nil && len(snap.SNI) > 0 {
		m.sniAgent.ImportWeights(snap.SNI)
	}
	if m.kaAgent != nil && len(snap.Keepalive) > 0 {
		m.kaAgent.ImportWeights(snap.Keepalive)
	}
	if m.jitterAgent != nil && len(snap.Jitter) > 0 {
		m.jitterAgent.ImportWeights(snap.Jitter)
	}
	if m.chunkAgent != nil && len(snap.Chunk) > 0 {
		m.chunkAgent.ImportWeights(snap.Chunk)
	}
	if m.connAgent != nil && len(snap.Conn) > 0 {
		m.connAgent.ImportWeights(snap.Conn)
	}
	if m.boAgent != nil && len(snap.Backoff) > 0 {
		m.boAgent.ImportWeights(snap.Backoff)
	}
	if m.serverAgent != nil && len(snap.Server) > 0 {
		m.serverAgent.ImportWeights(snap.Server)
	}
	if m.tlsAgent != nil && len(snap.TLS) > 0 {
		m.tlsAgent.ImportWeights(snap.TLS)
	}
}
