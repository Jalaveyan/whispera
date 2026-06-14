package interfaces

import (
	"context"
	"net"
	"time"
)

// Lifecycle manages start/stop of a component.
type Lifecycle interface {
	Start() error
	Stop() error
	HealthCheck() HealthStatus
}

// Descriptor provides identity metadata for a component.
type Descriptor interface {
	Name() string
	Version() string
	Dependencies() []string
}

// Module is the full module contract (Lifecycle + Descriptor + Init).
// Prefer Lifecycle or Descriptor when only a subset is needed.
type Module interface {
	Descriptor
	Init(ctx context.Context, cfg ModuleConfig) error
	Lifecycle
}

// TunnelConnector manages connection lifecycle.
type TunnelConnector interface {
	Connect(ctx context.Context) error
	Disconnect()
	Reconnect(ctx context.Context) error
}

// TunnelDataPlane sends and receives raw bytes over the tunnel.
type TunnelDataPlane interface {
	Send(data []byte) error
	Receive(buf []byte) (int, error)
}

// TunnelMonitor observes tunnel state without modifying it.
type TunnelMonitor interface {
	GetState() TunnelState
	IsConnected() bool
	GetSessionID() uint32
	OnStateChange(callback func(TunnelState))
}

// ObfuscationProcessor applies or removes obfuscation from raw bytes.
type ObfuscationProcessor interface {
	Process(data []byte, direction Direction) ([]byte, time.Duration, error)
}

// ObfuscationControl adjusts obfuscation behavior at runtime.
type ObfuscationControl interface {
	SetProfile(name string) error
	GetProfile() string
	SetThreatLevel(level int)
	SetRealityKey(key string)
}

type ModuleConfig interface {
	Validate() error
}

type HealthStatus struct {
	Healthy     bool
	Message     string
	LastChecked time.Time
	Details     map[string]interface{}
}

type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

type TransportType string

const (
	TransportUDP TransportType = "udp"
	TransportTCP TransportType = "tcp"

	TransportQUIC   TransportType = "quic"
	TransportYaDisk TransportType = "yadisk"
)

type Transport interface {
	Module

	Listen(addr string) error

	Dial(ctx context.Context, addr string) (net.Conn, error)

	Accept() (net.Conn, error)

	Type() TransportType

	Close() error
}

type DialableTransport interface {
	Transport
	DialConn(ctx context.Context, conn net.Conn, addr string) (net.Conn, error)
}

type PacketTransport interface {
	Transport

	ReadFrom(buf []byte) (n int, addr net.Addr, err error)

	WriteTo(buf []byte, addr net.Addr) (n int, err error)
}

type Session interface {
	ID() uint32

	ClientAddr() net.Addr

	LastActivity() time.Time

	UpdateActivity()

	Close() error

	Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error)

	Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error)

	GetStream(streamID uint16) (Stream, bool)

	CreateStream(streamID uint16) (Stream, error)

	SetMetadata(key string, value interface{})

	GetMetadata(key string) interface{}
}

type Stream interface {
	ID() uint16
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	IsClosed() bool
}

type SessionManager interface {
	Module

	GetSession(id uint32) (Session, bool)

	GetSessionByAddr(addr net.Addr) (Session, bool)

	CreateSession(params SessionParams) (Session, error)

	RemoveSession(id uint32)

	GetAllSessions() []Session

	Count() int

	Subscribe(eventType SessionEventType) <-chan SessionEvent

	SetMaxSessions(max int)
}

type SessionParams struct {
	ClientAddr net.Addr
	Seed       []byte
	UserID     string
	Metadata   map[string]interface{}
}
type SessionEventType string

const (
	SessionEventCreated SessionEventType = "created"
	SessionEventUpdated SessionEventType = "updated"
	SessionEventRemoved SessionEventType = "removed"
	SessionEventExpired SessionEventType = "expired"
	SessionEventRekeyed SessionEventType = "rekeyed"
)

type SessionEvent struct {
	Type      SessionEventType
	SessionID uint32
	Timestamp time.Time
	Data      interface{}
}

type Packet struct {
	SessionID uint32
	StreamID  uint16
	Seq       uint32
	Flags     byte
	Payload   []byte
	SrcAddr   net.Addr
	DstAddr   net.Addr
	Timestamp time.Time
}

type Destination struct {
	Type    DestinationType
	Address string
	Port    uint16
	Tag     string
}

type DestinationType string

const (
	DestinationDirect DestinationType = "direct"
	DestinationProxy  DestinationType = "proxy"
	DestinationBlock  DestinationType = "block"
	DestinationTUN    DestinationType = "tun"
)

type Router interface {
	Module

	Route(ctx context.Context, packet *Packet) (*Destination, error)

	AddRule(rule RoutingRule) error

	RemoveRule(id string) error

	UpdateRules(rules []RoutingRule) error

	GetRules() []RoutingRule
}

type RoutingRule struct {
	ID          string
	Priority    int
	Conditions  []RuleCondition
	Destination Destination
	Metadata    map[string]interface{}
}

type RuleCondition struct {
	Field    string
	Operator string
	Value    interface{}
}

// Obfuscator is the full obfuscation contract.
// Use ObfuscationProcessor when only processing is needed (e.g. GAN, ML obfuscators).
// Use ObfuscationControl when only runtime tuning is needed.
type Obfuscator interface {
	Module
	ObfuscationProcessor
	ObfuscationControl
	GetStats() ObfuscationStats
}
type ObfuscationStats struct {
	PacketsProcessed uint64
	BytesProcessed   uint64
	AvgProcessTime   time.Duration
	ProfileName      string
	ThreatLevel      int
}

type CryptoProvider interface {
	Module

	NewAEAD(key []byte) (AEAD, error)

	DeriveKeys(seed []byte, isServer bool) (sendKey, recvKey []byte, err error)

	GenerateSessionID() (uint32, error)
}

type AEAD interface {
	Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error)

	Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error)

	NonceSize() int

	Overhead() int
}

type HandshakeHandler interface {
	Module

	HandleHandshake(ctx context.Context, data []byte, addr net.Addr) (Session, error)

	InitiateHandshake(ctx context.Context, conn net.Conn, addr net.Addr) (Session, error)

	SetRateLimiter(rate float64, burst int)
}

type DataPlane interface {
	Module

	ProcessInbound(ctx context.Context, packet *Packet, session Session) error

	ProcessOutbound(ctx context.Context, data []byte, session Session) error

	SetTUN(tun TUNDevice)
}

type TUNDevice interface {
	Name() string

	Read(buf []byte) (int, error)

	Write(buf []byte) (int, error)

	Close() error

	MTU() int
}

type MetricsCollector interface {
	Module

	Increment(name string, labels map[string]string)

	Add(name string, value float64, labels map[string]string)

	Observe(name string, value float64, labels map[string]string)

	Set(name string, value float64, labels map[string]string)

	RegisterCounter(name, help string, labelNames []string) error

	RegisterGauge(name, help string, labelNames []string) error

	RegisterHistogram(name, help string, labelNames []string, buckets []float64) error
}

type ConfigProvider interface {
	Load(source string) error

	Get(key string) interface{}

	GetString(key string) string

	GetInt(key string) int

	GetBool(key string) bool

	GetDuration(key string) time.Duration

	Set(key string, value interface{})

	Watch(key string) <-chan interface{}

	Reload() error
}

type Logger interface {
	Debug(msg string, fields map[string]interface{})
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
	Fatal(msg string, fields map[string]interface{})
	WithFields(fields map[string]interface{}) Logger
	WithModule(name string) Logger
}

type TunnelState int

const (
	TunnelStateDisconnected TunnelState = iota
	TunnelStateConnecting
	TunnelStateConnected
	TunnelStateReconnecting
	TunnelStateError
)

// TunnelManager is the full tunnel contract.
// Prefer TunnelConnector, TunnelDataPlane or TunnelMonitor where only a subset is needed.
type TunnelManager interface {
	Module
	TunnelConnector
	TunnelDataPlane
	TunnelMonitor
}
type DNSResolver interface {
	Module

	Resolve(ctx context.Context, domain string) ([]net.IP, error)

	ResolveToString(ctx context.Context, domain string) (string, error)

	LookupFakeIP(ip net.IP) (string, bool)

	AddBlockedDomain(domain string)

	RemoveBlockedDomain(domain string)

	ClearCache()
}
type NATManager interface {
	Module

	AddMapping(internalIP net.IP, internalPort int, protocol string) (externalPort int, err error)

	RemoveMapping(externalPort int, protocol string) error

	GetMapping(externalPort int, protocol string) (internalIP net.IP, internalPort int, ok bool)

	Translate(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, protocol string) (net.IP, int)
}

type FirewallRule struct {
	ID        string
	Direction Direction
	Action    string
	Protocol  string
	SrcAddr   string
	DstAddr   string
	SrcPort   string
	DstPort   string
	Priority  int
}

type Firewall interface {
	Module

	AddRule(rule FirewallRule) error

	RemoveRule(id string) error

	Check(packet *Packet) bool

	GetRules() []FirewallRule
}

type VPNStats struct {
	State          TunnelState
	ConnectedSince time.Time
	ServerAddr     string
	SessionID      uint32

	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64

	Latency    time.Duration
	PacketLoss float64

	ActiveSessions int
}

type ControlPlane interface {
	Module

	RegisterBridge(ctx context.Context, info BridgeRegistration) (string, error)

	DeregisterBridge(ctx context.Context, bridgeID string) error

	GetBridgeConfig(ctx context.Context, bridgeID string) (map[string]interface{}, error)

	PushConfig(ctx context.Context, bridgeID string, config map[string]interface{}) error

	IssueBridgeToken(ctx context.Context, bridgeID string) (string, error)

	RevokeBridgeToken(ctx context.Context, bridgeID string) error

	ListBridges(ctx context.Context) ([]BridgeStatus, error)

	DeliverUpdate(ctx context.Context, version string, binaryURL string, checksum string) error

	CollectMetrics(ctx context.Context, bridgeID string, metrics map[string]interface{}) error
}

type BridgeRegistration struct {
	Address   string
	Type      string
	Provider  string
	Region    string
	PublicKey string
	Token     string
}

type BridgeStatus struct {
	ID        string
	Address   string
	Type      string
	IsAlive   bool
	Latency   int
	Load      float64
	CurUsers  int
	Version   string
	LastCheck time.Time
}
