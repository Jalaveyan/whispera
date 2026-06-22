package interfaces

import (
	"context"
	"net"
	"time"
)

type Module interface {
	Name() string
	Version() string
	Dependencies() []string
	Init(ctx context.Context, cfg ModuleConfig) error
	Start() error
	Stop() error
	HealthCheck() HealthStatus
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
	TransportUDP    TransportType = "udp"
	TransportTCP    TransportType = "tcp"
	TransportQUIC   TransportType = "quic"
	TransportYaDisk TransportType = "yadisk"
)

type Transport interface {
	Module
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Type() TransportType
	Close() error
}

type StreamAcceptor interface {
	Accept() (net.Conn, error)
}

type DialableTransport interface {
	Transport
	DialConn(ctx context.Context, conn net.Conn, addr string) (net.Conn, error)
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

type SessionStore interface {
	GetSessionByAddr(addr net.Addr) (Session, bool)
	CreateSession(params SessionParams) (Session, error)
}

type SessionManager interface {
	Module
	SessionStore
	GetSession(id uint32) (Session, bool)
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

type ObfuscationProcessor interface {
	Process(data []byte, direction Direction) ([]byte, time.Duration, error)
}

type ObfuscationControl interface {
	SetProfile(name string) error
	GetProfile() string
	SetThreatLevel(level int)
	SetRealityKey(key string)
}

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
