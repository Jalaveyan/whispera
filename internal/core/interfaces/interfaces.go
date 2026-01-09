// Package interfaces defines the core interfaces for all modular components
package interfaces

import (
	"context"
	"net"
	"time"
)

// Module is the base interface that all modules must implement
type Module interface {
	// Name returns the unique name of the module
	Name() string

	// Version returns the semantic version of the module
	Version() string

	// Init initializes the module with the given configuration
	Init(ctx context.Context, cfg ModuleConfig) error

	// Start starts the module
	Start() error

	// Stop gracefully stops the module
	Stop() error

	// HealthCheck returns the current health status of the module
	HealthCheck() HealthStatus

	// Dependencies returns the list of module names this module depends on
	Dependencies() []string
}

// ModuleConfig is the base configuration interface for modules
type ModuleConfig interface {
	Validate() error
}

// HealthStatus represents the health of a module
type HealthStatus struct {
	Healthy     bool
	Message     string
	LastChecked time.Time
	Details     map[string]interface{}
}

// Direction indicates traffic direction
type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

// TransportType represents the type of transport
type TransportType string

const (
	TransportUDP       TransportType = "udp"
	TransportTCP       TransportType = "tcp"
	TransportWebSocket TransportType = "websocket"
	TransportXHTTP     TransportType = "xhttp"
	TransportQUIC      TransportType = "quic"
)

// Transport defines the interface for network transports
type Transport interface {
	Module

	// Listen starts listening on the given address
	Listen(addr string) error

	// Dial connects to the given address
	Dial(ctx context.Context, addr string) (net.Conn, error)

	// Accept accepts a new connection (blocking)
	Accept() (net.Conn, error)

	// Type returns the transport type
	Type() TransportType

	// Close closes the transport
	Close() error
}

// PacketTransport is for packet-based transports (UDP)
type PacketTransport interface {
	Transport

	// ReadFrom reads a packet from the transport
	ReadFrom(buf []byte) (n int, addr net.Addr, err error)

	// WriteTo writes a packet to the transport
	WriteTo(buf []byte, addr net.Addr) (n int, err error)
}

// Session represents a client session
type Session interface {
	// ID returns the session ID
	ID() uint32

	// ClientAddr returns the client address
	ClientAddr() net.Addr

	// LastActivity returns the time of last activity
	LastActivity() time.Time

	// UpdateActivity updates the last activity time
	UpdateActivity()

	// Close closes the session
	Close() error

	// Encrypt encrypts data for this session
	Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error)

	// Decrypt decrypts data for this session
	Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error)

	// GetStream gets a stream by ID
	GetStream(streamID uint16) (Stream, bool)

	// CreateStream creates a new stream
	CreateStream(streamID uint16) (Stream, error)

	// SetMetadata sets session metadata
	SetMetadata(key string, value interface{})

	// GetMetadata gets session metadata
	GetMetadata(key string) interface{}
}

// Stream represents a multiplexed stream within a session
type Stream interface {
	ID() uint16
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	IsClosed() bool
}

// SessionManager manages all active sessions
type SessionManager interface {
	Module

	// GetSession gets a session by ID
	GetSession(id uint32) (Session, bool)

	// GetSessionByAddr gets a session by client address
	GetSessionByAddr(addr net.Addr) (Session, bool)

	// CreateSession creates a new session
	CreateSession(params SessionParams) (Session, error)

	// RemoveSession removes a session
	RemoveSession(id uint32)

	// GetAllSessions returns all active sessions
	GetAllSessions() []Session

	// Count returns the number of active sessions
	Count() int

	// Subscribe subscribes to session events
	Subscribe(eventType SessionEventType) <-chan SessionEvent

	// SetMaxSessions sets the maximum number of sessions
	SetMaxSessions(max int)
}

// SessionParams contains parameters for creating a session
type SessionParams struct {
	ClientAddr net.Addr
	Seed       []byte
	UserID     string
	Metadata   map[string]interface{}
}

// SessionEventType defines types of session events
type SessionEventType string

const (
	SessionEventCreated SessionEventType = "created"
	SessionEventUpdated SessionEventType = "updated"
	SessionEventRemoved SessionEventType = "removed"
	SessionEventExpired SessionEventType = "expired"
	SessionEventRekeyed SessionEventType = "rekeyed"
)

// SessionEvent represents a session lifecycle event
type SessionEvent struct {
	Type      SessionEventType
	SessionID uint32
	Timestamp time.Time
	Data      interface{}
}

// Packet represents a network packet
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

// Destination represents a routing destination
type Destination struct {
	Type    DestinationType
	Address string
	Port    uint16
	Tag     string
}

// DestinationType defines types of routing destinations
type DestinationType string

const (
	DestinationDirect DestinationType = "direct"
	DestinationProxy  DestinationType = "proxy"
	DestinationBlock  DestinationType = "block"
	DestinationTUN    DestinationType = "tun"
)

// Router defines the interface for packet routing
type Router interface {
	Module

	// Route determines the destination for a packet
	Route(ctx context.Context, packet *Packet) (*Destination, error)

	// AddRule adds a routing rule
	AddRule(rule RoutingRule) error

	// RemoveRule removes a routing rule by ID
	RemoveRule(id string) error

	// UpdateRules replaces all rules
	UpdateRules(rules []RoutingRule) error

	// GetRules returns all current rules
	GetRules() []RoutingRule
}

// RoutingRule defines a routing rule
type RoutingRule struct {
	ID          string
	Priority    int
	Conditions  []RuleCondition
	Destination Destination
	Metadata    map[string]interface{}
}

// RuleCondition defines a condition for a routing rule
type RuleCondition struct {
	Field    string      // e.g., "dst_ip", "dst_port", "domain", "geoip"
	Operator string      // e.g., "eq", "contains", "in", "cidr"
	Value    interface{} // The value to match against
}

// Obfuscator defines the interface for traffic obfuscation
type Obfuscator interface {
	Module

	// Process obfuscates/deobfuscates data
	Process(data []byte, direction Direction) ([]byte, time.Duration, error)

	// SetProfile sets the obfuscation profile
	SetProfile(name string) error

	// GetProfile returns the current profile name
	GetProfile() string

	// GetStats returns obfuscation statistics
	GetStats() ObfuscationStats

	// SetThreatLevel sets the current threat level (0-10)
	SetThreatLevel(level int)
}

// ObfuscationStats contains obfuscation statistics
type ObfuscationStats struct {
	PacketsProcessed uint64
	BytesProcessed   uint64
	AvgProcessTime   time.Duration
	ProfileName      string
	ThreatLevel      int
}

// CryptoProvider provides cryptographic operations
type CryptoProvider interface {
	Module

	// NewAEAD creates a new AEAD cipher for a session
	NewAEAD(key []byte) (AEAD, error)

	// DeriveKeys derives session keys from a seed
	DeriveKeys(seed []byte, isServer bool) (sendKey, recvKey []byte, err error)

	// GenerateSessionID generates a random session ID
	GenerateSessionID() (uint32, error)
}

// AEAD represents an Authenticated Encryption with Associated Data cipher
type AEAD interface {
	// Encrypt encrypts plaintext with the given sequence and AAD
	Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext with the given sequence and AAD
	Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error)

	// NonceSize returns the size of the nonce
	NonceSize() int

	// Overhead returns the maximum overhead of sealing
	Overhead() int
}

// HandshakeHandler handles session handshakes
type HandshakeHandler interface {
	Module

	// HandleHandshake processes a handshake packet
	HandleHandshake(ctx context.Context, data []byte, addr net.Addr) (Session, error)

	// InitiateHandshake initiates a handshake with a server
	InitiateHandshake(ctx context.Context, conn net.Conn, addr net.Addr) (Session, error)

	// SetRateLimiter sets the handshake rate limiter
	SetRateLimiter(rate float64, burst int)
}

// DataPlane handles packet processing
type DataPlane interface {
	Module

	// ProcessInbound processes an inbound packet
	ProcessInbound(ctx context.Context, packet *Packet, session Session) error

	// ProcessOutbound processes an outbound packet
	ProcessOutbound(ctx context.Context, data []byte, session Session) error

	// SetTUN sets the TUN interface for IP packet handling
	SetTUN(tun TUNDevice)
}

// TUNDevice represents a TUN network interface
type TUNDevice interface {
	// Name returns the interface name
	Name() string

	// Read reads a packet from the TUN device
	Read(buf []byte) (int, error)

	// Write writes a packet to the TUN device
	Write(buf []byte) (int, error)

	// Close closes the TUN device
	Close() error

	// MTU returns the MTU of the device
	MTU() int
}

// MetricsCollector collects and exposes metrics
type MetricsCollector interface {
	Module

	// Increment increments a counter metric
	Increment(name string, labels map[string]string)

	// Add adds a value to a counter metric
	Add(name string, value float64, labels map[string]string)

	// Observe observes a value for a histogram/summary metric
	Observe(name string, value float64, labels map[string]string)

	// Set sets a gauge metric value
	Set(name string, value float64, labels map[string]string)

	// RegisterCounter registers a new counter metric
	RegisterCounter(name, help string, labelNames []string) error

	// RegisterGauge registers a new gauge metric
	RegisterGauge(name, help string, labelNames []string) error

	// RegisterHistogram registers a new histogram metric
	RegisterHistogram(name, help string, labelNames []string, buckets []float64) error
}

// ConfigProvider provides configuration management
type ConfigProvider interface {
	// Load loads configuration from the given source
	Load(source string) error

	// Get gets a configuration value
	Get(key string) interface{}

	// GetString gets a string configuration value
	GetString(key string) string

	// GetInt gets an integer configuration value
	GetInt(key string) int

	// GetBool gets a boolean configuration value
	GetBool(key string) bool

	// GetDuration gets a duration configuration value
	GetDuration(key string) time.Duration

	// Set sets a configuration value
	Set(key string, value interface{})

	// Watch watches for configuration changes
	Watch(key string) <-chan interface{}

	// Reload reloads the configuration
	Reload() error
}

// Logger provides logging capabilities
type Logger interface {
	Debug(msg string, fields map[string]interface{})
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
	Fatal(msg string, fields map[string]interface{})
	WithFields(fields map[string]interface{}) Logger
	WithModule(name string) Logger
}

// ============================================
// VPN-Specific Interfaces
// ============================================

// TunnelState represents the state of a VPN tunnel
type TunnelState int

const (
	TunnelStateDisconnected TunnelState = iota
	TunnelStateConnecting
	TunnelStateConnected
	TunnelStateReconnecting
	TunnelStateError
)

// TunnelManager manages VPN tunnel lifecycle
type TunnelManager interface {
	Module

	// Connect establishes the VPN tunnel
	Connect(ctx context.Context) error

	// Disconnect closes the VPN tunnel
	Disconnect()

	// Reconnect reconnects the tunnel
	Reconnect(ctx context.Context) error

	// Send sends data through the tunnel
	Send(data []byte) error

	// Receive receives data from the tunnel
	Receive(buf []byte) (int, error)

	// GetState returns the current tunnel state
	GetState() TunnelState

	// IsConnected returns true if tunnel is connected
	IsConnected() bool

	// GetSessionID returns the session ID
	GetSessionID() uint32

	// OnStateChange sets the state change callback
	OnStateChange(callback func(TunnelState))
}

// DNSResolver handles DNS resolution for VPN
type DNSResolver interface {
	Module

	// Resolve resolves a domain to IP addresses
	Resolve(ctx context.Context, domain string) ([]net.IP, error)

	// ResolveToString resolves a domain to a string IP
	ResolveToString(ctx context.Context, domain string) (string, error)

	// LookupFakeIP returns the domain for a fake IP (if using Fake-IP mode)
	LookupFakeIP(ip net.IP) (string, bool)

	// AddBlockedDomain adds a domain to the block list
	AddBlockedDomain(domain string)

	// RemoveBlockedDomain removes a domain from the block list
	RemoveBlockedDomain(domain string)

	// ClearCache clears the DNS cache
	ClearCache()
}

// NATManager manages Network Address Translation for VPN
type NATManager interface {
	Module

	// AddMapping adds a NAT mapping
	AddMapping(internalIP net.IP, internalPort int, protocol string) (externalPort int, err error)

	// RemoveMapping removes a NAT mapping
	RemoveMapping(externalPort int, protocol string) error

	// GetMapping gets a NAT mapping
	GetMapping(externalPort int, protocol string) (internalIP net.IP, internalPort int, ok bool)

	// Translate translates an address
	Translate(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, protocol string) (net.IP, int)
}

// FirewallRule defines a firewall rule
type FirewallRule struct {
	ID        string
	Direction Direction
	Action    string // "allow", "deny", "log"
	Protocol  string // "tcp", "udp", "icmp", "*"
	SrcAddr   string
	DstAddr   string
	SrcPort   string
	DstPort   string
	Priority  int
}

// Firewall manages packet filtering
type Firewall interface {
	Module

	// AddRule adds a firewall rule
	AddRule(rule FirewallRule) error

	// RemoveRule removes a firewall rule
	RemoveRule(id string) error

	// Check checks if a packet is allowed
	Check(packet *Packet) bool

	// GetRules returns all rules
	GetRules() []FirewallRule
}

// VPNStats contains comprehensive VPN statistics
type VPNStats struct {
	// Connection
	State          TunnelState
	ConnectedSince time.Time
	ServerAddr     string
	SessionID      uint32

	// Traffic
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64

	// Performance
	Latency    time.Duration
	PacketLoss float64

	// Sessions
	ActiveSessions int
}
