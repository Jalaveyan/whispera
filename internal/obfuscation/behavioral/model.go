// Package behavioral implements realistic messenger behavior simulation
// Based on multi-layer analysis: L3/L4, L5/L6, L7, timing, context
package behavioral

import (
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"time"
)

// =============================================================================
// COMPLETE MESSENGER BEHAVIORAL MODEL
// =============================================================================

// MessengerProfile represents a complete behavioral profile for a messenger
type MessengerProfile struct {
	Name string

	// L3/L4 Transport Layer
	Transport TransportProfile

	// L5/L6 TLS/QUIC Layer
	TLS TLSProfile

	// L7 Application Layer
	Application ApplicationProfile

	// Timing Model
	Timing TimingModel

	// Context & Ecosystem
	Context ContextProfile

	// Client/Device Profile
	Client ClientProfile
}

// =============================================================================
// L3/L4 TRANSPORT LAYER
// =============================================================================

type TransportProfile struct {
	// TCP Fingerprint
	TCP TCPFingerprint

	// UDP settings
	UDP UDPProfile

	// Protocol preference
	PreferredProtocol string // "tcp", "udp", "quic"
}

type TCPFingerprint struct {
	// TCP options order (как в реальном стеке)
	OptionsOrder []string // ["mss", "sack_permitted", "timestamps", "nop", "window_scale"]

	// Initial window size
	InitialWindowSize int // e.g., 65535

	// MSS (Maximum Segment Size)
	MSS int // e.g., 1460

	// Window scaling factor
	WindowScale int // e.g., 7

	// SACK permitted
	SACKPermitted bool

	// Timestamps enabled
	Timestamps bool

	// Keep-alive interval
	KeepAliveInterval time.Duration

	// Keep-alive probes
	KeepAliveProbes int

	// Retransmission behavior
	RetransmitMinTimeout time.Duration
	RetransmitMaxTimeout time.Duration
}

type UDPProfile struct {
	// Preferred packet sizes
	PreferredSizes []int

	// PMTU discovery behavior
	PMTUDiscovery bool

	// Fragment behavior
	AllowFragmentation bool
}

// =============================================================================
// L5/L6 TLS/QUIC LAYER
// =============================================================================

type TLSProfile struct {
	// JA3/JA4 fingerprints
	JA3  string
	JA4  string
	JA3S string // Server response
	JA4S string

	// ClientHello structure
	ClientHello ClientHelloProfile

	// Session behavior
	SessionResumption bool
	SessionTickets    bool
	ZeroRTT           bool // 0-RTT behavior
	MaxEarlyDataSize  int

	// Certificate behavior
	CertificateCompression bool
	OCSPStapling           bool
}

type ClientHelloProfile struct {
	// Cipher suites in exact order
	CipherSuites []uint16

	// Extensions in exact order
	Extensions []uint16

	// Supported groups
	SupportedGroups []uint16

	// Signature algorithms
	SignatureAlgorithms []uint16

	// ALPN protocols
	ALPN []string

	// Supported versions
	SupportedVersions []uint16

	// Key share groups
	KeyShareGroups []uint16

	// PSK key exchange modes
	PSKModes []uint8

	// ECH (Encrypted Client Hello)
	ECHEnabled bool

	// Padding behavior
	PaddingEnabled bool
	PaddingMin     int
	PaddingMax     int
}

type QUICProfile struct {
	// Version
	Version uint32

	// Transport parameters
	TransportParams QUICTransportParams

	// Handshake timing
	HandshakeTimeout time.Duration

	// Initial packet size
	InitialPacketSize int

	// Packet size distribution
	PacketSizeDistribution Distribution
}

type QUICTransportParams struct {
	MaxIdleTimeout                time.Duration
	MaxUDPPayloadSize             int
	InitialMaxData                int
	InitialMaxStreamDataBidiLocal int
	InitialMaxStreamsBidi         int
	InitialMaxStreamsUni          int
}

// =============================================================================
// L7 APPLICATION LAYER
// =============================================================================

type ApplicationProfile struct {
	// Message patterns
	Message MessagePattern

	// Activity states
	States []ActivityState

	// Burst behavior (typing, sending media)
	Bursts BurstProfile

	// Heartbeat/Keep-alive
	Heartbeat HeartbeatProfile

	// ACK patterns
	ACK ACKProfile

	// Media handling
	Media MediaProfile
}

type MessagePattern struct {
	// Text message sizes distribution
	TextSizeDistribution Distribution

	// Emoji-only message size
	EmojiSize int

	// Sticker size range
	StickerSizeMin int
	StickerSizeMax int

	// Voice message patterns
	VoiceDurationMin time.Duration
	VoiceDurationMax time.Duration
	VoiceBitrate     int

	// Typing indicator
	TypingIndicatorInterval time.Duration
	TypingTimeout           time.Duration
}

type ActivityState struct {
	Name string // "idle", "typing", "sending", "receiving", "online"

	// Packet frequency in this state
	PacketsPerSecond Distribution

	// Packet sizes in this state
	PacketSizes Distribution

	// Duration of this state
	Duration Distribution

	// Transition probabilities to other states
	Transitions map[string]float64
}

type BurstProfile struct {
	// Message thread burst
	ThreadBurstSize Distribution // number of messages in burst
	ThreadBurstGap  Distribution // milliseconds between messages
	ThreadCooldown  Distribution // milliseconds after burst

	// Media upload burst
	MediaBurstPackets  Distribution
	MediaBurstInterval Distribution

	// Group chat burst
	GroupReadBurst  Distribution
	GroupReplyDelay Distribution
}

type HeartbeatProfile struct {
	// Background heartbeat
	BackgroundInterval time.Duration
	BackgroundJitter   float64

	// Active connection heartbeat
	ActiveInterval time.Duration
	ActiveJitter   float64

	// Mobile power saving heartbeat
	PowerSaveInterval time.Duration
}

type ACKProfile struct {
	// Delayed ACK settings
	DelayedACKTimeout time.Duration

	// ACK coalescing
	CoalesceMax int

	// ACK pattern during messaging
	MessageACK ACKBehavior
}

type ACKBehavior struct {
	ImmediateACK bool
	DelayMs      int
	BatchSize    int
}

type MediaProfile struct {
	// Photo upload
	PhotoChunkSize      int
	PhotoChunks         Distribution
	PhotoUploadInterval Distribution

	// Video upload
	VideoChunkSize       int
	VideoBufferSegments  int
	VideoSegmentDuration time.Duration

	// File transfer
	FileChunkSize int
	FileChunkGap  Distribution
}

// =============================================================================
// TIMING MODEL (ML EVASION)
// =============================================================================

type TimingModel struct {
	// Inter-packet delay distribution
	IPD Distribution

	// Jitter model
	Jitter JitterModel

	// Daily activity patterns
	DailyPattern DailyActivityPattern

	// Human noise
	HumanNoise HumanNoiseModel

	// Network condition responses
	NetworkResponse NetworkResponseModel
}

type JitterModel struct {
	// Base jitter (milliseconds)
	BaseJitter float64

	// Network-dependent jitter
	NetworkJitter float64

	// Application-level jitter
	AppJitter float64

	// Distribution type
	Distribution string // "gaussian", "exponential", "pareto"
}

type DailyActivityPattern struct {
	// Activity levels by hour (0-23)
	HourlyActivity [24]float64

	// Weekend modifier
	WeekendModifier float64

	// Peak hours (localized)
	PeakHours []int
}

type HumanNoiseModel struct {
	// Reading time per message character
	ReadingTimePerChar time.Duration

	// Thinking time before reply
	ThinkingTime Distribution

	// Typo/correction probability
	CorrectionRate float64

	// Distraction probability
	DistractionRate     float64
	DistractionDuration Distribution

	// Multitasking behavior
	MultitaskingGaps Distribution
}

type NetworkResponseModel struct {
	// Retry intervals on failure
	RetryIntervals []time.Duration

	// Backoff multiplier
	BackoffMultiplier float64

	// Maximum retries
	MaxRetries int

	// Reconnection behavior after network change
	ReconnectDelay Distribution
}

// =============================================================================
// CONTEXT & ECOSYSTEM
// =============================================================================

type ContextProfile struct {
	// DNS behavior
	DNS DNSProfile

	// CDN patterns
	CDN CDNProfile

	// Push notifications
	Push PushProfile

	// Background connections
	Background BackgroundProfile

	// API endpoints
	Endpoints []EndpointProfile
}

type DNSProfile struct {
	// Primary servers (messenger uses)
	Servers []string

	// Query patterns
	QueryTypes []string // ["A", "AAAA", "HTTPS"]

	// TTL handling
	RespectTTL bool

	// DNS over HTTPS
	DoHEnabled bool
	DoHServer  string
}

type CDNProfile struct {
	// CDN domains used
	Domains []string

	// Connection patterns
	ConnectionsPerDomain int

	// Prefetch behavior
	PrefetchEnabled bool
}

type PushProfile struct {
	// Push technology
	Technology string // "fcm", "apns", "websocket", "mqtt"

	// Heartbeat interval
	HeartbeatInterval time.Duration

	// Background wakeup behavior
	WakeupPattern WakeupPattern
}

type WakeupPattern struct {
	// Wake interval
	Interval time.Duration

	// Jitter
	Jitter float64

	// Activity after wake
	PostWakeActivity time.Duration
}

type BackgroundProfile struct {
	// Number of background connections
	ConnectionCount int

	// Connection purposes
	Connections []BackgroundConnection
}

type BackgroundConnection struct {
	Purpose  string // "api", "media", "events", "presence"
	Interval time.Duration
	Size     Distribution
}

type EndpointProfile struct {
	Path          string
	Method        string
	RequestSize   Distribution
	ResponseSize  Distribution
	CallFrequency Distribution
}

// =============================================================================
// CLIENT/DEVICE PROFILE
// =============================================================================

type ClientProfile struct {
	// OS details
	OS OSProfile

	// App details
	App AppProfile

	// Device details
	Device DeviceProfile

	// Network behavior
	Network ClientNetworkProfile
}

type OSProfile struct {
	Name    string // "Android", "iOS", "Windows", "macOS"
	Version string
	Build   string

	// OS-specific socket behavior
	SocketBufferSize int

	// Power management
	PowerSaveMode     string // "normal", "doze", "app_standby"
	PowerSaveBehavior PowerSaveBehavior
}

type PowerSaveBehavior struct {
	// Network scheduling during power save
	NetworkSchedule    time.Duration
	ReducedHeartbeat   time.Duration
	BatchedRequests    bool
	DeferrableInterval time.Duration
}

type AppProfile struct {
	Name        string
	Version     string
	BuildNumber string
	UserAgent   string

	// App-specific behaviors
	ForegroundInterval time.Duration
	BackgroundInterval time.Duration
}

type DeviceProfile struct {
	Manufacturer  string
	Model         string
	ScreenDensity float64

	// Network capabilities
	CellularCapable bool
	WiFiPreferred   bool
	IPv6Supported   bool
}

type ClientNetworkProfile struct {
	// Socket behaviors
	TCPNoDelay    bool
	TCPQuickACK   bool
	SocketTimeout time.Duration

	// Connection pooling
	MaxIdleConns int
	IdleTimeout  time.Duration
}

// =============================================================================
// STATISTICAL DISTRIBUTIONS
// =============================================================================

type Distribution struct {
	Type   string // "gaussian", "exponential", "pareto", "uniform", "lognormal"
	Params []float64
}

// Sample generates a value from the distribution
func (d Distribution) Sample() float64 {
	switch d.Type {
	case "gaussian":
		return sampleGaussian(d.Params[0], d.Params[1])
	case "exponential":
		return sampleExponential(d.Params[0])
	case "pareto":
		return samplePareto(d.Params[0], d.Params[1])
	case "uniform":
		return sampleUniform(d.Params[0], d.Params[1])
	case "lognormal":
		return sampleLognormal(d.Params[0], d.Params[1])
	default:
		return d.Params[0]
	}
}

func sampleGaussian(mean, stddev float64) float64 {
	// Box-Muller transform
	u1, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	u2, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	r1 := float64(u1.Int64()) / 1000000.0
	r2 := float64(u2.Int64()) / 1000000.0
	z := math.Sqrt(-2*math.Log(r1)) * math.Cos(2*math.Pi*r2)
	return mean + stddev*z
}

func sampleExponential(lambda float64) float64 {
	u, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	r := float64(u.Int64()) / 1000000.0
	return -math.Log(1-r) / lambda
}

func samplePareto(xm, alpha float64) float64 {
	u, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	r := float64(u.Int64()) / 1000000.0
	return xm / math.Pow(r, 1/alpha)
}

func sampleUniform(min, max float64) float64 {
	u, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	r := float64(u.Int64()) / 1000000.0
	return min + r*(max-min)
}

func sampleLognormal(mu, sigma float64) float64 {
	normal := sampleGaussian(mu, sigma)
	return math.Exp(normal)
}

// =============================================================================
// BEHAVIOR ENGINE
// =============================================================================

// BehaviorEngine generates realistic traffic based on profile
type BehaviorEngine struct {
	profile *MessengerProfile
	state   string
	mu      sync.RWMutex

	// State machine
	lastPacketTime time.Time
	packetsInBurst int
	currentBurst   bool

	// Daily pattern
	lastHour int

	// Human noise
	isDistracted   bool
	distractionEnd time.Time
}

// NewBehaviorEngine creates a new behavior engine
func NewBehaviorEngine(profile *MessengerProfile) *BehaviorEngine {
	return &BehaviorEngine{
		profile:        profile,
		state:          "idle",
		lastPacketTime: time.Now(),
	}
}

// NextPacketDelay calculates the delay before the next packet
func (e *BehaviorEngine) NextPacketDelay() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Get base delay from current state
	var state *ActivityState
	for _, s := range e.profile.Application.States {
		if s.Name == e.state {
			state = &s
			break
		}
	}
	if state == nil {
		return time.Millisecond * time.Duration(e.profile.Timing.IPD.Sample())
	}

	// Calculate base delay
	pps := state.PacketsPerSecond.Sample()
	if pps <= 0 {
		pps = 0.1
	}
	baseDelay := time.Second / time.Duration(pps)

	// Apply jitter
	jitter := e.profile.Timing.Jitter.BaseJitter * sampleGaussian(0, 1)
	delay := baseDelay + time.Duration(jitter)*time.Millisecond

	// Apply daily pattern modifier
	hour := time.Now().Hour()
	activityMod := e.profile.Timing.DailyPattern.HourlyActivity[hour]
	if activityMod > 0 {
		delay = time.Duration(float64(delay) / activityMod)
	}

	// Apply human noise - distraction
	if !e.isDistracted && sampleUniform(0, 1) < e.profile.Timing.HumanNoise.DistractionRate {
		e.isDistracted = true
		e.distractionEnd = time.Now().Add(time.Duration(e.profile.Timing.HumanNoise.DistractionDuration.Sample()) * time.Millisecond)
	}
	if e.isDistracted {
		if time.Now().After(e.distractionEnd) {
			e.isDistracted = false
		} else {
			// Add distraction delay
			delay += time.Duration(e.profile.Timing.HumanNoise.DistractionDuration.Sample()) * time.Millisecond
		}
	}

	// Ensure minimum delay
	if delay < time.Millisecond {
		delay = time.Millisecond
	}

	e.lastPacketTime = time.Now()
	return delay
}

// NextPacketSize calculates the next packet size
func (e *BehaviorEngine) NextPacketSize() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Get size from current state
	for _, state := range e.profile.Application.States {
		if state.Name == e.state {
			return int(state.PacketSizes.Sample())
		}
	}

	return int(e.profile.Application.Message.TextSizeDistribution.Sample())
}

// TransitionState transitions to a new state
func (e *BehaviorEngine) TransitionState() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Find current state
	for _, state := range e.profile.Application.States {
		if state.Name == e.state {
			// Sample transition
			r := sampleUniform(0, 1)
			cumulative := 0.0
			for nextState, prob := range state.Transitions {
				cumulative += prob
				if r < cumulative {
					e.state = nextState
					return
				}
			}
		}
	}
}

// GetCurrentState returns the current state
func (e *BehaviorEngine) GetCurrentState() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state
}

// SetState sets the current state
func (e *BehaviorEngine) SetState(state string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = state
}
