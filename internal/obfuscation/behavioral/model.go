package behavioral

import (
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"time"
)


type MessengerProfile struct {
	Name string

	Transport TransportProfile

	TLS TLSProfile

	Application ApplicationProfile

	Timing TimingModel

	Context ContextProfile

	Client ClientProfile
}


type TransportProfile struct {
	TCP TCPFingerprint

	UDP UDPProfile

	PreferredProtocol string
}

type TCPFingerprint struct {
	OptionsOrder []string

	InitialWindowSize int

	MSS int

	WindowScale int

	SACKPermitted bool

	Timestamps bool

	KeepAliveInterval time.Duration

	KeepAliveProbes int

	RetransmitMinTimeout time.Duration
	RetransmitMaxTimeout time.Duration
}

type UDPProfile struct {
	PreferredSizes []int

	PMTUDiscovery bool

	AllowFragmentation bool
}


type TLSProfile struct {
	JA3  string
	JA4  string
	JA3S string
	JA4S string

	ClientHello ClientHelloProfile

	SessionResumption bool
	SessionTickets    bool
	ZeroRTT           bool
	MaxEarlyDataSize  int

	CertificateCompression bool
	OCSPStapling           bool
}

type ClientHelloProfile struct {
	CipherSuites []uint16

	Extensions []uint16

	SupportedGroups []uint16

	SignatureAlgorithms []uint16

	ALPN []string

	SupportedVersions []uint16

	KeyShareGroups []uint16

	PSKModes []uint8

	ECHEnabled bool

	PaddingEnabled bool
	PaddingMin     int
	PaddingMax     int
}

type QUICProfile struct {
	Version uint32

	TransportParams QUICTransportParams

	HandshakeTimeout time.Duration

	InitialPacketSize int

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


type ApplicationProfile struct {
	Message MessagePattern

	States []ActivityState

	Bursts BurstProfile

	Heartbeat HeartbeatProfile

	ACK ACKProfile

	Media MediaProfile
}

type MessagePattern struct {
	TextSizeDistribution Distribution

	EmojiSize int

	StickerSizeMin int
	StickerSizeMax int

	VoiceDurationMin time.Duration
	VoiceDurationMax time.Duration
	VoiceBitrate     int

	TypingIndicatorInterval time.Duration
	TypingTimeout           time.Duration
}

type ActivityState struct {
	Name string

	PacketsPerSecond Distribution

	PacketSizes Distribution

	Duration Distribution

	Transitions map[string]float64
}

type BurstProfile struct {
	ThreadBurstSize Distribution
	ThreadBurstGap  Distribution
	ThreadCooldown  Distribution

	MediaBurstPackets  Distribution
	MediaBurstInterval Distribution

	GroupReadBurst  Distribution
	GroupReplyDelay Distribution
}

type HeartbeatProfile struct {
	BackgroundInterval time.Duration
	BackgroundJitter   float64

	ActiveInterval time.Duration
	ActiveJitter   float64

	PowerSaveInterval time.Duration
}

type ACKProfile struct {
	DelayedACKTimeout time.Duration

	CoalesceMax int

	MessageACK ACKBehavior
}

type ACKBehavior struct {
	ImmediateACK bool
	DelayMs      int
	BatchSize    int
}

type MediaProfile struct {
	PhotoChunkSize      int
	PhotoChunks         Distribution
	PhotoUploadInterval Distribution

	VideoChunkSize       int
	VideoBufferSegments  int
	VideoSegmentDuration time.Duration

	FileChunkSize int
	FileChunkGap  Distribution
}


type TimingModel struct {
	IPD Distribution

	Jitter JitterModel

	DailyPattern DailyActivityPattern

	HumanNoise HumanNoiseModel

	NetworkResponse NetworkResponseModel
}

type JitterModel struct {
	BaseJitter float64

	NetworkJitter float64

	AppJitter float64

	Distribution string
}

type DailyActivityPattern struct {
	HourlyActivity [24]float64

	WeekendModifier float64

	PeakHours []int
}

type HumanNoiseModel struct {
	ReadingTimePerChar time.Duration

	ThinkingTime Distribution

	CorrectionRate float64

	DistractionRate     float64
	DistractionDuration Distribution

	MultitaskingGaps Distribution
}

type NetworkResponseModel struct {
	RetryIntervals []time.Duration

	BackoffMultiplier float64

	MaxRetries int

	ReconnectDelay Distribution
}


type ContextProfile struct {
	DNS DNSProfile

	CDN CDNProfile

	Push PushProfile

	Background BackgroundProfile

	Endpoints []EndpointProfile
}

type DNSProfile struct {
	Servers []string

	QueryTypes []string

	RespectTTL bool

	DoHEnabled bool
	DoHServer  string
}

type CDNProfile struct {
	Domains []string

	ConnectionsPerDomain int

	PrefetchEnabled bool
}

type PushProfile struct {
	Technology string

	HeartbeatInterval time.Duration

	WakeupPattern WakeupPattern
}

type WakeupPattern struct {
	Interval time.Duration

	Jitter float64

	PostWakeActivity time.Duration
}

type BackgroundProfile struct {
	ConnectionCount int

	Connections []BackgroundConnection
}

type BackgroundConnection struct {
	Purpose  string
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


type ClientProfile struct {
	OS OSProfile

	App AppProfile

	Device DeviceProfile

	Network ClientNetworkProfile
}

type OSProfile struct {
	Name    string
	Version string
	Build   string

	SocketBufferSize int

	PowerSaveMode     string
	PowerSaveBehavior PowerSaveBehavior
}

type PowerSaveBehavior struct {
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

	ForegroundInterval time.Duration
	BackgroundInterval time.Duration
}

type DeviceProfile struct {
	Manufacturer  string
	Model         string
	ScreenDensity float64

	CellularCapable bool
	WiFiPreferred   bool
	IPv6Supported   bool
}

type ClientNetworkProfile struct {
	TCPNoDelay    bool
	TCPQuickACK   bool
	SocketTimeout time.Duration

	MaxIdleConns int
	IdleTimeout  time.Duration
}


type Distribution struct {
	Type   string
	Params []float64
}

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


type BehaviorEngine struct {
	profile *MessengerProfile
	state   string
	mu      sync.RWMutex

	lastPacketTime time.Time
	packetsInBurst int
	currentBurst   bool

	lastHour int

	isDistracted   bool
	distractionEnd time.Time
}

func NewBehaviorEngine(profile *MessengerProfile) *BehaviorEngine {
	return &BehaviorEngine{
		profile:        profile,
		state:          "idle",
		lastPacketTime: time.Now(),
	}
}

func (e *BehaviorEngine) NextPacketDelay() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()

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

	pps := state.PacketsPerSecond.Sample()
	if pps <= 0 {
		pps = 0.1
	}
	baseDelay := time.Duration(float64(time.Second) / pps)

	jitter := e.profile.Timing.Jitter.BaseJitter * sampleGaussian(0, 1)
	delay := baseDelay + time.Duration(jitter)*time.Millisecond

	hour := time.Now().Hour()
	activityMod := e.profile.Timing.DailyPattern.HourlyActivity[hour]
	if activityMod > 0 {
		delay = time.Duration(float64(delay) / activityMod)
	}

	if !e.isDistracted && sampleUniform(0, 1) < e.profile.Timing.HumanNoise.DistractionRate {
		e.isDistracted = true
		e.distractionEnd = time.Now().Add(time.Duration(e.profile.Timing.HumanNoise.DistractionDuration.Sample()) * time.Millisecond)
	}
	if e.isDistracted {
		if time.Now().After(e.distractionEnd) {
			e.isDistracted = false
		} else {
			delay += time.Duration(e.profile.Timing.HumanNoise.DistractionDuration.Sample()) * time.Millisecond
		}
	}

	if delay < time.Millisecond {
		delay = time.Millisecond
	}

	e.lastPacketTime = time.Now()
	return delay
}

func (e *BehaviorEngine) NextPacketSize() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, state := range e.profile.Application.States {
		if state.Name == e.state {
			return int(state.PacketSizes.Sample())
		}
	}

	return int(e.profile.Application.Message.TextSizeDistribution.Sample())
}

func (e *BehaviorEngine) TransitionState() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, state := range e.profile.Application.States {
		if state.Name == e.state {
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

func (e *BehaviorEngine) GetCurrentState() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state
}

func (e *BehaviorEngine) SetState(state string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = state
}
