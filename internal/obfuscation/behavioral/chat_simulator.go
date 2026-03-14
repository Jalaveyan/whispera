package behavioral

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

type ChatState string

const (
	StateIdle          ChatState = "idle"
	StateTyping        ChatState = "typing"
	StateSending       ChatState = "sending"
	StateReadReceipt   ChatState = "read_receipt"
	StateScrollFeed    ChatState = "scroll_feed"
	StateViewMedia     ChatState = "view_media"
	StateVoiceRecord   ChatState = "voice_record"
	StateOnline        ChatState = "online"
	StateBackground    ChatState = "background"
)

type ChatEvent struct {
	Type      string
	Size      int
	Direction string
	Delay     time.Duration
}

type ChatSimulator struct {
	mu       sync.Mutex
	engine   *BehaviorEngine
	state    ChatState
	profile  *MessengerProfile
	stopCh   chan struct{}
	eventCh  chan ChatEvent
	lastSend time.Time

	msgCount      int
	sessionStart  time.Time
	typingStarted time.Time
}

func NewChatSimulator(profile *MessengerProfile) *ChatSimulator {
	return &ChatSimulator{
		engine:       NewBehaviorEngine(profile),
		state:        StateIdle,
		profile:      profile,
		stopCh:       make(chan struct{}),
		eventCh:      make(chan ChatEvent, 64),
		sessionStart: time.Now(),
	}
}

func (cs *ChatSimulator) Events() <-chan ChatEvent {
	return cs.eventCh
}

func (cs *ChatSimulator) Start() {
	go cs.runLoop()
}

func (cs *ChatSimulator) Stop() {
	close(cs.stopCh)
}

func (cs *ChatSimulator) runLoop() {
	heartbeatTicker := time.NewTicker(cs.profile.Application.Heartbeat.BackgroundInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-cs.stopCh:
			return
		case <-heartbeatTicker.C:
			cs.emitEvent("heartbeat", 32+randN(16), "outbound")
		default:
		}

		cs.mu.Lock()
		nextState := cs.transition()
		cs.state = nextState
		cs.mu.Unlock()

		cs.executeState(nextState)
	}
}

func (cs *ChatSimulator) transition() ChatState {
	transitions := map[ChatState]map[ChatState]float64{
		StateIdle: {
			StateTyping:     0.30,
			StateScrollFeed: 0.25,
			StateOnline:     0.20,
			StateBackground: 0.15,
			StateViewMedia:  0.10,
		},
		StateTyping: {
			StateSending:    0.70,
			StateIdle:       0.15,
			StateTyping:     0.15,
		},
		StateSending: {
			StateIdle:        0.30,
			StateReadReceipt: 0.25,
			StateScrollFeed:  0.20,
			StateTyping:      0.15,
			StateViewMedia:   0.10,
		},
		StateReadReceipt: {
			StateIdle:       0.30,
			StateTyping:     0.35,
			StateScrollFeed: 0.25,
			StateViewMedia:  0.10,
		},
		StateScrollFeed: {
			StateIdle:       0.25,
			StateViewMedia:  0.20,
			StateTyping:     0.25,
			StateScrollFeed: 0.20,
			StateBackground: 0.10,
		},
		StateViewMedia: {
			StateScrollFeed: 0.30,
			StateIdle:       0.25,
			StateTyping:     0.25,
			StateBackground: 0.20,
		},
		StateOnline: {
			StateIdle:       0.30,
			StateTyping:     0.30,
			StateScrollFeed: 0.25,
			StateBackground: 0.15,
		},
		StateBackground: {
			StateIdle:       0.40,
			StateOnline:     0.30,
			StateScrollFeed: 0.20,
			StateTyping:     0.10,
		},
		StateVoiceRecord: {
			StateSending: 0.80,
			StateIdle:    0.20,
		},
	}

	trans, ok := transitions[cs.state]
	if !ok {
		return StateIdle
	}

	r := randFloat()
	cumulative := 0.0
	for state, prob := range trans {
		cumulative += prob
		if r < cumulative {
			return state
		}
	}
	return StateIdle
}

func (cs *ChatSimulator) executeState(state ChatState) {
	switch state {
	case StateIdle:
		cs.doIdle()
	case StateTyping:
		cs.doTyping()
	case StateSending:
		cs.doSending()
	case StateReadReceipt:
		cs.doReadReceipt()
	case StateScrollFeed:
		cs.doScrollFeed()
	case StateViewMedia:
		cs.doViewMedia()
	case StateVoiceRecord:
		cs.doVoiceRecord()
	case StateOnline:
		cs.doOnline()
	case StateBackground:
		cs.doBackground()
	}
}

func (cs *ChatSimulator) doIdle() {
	delay := time.Duration(2000+randN(5000)) * time.Millisecond
	cs.sleep(delay)
}

func (cs *ChatSimulator) doTyping() {
	cs.typingStarted = time.Now()
	cs.emitEvent("typing_start", 20+randN(10), "outbound")

	typingDuration := time.Duration(cs.profile.Application.Message.TextSizeDistribution.Sample()*50) * time.Millisecond
	if typingDuration < 500*time.Millisecond {
		typingDuration = 500 * time.Millisecond
	}
	if typingDuration > 15*time.Second {
		typingDuration = 15 * time.Second
	}

	intervals := int(typingDuration / (cs.profile.Application.Message.TypingIndicatorInterval))
	if intervals < 1 {
		intervals = 1
	}
	for i := 0; i < intervals; i++ {
		cs.emitEvent("typing_indicator", 16+randN(8), "outbound")
		cs.sleep(cs.profile.Application.Message.TypingIndicatorInterval)
	}

	if randFloat() < cs.profile.Timing.HumanNoise.CorrectionRate {
		cs.emitEvent("typing_correction", 20+randN(10), "outbound")
		cs.sleep(time.Duration(300+randN(700)) * time.Millisecond)
	}
}

func (cs *ChatSimulator) doSending() {
	msgSize := int(cs.profile.Application.Message.TextSizeDistribution.Sample())
	if msgSize < 10 {
		msgSize = 10
	}

	cs.emitEvent("message_send", msgSize, "outbound")
	cs.sleep(time.Duration(50+randN(150)) * time.Millisecond)

	cs.emitEvent("message_ack", 24, "inbound")
	cs.sleep(time.Duration(100+randN(300)) * time.Millisecond)

	cs.emitEvent("message_delivered", 20, "inbound")

	cs.msgCount++
	cs.lastSend = time.Now()

	if randFloat() < 0.3 {
		cs.sleep(time.Duration(500+randN(2000)) * time.Millisecond)
		replySize := int(cs.profile.Application.Message.TextSizeDistribution.Sample())
		cs.emitEvent("message_receive", replySize, "inbound")
	}
}

func (cs *ChatSimulator) doReadReceipt() {
	if cs.profile.Application.ACK.MessageACK.ImmediateACK {
		cs.emitEvent("read_receipt", 16, "outbound")
	} else {
		cs.sleep(time.Duration(cs.profile.Application.ACK.MessageACK.DelayMs) * time.Millisecond)
		cs.emitEvent("read_receipt", 16, "outbound")
	}
	cs.sleep(time.Duration(200+randN(500)) * time.Millisecond)
}

func (cs *ChatSimulator) doScrollFeed() {
	scrollCount := 3 + randN(8)
	for i := 0; i < scrollCount; i++ {
		reqSize := 64 + randN(128)
		cs.emitEvent("feed_request", reqSize, "outbound")

		cs.sleep(time.Duration(100+randN(200)) * time.Millisecond)

		respSize := 512 + randN(4096)
		cs.emitEvent("feed_response", respSize, "inbound")

		readDelay := time.Duration(cs.profile.Timing.HumanNoise.ReadingTimePerChar) * time.Duration(50+randN(200))
		cs.sleep(readDelay)
	}
}

func (cs *ChatSimulator) doViewMedia() {
	cs.emitEvent("media_request", 64+randN(64), "outbound")
	cs.sleep(time.Duration(50+randN(100)) * time.Millisecond)

	chunks := int(cs.profile.Application.Media.PhotoChunks.Sample())
	if chunks < 1 {
		chunks = 3
	}
	chunkSize := cs.profile.Application.Media.PhotoChunkSize
	if chunkSize == 0 {
		chunkSize = 16384
	}

	for i := 0; i < chunks; i++ {
		cs.emitEvent("media_chunk", chunkSize, "inbound")
		cs.sleep(time.Duration(cs.profile.Application.Media.PhotoUploadInterval.Sample()) * time.Millisecond)
	}

	viewTime := time.Duration(2000+randN(5000)) * time.Millisecond
	cs.sleep(viewTime)
}

func (cs *ChatSimulator) doVoiceRecord() {
	cs.emitEvent("voice_start", 24, "outbound")

	duration := cs.profile.Application.Message.VoiceDurationMin +
		time.Duration(randN(int(cs.profile.Application.Message.VoiceDurationMax-cs.profile.Application.Message.VoiceDurationMin)))
	if duration < time.Second {
		duration = 2 * time.Second
	}

	chunkInterval := 100 * time.Millisecond
	chunks := int(duration / chunkInterval)
	chunkSize := cs.profile.Application.Message.VoiceBitrate / 8 / 10
	if chunkSize < 100 {
		chunkSize = 200
	}

	for i := 0; i < chunks; i++ {
		cs.emitEvent("voice_chunk", chunkSize, "outbound")
		cs.sleep(chunkInterval)
	}

	cs.emitEvent("voice_end", 32, "outbound")
}

func (cs *ChatSimulator) doOnline() {
	cs.emitEvent("presence_online", 24, "outbound")
	cs.sleep(time.Duration(1000+randN(3000)) * time.Millisecond)

	if randFloat() < 0.4 {
		cs.emitEvent("presence_update", 32, "inbound")
	}
}

func (cs *ChatSimulator) doBackground() {
	cs.emitEvent("background_sync", 48+randN(64), "outbound")
	cs.sleep(time.Duration(5000+randN(10000)) * time.Millisecond)

	if randFloat() < 0.3 {
		cs.emitEvent("push_notification", 128+randN(256), "inbound")
	}
}

func (cs *ChatSimulator) emitEvent(eventType string, size int, direction string) {
	select {
	case cs.eventCh <- ChatEvent{
		Type:      eventType,
		Size:      size,
		Direction: direction,
	}:
	default:
	}
}

func (cs *ChatSimulator) sleep(d time.Duration) {
	select {
	case <-cs.stopCh:
	case <-time.After(d):
	}
}

func randN(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(binary.BigEndian.Uint32(b)) % n
}

func randFloat() float64 {
	b := make([]byte, 8)
	rand.Read(b)
	return float64(binary.BigEndian.Uint64(b)) / float64(^uint64(0))
}
