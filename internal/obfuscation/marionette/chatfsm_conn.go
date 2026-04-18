package marionette

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/behavioral"
)

type ChatFSMConn struct {
	net.Conn

	engine *ProtocolEngine

	profilePtr  atomic.Pointer[behavioral.MessengerProfile]
	behaviorPtr atomic.Pointer[behavioral.BehaviorEngine]

	writeMu sync.Mutex

	readMu  sync.Mutex
	readBuf []byte
	hdr     [16]byte

	stopOnce sync.Once
	stopCh   chan struct{}

	coverIntervalNs atomic.Int64
	coverEnabled    atomic.Bool

	id uint64

	recvDataSeen atomic.Bool
	lastRecvSeq  atomic.Uint32
	lastRecvAt   atomic.Int64
	pendingAck   atomic.Bool
	pendingRead  atomic.Bool
	lastWriteAt  atomic.Int64

	background atomic.Bool
}

var connIDSeq atomic.Uint64

const maxFramePayload = 60 * 1024

func NewChatFSMConn(conn net.Conn, chatID uint32, coverInterval time.Duration) *ChatFSMConn {
	return NewChatFSMConnWithProfile(conn, chatID, behavioral.VKMessengerProfile(), coverInterval)
}

func NewChatFSMConnWithProfile(conn net.Conn, chatID uint32, profile *behavioral.MessengerProfile, coverInterval time.Duration) *ChatFSMConn {
	if profile == nil {
		profile = behavioral.VKMessengerProfile()
	}
	c := &ChatFSMConn{
		Conn:   conn,
		engine: NewProtocolEngine(chatID, coverInterval),
		stopCh: make(chan struct{}),
		id:     connIDSeq.Add(1),
	}
	c.profilePtr.Store(profile)
	c.behaviorPtr.Store(behavioral.NewBehaviorEngine(profile))
	c.coverIntervalNs.Store(int64(coverInterval))
	c.coverEnabled.Store(coverInterval > 0)

	c.engine.SetSendFunc(c.writeRawFrame)
	go c.coverLoop()
	go c.ackScheduler()
	go c.sessionRotator()

	registerLiveConn(c)
	return c
}

func (c *ChatFSMConn) profile() *behavioral.MessengerProfile {
	return c.profilePtr.Load()
}
func (c *ChatFSMConn) behavior() *behavioral.BehaviorEngine {
	return c.behaviorPtr.Load()
}
func (c *ChatFSMConn) coverInterval() time.Duration {
	return time.Duration(c.coverIntervalNs.Load())
}

func (c *ChatFSMConn) ID() uint64 { return c.id }

func (c *ChatFSMConn) SetProfile(p *behavioral.MessengerProfile) {
	if p == nil {
		return
	}
	c.profilePtr.Store(p)
	c.behaviorPtr.Store(behavioral.NewBehaviorEngine(p))
}

func (c *ChatFSMConn) SetCoverInterval(d time.Duration) {
	c.coverIntervalNs.Store(int64(d))
}

func (c *ChatFSMConn) SetCoverEnabled(enabled bool) {
	c.coverEnabled.Store(enabled)
}

func (c *ChatFSMConn) SetSessionForeground(fg bool) {
	c.background.Store(!fg)
}

func (c *ChatFSMConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	if c.coverEnabled.Load() && c.coverInterval() > 0 && !c.background.Load() {
		c.emitTypingEnvelope(true)
	}

	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxFramePayload {
			chunk = b[:maxFramePayload]
		}
		frame := c.engine.WrapData(chunk)
		if err := c.writeRawFrame(frame); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	c.lastWriteAt.Store(time.Now().UnixNano())

	if c.coverEnabled.Load() && c.coverInterval() > 0 && !c.background.Load() {
		c.emitTypingEnvelope(false)
	}

	return total, nil
}

func (c *ChatFSMConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	for {
		if _, err := io.ReadFull(c.Conn, c.hdr[:]); err != nil {
			return 0, err
		}
		payloadLen := int(binary.BigEndian.Uint16(c.hdr[2:4]))
		if payloadLen > 65535 {
			return 0, io.ErrUnexpectedEOF
		}

		var payload []byte
		if payloadLen > 0 {
			payload = make([]byte, payloadLen)
			if _, err := io.ReadFull(c.Conn, payload); err != nil {
				return 0, err
			}
		}

		ft := FrameType(c.hdr[0])
		seq := binary.BigEndian.Uint32(c.hdr[4:8])

		switch ft {
		case FrameData:
			c.recvDataSeen.Store(true)
			c.lastRecvSeq.Store(seq)
			c.lastRecvAt.Store(time.Now().UnixNano())
			c.pendingAck.Store(true)
			c.pendingRead.Store(true)
			if c.coverEnabled.Load() && c.coverInterval() > 0 {
				go c.scheduleReplyIntent()
			}
			n := copy(b, payload)
			if n < len(payload) {
				c.readBuf = payload[n:]
			}
			return n, nil
		default:
			continue
		}
	}
}

func (c *ChatFSMConn) writeRawFrame(frame []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.Conn.Write(frame)
	return err
}

func (c *ChatFSMConn) tryWriteCoverFrame(frame []byte) {
	if !c.writeMu.TryLock() {
		return
	}
	defer c.writeMu.Unlock()
	_, _ = c.Conn.Write(frame)
}

func (c *ChatFSMConn) coverLoop() {
	for {
		profile := c.profile()
		behavior := c.behavior()

		delay := behavior.NextPacketDelay()
		if c.background.Load() {
			delay = profile.Application.Heartbeat.BackgroundInterval +
				time.Duration(float64(profile.Application.Heartbeat.BackgroundInterval)*profile.Application.Heartbeat.BackgroundJitter*sampleSignedUnit())
			if delay < time.Second {
				delay = time.Second
			}
		}
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
		if !c.coverEnabled.Load() || c.coverInterval() <= 0 {
			delay = time.Second
		}

		select {
		case <-c.stopCh:
			return
		case <-time.After(delay):
		}

		if !c.coverEnabled.Load() || c.coverInterval() <= 0 {
			continue
		}
		behavior.TransitionState()
		c.emitContextualCover()
	}
}

func (c *ChatFSMConn) emitContextualCover() {
	profile := c.profile()
	behavior := c.behavior()
	state := behavior.GetCurrentState()

	switch state {
	case "streaming", "buffering", "playing":
		go c.emitMediaChunkBurst()
		return
	case "seeking":
		go c.emitSeekBurst()
		return
	}

	var allowed []FrameType
	switch state {
	case "idle":
		allowed = []FrameType{FrameKeepAlive, FramePresence, FrameBackgroundSync}
	case "feed_scroll":
		allowed = []FrameType{FrameFeedRequest, FrameFeedResponse, FramePresence, FrameKeepAlive}
	case "content_view":
		if profile.Application.Media.PhotoChunkSize > 0 && randByte()%12 == 0 {
			go c.emitPhotoUploadBurst()
			return
		}
		allowed = []FrameType{FrameFeedRequest, FrameFeedResponse, FramePresence, FrameKeepAlive}
	case "typing":
		allowed = []FrameType{FrameTypingStart, FrameTypingStop, FramePresence}
	case "sending":
		if profile.Application.Message.VoiceDurationMax > 0 && randByte()%18 == 0 {
			go c.emitVoiceBurst()
			return
		}
		if profile.Application.Message.StickerSizeMax > 0 && randByte()%24 == 0 {
			c.emitStickerFrame()
			return
		}
		allowed = []FrameType{FrameMessageAck, FrameKeepAlive, FramePresence}
	case "api_poll":
		allowed = []FrameType{FrameFeedRequest, FrameFeedResponse}
	case "paused":
		allowed = []FrameType{FrameKeepAlive, FrameBackgroundSync}
	case "background":
		allowed = []FrameType{FrameBackgroundSync, FrameKeepAlive, FramePushNotify}
	default:
		allowed = []FrameType{FrameKeepAlive, FramePresence}
	}

	ft := allowed[int(randByte())%len(allowed)]

	if (ft == FrameMessageAck || ft == FrameReadReceipt) && !c.recvDataSeen.Load() {
		ft = FrameKeepAlive
	}

	size := behavior.NextPacketSize()
	if size < 8 {
		size = 8
	}
	if size > maxFramePayload {
		size = maxFramePayload
	}
	payload := c.buildBinaryPayload(ft, size)

	frame := &ChatFrame{
		Type:      ft,
		SeqNum:    c.engine.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    c.engine.chatID,
		Payload:   payload,
	}
	c.tryWriteCoverFrame(frame.Marshal())
}

func (c *ChatFSMConn) emitVoiceBurst() {
	msg := c.profile().Application.Message
	durMin := msg.VoiceDurationMin
	durMax := msg.VoiceDurationMax
	if durMax <= durMin {
		durMax = durMin + 5*time.Second
	}
	span := int64(durMax - durMin)
	dur := durMin + time.Duration(int64(randByte())*span/255)
	if dur < time.Second {
		dur = 2 * time.Second
	}

	chunkInterval := 100 * time.Millisecond
	chunkSize := msg.VoiceBitrate / 8 / 10
	if chunkSize < 200 {
		chunkSize = 200
	}
	if chunkSize > maxFramePayload {
		chunkSize = maxFramePayload
	}
	chunks := int(dur / chunkInterval)

	for i := 0; i < chunks; i++ {
		select {
		case <-c.stopCh:
			return
		default:
		}
		payload := c.buildBinaryPayload(FrameVoiceChunk, chunkSize)
		frame := &ChatFrame{
			Type:      FrameVoiceChunk,
			SeqNum:    c.engine.nextSeq(),
			Timestamp: time.Now().Unix(),
			ChatID:    c.engine.chatID,
			Payload:   payload,
		}
		c.tryWriteCoverFrame(frame.Marshal())
		select {
		case <-c.stopCh:
			return
		case <-time.After(chunkInterval):
		}
	}
}

func (c *ChatFSMConn) emitStickerFrame() {
	msg := c.profile().Application.Message
	min := msg.StickerSizeMin
	max := msg.StickerSizeMax
	if max <= min {
		max = min + 16384
	}
	size := min + int(randByte())*(max-min)/255
	if size > maxFramePayload {
		size = maxFramePayload
	}
	payload := c.buildBinaryPayload(FrameStickerSend, size)
	frame := &ChatFrame{
		Type:      FrameStickerSend,
		SeqNum:    c.engine.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    c.engine.chatID,
		Payload:   payload,
	}
	c.tryWriteCoverFrame(frame.Marshal())
}

func (c *ChatFSMConn) emitPhotoUploadBurst() {
	media := c.profile().Application.Media
	chunkSize := media.PhotoChunkSize
	if chunkSize <= 0 {
		return
	}
	if chunkSize > maxFramePayload {
		chunkSize = maxFramePayload
	}
	chunks := int(media.PhotoChunks.Sample())
	if chunks < 1 {
		chunks = 3
	}
	if chunks > 80 {
		chunks = 80
	}

	meta := c.buildBinaryPayload(FrameMediaUpload, 256)
	c.tryWriteCoverFrame((&ChatFrame{
		Type: FrameMediaUpload, SeqNum: c.engine.nextSeq(),
		Timestamp: time.Now().Unix(), ChatID: c.engine.chatID, Payload: meta,
	}).Marshal())

	gap := time.Duration(media.PhotoUploadInterval.Sample()) * time.Millisecond
	if gap < 5*time.Millisecond {
		gap = 25 * time.Millisecond
	}
	if gap > time.Second {
		gap = time.Second
	}

	for i := 0; i < chunks; i++ {
		select {
		case <-c.stopCh:
			return
		default:
		}
		payload := c.buildBinaryPayload(FrameMediaChunk, chunkSize)
		c.tryWriteCoverFrame((&ChatFrame{
			Type: FrameMediaChunk, SeqNum: c.engine.nextSeq(),
			Timestamp: time.Now().Unix(), ChatID: c.engine.chatID, Payload: payload,
		}).Marshal())
		select {
		case <-c.stopCh:
			return
		case <-time.After(gap):
		}
	}
}

func (c *ChatFSMConn) emitMediaChunkBurst() {
	media := c.profile().Application.Media
	chunkSize := media.VideoChunkSize
	if chunkSize <= 0 {
		chunkSize = 65536
	}
	if chunkSize > maxFramePayload {
		chunkSize = maxFramePayload
	}
	subChunks := 4 + int(randByte()%4)
	for i := 0; i < subChunks; i++ {
		select {
		case <-c.stopCh:
			return
		default:
		}
		payload := c.buildBinaryPayload(FrameMediaChunk, chunkSize/subChunks)
		c.tryWriteCoverFrame((&ChatFrame{
			Type: FrameMediaChunk, SeqNum: c.engine.nextSeq(),
			Timestamp: time.Now().Unix(), ChatID: c.engine.chatID, Payload: payload,
		}).Marshal())
		select {
		case <-c.stopCh:
			return
		case <-time.After(media.VideoSegmentDuration / time.Duration(subChunks*2)):
		}
	}
}

func (c *ChatFSMConn) emitSeekBurst() {
	c.tryWriteCoverFrame((&ChatFrame{
		Type: FrameMediaUpload, SeqNum: c.engine.nextSeq(),
		Timestamp: time.Now().Unix(), ChatID: c.engine.chatID,
		Payload: c.buildBinaryPayload(FrameMediaUpload, 320),
	}).Marshal())
	c.emitMediaChunkBurst()
}

func (c *ChatFSMConn) scheduleReplyIntent() {
	if randByte()%100 >= 35 {
		return
	}
	delay := time.Duration(c.profile().Application.Bursts.GroupReplyDelay.Sample()) * time.Millisecond
	if delay <= 0 {
		delay = 1500 * time.Millisecond
	}
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	select {
	case <-c.stopCh:
		return
	case <-time.After(delay):
	}
	c.behavior().SetState("typing")
}

func (c *ChatFSMConn) ackScheduler() {
	const baseTick = 50 * time.Millisecond
	tick := time.NewTicker(baseTick)
	defer tick.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-tick.C:
		}

		if !c.coverEnabled.Load() {
			continue
		}
		if !c.pendingAck.Load() && !c.pendingRead.Load() {
			continue
		}

		profile := c.profile()
		ackDelay := profile.Application.ACK.DelayedACKTimeout
		if ackDelay <= 0 {
			ackDelay = 80 * time.Millisecond
		}

		nowNs := time.Now().UnixNano()
		recvNs := c.lastRecvAt.Load()
		elapsed := time.Duration(nowNs - recvNs)

		if c.pendingAck.Load() && elapsed >= ackDelay {
			c.pendingAck.Store(false)
			c.emitAckFrame(FrameMessageAck)
		}

		readDelay := profile.Timing.HumanNoise.ReadingTimePerChar * 80
		if readDelay <= 0 {
			readDelay = 1500 * time.Millisecond
		}
		if readDelay > 5*time.Second {
			readDelay = 5 * time.Second
		}
		if c.pendingRead.Load() && elapsed >= readDelay {
			c.pendingRead.Store(false)
			c.emitAckFrame(FrameReadReceipt)
		}
	}
}

func (c *ChatFSMConn) emitAckFrame(ft FrameType) {
	size := c.behavior().NextPacketSize() / 4
	if size < 12 {
		size = 12
	}
	if size > 96 {
		size = 96
	}
	payload := c.buildBinaryPayload(ft, size)
	frame := &ChatFrame{
		Type:      ft,
		SeqNum:    c.engine.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    c.engine.chatID,
		Payload:   payload,
	}
	c.tryWriteCoverFrame(frame.Marshal())
}

func (c *ChatFSMConn) emitTypingEnvelope(start bool) {
	if start {
		_ = c.emitTyping(FrameTypingStart)
		indicators := 1 + int(randByte()%2)
		for i := 0; i < indicators; i++ {
			_ = c.emitTyping(FrameTypingStart)
		}
	} else {
		_ = c.emitTyping(FrameTypingStop)
	}
}

func (c *ChatFSMConn) emitTyping(ft FrameType) error {
	size := 16 + int(randByte()%32)
	payload := c.buildBinaryPayload(ft, size)
	frame := &ChatFrame{
		Type:      ft,
		SeqNum:    c.engine.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    c.engine.chatID,
		Payload:   payload,
	}
	c.tryWriteCoverFrame(frame.Marshal())
	return nil
}

func (c *ChatFSMConn) sessionRotator() {
	for {
		profile := c.profile()
		fg := profile.Client.App.ForegroundInterval
		bg := profile.Client.App.BackgroundInterval
		if fg <= 0 {
			fg = 30 * time.Second
		}
		if bg <= 0 {
			bg = 60 * time.Second
		}

		fgDur := fg*time.Duration(8+randByte()%8) + time.Duration(randByte())*time.Millisecond
		select {
		case <-c.stopCh:
			return
		case <-time.After(fgDur):
		}
		c.background.Store(true)
		c.behavior().SetState("idle")

		bgDur := bg*time.Duration(2+randByte()%6) + time.Duration(randByte())*time.Millisecond
		select {
		case <-c.stopCh:
			return
		case <-time.After(bgDur):
		}
		c.background.Store(false)
	}
}

func (c *ChatFSMConn) buildBinaryPayload(ft FrameType, size int) []byte {
	if size < 1 {
		return nil
	}
	buf := make([]byte, size)
	buf[0] = byte(ft)
	if size >= 5 {
		binary.BigEndian.PutUint32(buf[1:5], uint32(time.Now().Unix()))
	}
	if size >= 9 && (ft == FrameMessageAck || ft == FrameReadReceipt) {
		binary.BigEndian.PutUint32(buf[5:9], c.lastRecvSeq.Load())
	}
	if size > 9 {
		_, _ = rand.Read(buf[9:])
	} else if size > 5 {
		_, _ = rand.Read(buf[5:])
	} else if size > 1 {
		_, _ = rand.Read(buf[1:])
	}
	return buf
}

func sampleSignedUnit() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	u := binary.BigEndian.Uint64(b[:])
	return (float64(u)/float64(^uint64(0)))*2.0 - 1.0
}

func (c *ChatFSMConn) Close() error {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		unregisterLiveConn(c)
	})
	return c.Conn.Close()
}
