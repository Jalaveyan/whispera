package protocol

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"whispera/core/relay"
)

const (
	rtFECK                 = 10
	rtFECM                 = 4
	rtDatagramMaxProtected = 1100
	rtFECBlockWait         = 30 * time.Millisecond
	rtFECSweepEvery        = 10 * time.Millisecond
	rtUDPTargetIdle        = 2 * time.Minute
)

const (
	rtMarkerFEC byte = 0xFF
	rtMarkerRaw byte = 0xFE
)

func encodeRTAddr(host string, port uint16) []byte {
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(b, 0x01)
			b = append(b, ip4...)
		} else {
			b = append(b, 0x04)
			b = append(b, ip.To16()...)
		}
	} else {
		b = append(b, 0x03, byte(len(host)))
		b = append(b, []byte(host)...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

func decodeRTAddr(b []byte) (host string, port uint16, rest []byte, ok bool) {
	if len(b) < 1 {
		return "", 0, nil, false
	}
	switch b[0] {
	case 0x01:
		if len(b) < 7 {
			return "", 0, nil, false
		}
		return net.IP(b[1:5]).String(), binary.BigEndian.Uint16(b[5:7]), b[7:], true
	case 0x04:
		if len(b) < 19 {
			return "", 0, nil, false
		}
		return net.IP(b[1:17]).String(), binary.BigEndian.Uint16(b[17:19]), b[19:], true
	case 0x03:
		if len(b) < 2 {
			return "", 0, nil, false
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, nil, false
		}
		return string(b[2 : 2+l]), binary.BigEndian.Uint16(b[2+l : 4+l]), b[4+l:], true
	default:
		return "", 0, nil, false
	}
}

type rtFECSender struct {
	mu         sync.Mutex
	enc        *relay.FECEncoder
	blockStart uint32
	cnt        int
	lastAt     time.Time
}

func newRTFECSender() *rtFECSender {
	return &rtFECSender{enc: relay.NewFECEncoder(rtFECK, rtFECM)}
}

func (s *rtFECSender) flushLocked() [][]byte {
	if s.cnt == 0 {
		return nil
	}
	var pkts [][]byte
	for s.cnt < rtFECK {
		seq := s.blockStart + uint32(s.cnt)
		pkts = append(pkts, s.enc.EncodeFEC(nil, seq, 0))
		s.cnt++
	}
	parityBase := s.blockStart + uint32(rtFECK)
	pkts = append(pkts, s.enc.GetParityPackets(parityBase, 0)...)
	s.blockStart += uint32(rtFECK + rtFECM)
	s.cnt = 0
	return pkts
}

func (s *rtFECSender) encode(payload []byte) [][]byte {
	if len(payload) > rtDatagramMaxProtected || s.enc == nil {
		return [][]byte{append([]byte{rtMarkerRaw}, payload...)}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var pkts [][]byte
	if s.cnt > 0 && time.Since(s.lastAt) >= rtFECBlockWait {
		pkts = s.flushLocked()
	}
	s.lastAt = time.Now()

	seq := s.blockStart + uint32(s.cnt)
	pkts = append(pkts, s.enc.EncodeFEC(payload, seq, 0))
	s.cnt++
	if s.cnt == rtFECK {
		parityBase := s.blockStart + uint32(rtFECK)
		pkts = append(pkts, s.enc.GetParityPackets(parityBase, 0)...)
		s.blockStart += uint32(rtFECK + rtFECM)
		s.cnt = 0
	}
	return pkts
}

type rtFECReceiver struct {
	mu       sync.Mutex
	dec      *relay.FECDecoder
	received map[uint32][]byte
	firstAt  map[uint32]time.Time
}

func newRTFECReceiver() *rtFECReceiver {
	return &rtFECReceiver{
		dec:      relay.NewFECDecoder(rtFECK, rtFECM),
		received: make(map[uint32][]byte),
		firstAt:  make(map[uint32]time.Time),
	}
}

func (r *rtFECReceiver) ingest(packet []byte) {
	if len(packet) < 9 || packet[0] != rtMarkerFEC {
		return
	}
	seq := binary.BigEndian.Uint32(packet[1:5])
	blockSize := uint32(rtFECK + rtFECM)
	blockStart := (seq / blockSize) * blockSize
	posInBlock := seq - blockStart

	r.mu.Lock()
	if _, ok := r.firstAt[blockStart]; !ok {
		r.firstAt[blockStart] = time.Now()
	}
	if posInBlock < uint32(rtFECK) {
		dataLen := binary.BigEndian.Uint16(packet[7:9])
		if int(dataLen)+9 <= len(packet) {
			r.received[seq] = append([]byte{}, packet[9:9+int(dataLen)]...)
		}
	}
	r.mu.Unlock()

	r.dec.DecodeFEC(packet, seq)
}

func (r *rtFECReceiver) sweep(deliver func([]byte)) {
	var due []uint32

	r.mu.Lock()
	now := time.Now()
	for bs, t := range r.firstAt {
		have := 0
		for i := uint32(0); i < uint32(rtFECK); i++ {
			if _, ok := r.received[bs+i]; ok {
				have++
			}
		}
		if have == rtFECK || now.Sub(t) >= rtFECBlockWait {
			due = append(due, bs)
		}
	}
	for _, bs := range due {
		delete(r.firstAt, bs)
	}
	r.mu.Unlock()

	for _, bs := range due {
		r.deliverBlock(bs, deliver)
	}
}

func (r *rtFECReceiver) deliverBlock(blockStart uint32, deliver func([]byte)) {
	r.mu.Lock()
	missing := false
	for i := uint32(0); i < uint32(rtFECK); i++ {
		if _, ok := r.received[blockStart+i]; !ok {
			missing = true
			break
		}
	}
	r.mu.Unlock()

	if missing {
		recovered := r.dec.Reconstruct(blockStart, rtFECK, rtFECM)
		r.mu.Lock()
		ri := 0
		for i := uint32(0); i < uint32(rtFECK); i++ {
			if _, ok := r.received[blockStart+i]; !ok && ri < len(recovered) {
				r.received[blockStart+i] = recovered[ri]
				ri++
			}
		}
		r.mu.Unlock()
	}

	r.mu.Lock()
	payloads := make([][]byte, 0, rtFECK)
	for i := uint32(0); i < uint32(rtFECK); i++ {
		if p, ok := r.received[blockStart+i]; ok && len(p) > 0 {
			payloads = append(payloads, p)
		}
		delete(r.received, blockStart+i)
	}
	for i := uint32(rtFECK); i < uint32(rtFECK+rtFECM); i++ {
		delete(r.received, blockStart+i)
	}
	r.mu.Unlock()

	r.dec.Forget(blockStart, rtFECK, rtFECM)

	for _, p := range payloads {
		deliver(p)
	}
}

func processIncomingRTDatagram(packet []byte, recv *rtFECReceiver, deliver func([]byte)) {
	if len(packet) == 0 {
		return
	}
	switch packet[0] {
	case rtMarkerRaw:
		deliver(append([]byte{}, packet[1:]...))
	case rtMarkerFEC:
		recv.ingest(packet)
	}
}

type RTDatagramClient struct {
	conn     *quicgo.Conn
	sender   *rtFECSender
	receiver *rtFECReceiver
	cancel   context.CancelFunc

	mu      sync.Mutex
	targets map[string]chan []byte
}

func NewRTDatagramClient(conn *quicgo.Conn) *RTDatagramClient {
	ctx, cancel := context.WithCancel(context.Background())
	c := &RTDatagramClient{
		conn:     conn,
		sender:   newRTFECSender(),
		receiver: newRTFECReceiver(),
		cancel:   cancel,
		targets:  make(map[string]chan []byte),
	}
	go c.receiveLoop(ctx)
	go c.sweepLoop(ctx)
	return c
}

func (c *RTDatagramClient) deliver(payload []byte) {
	host, port, data, ok := decodeRTAddr(payload)
	if !ok {
		return
	}
	key := net.JoinHostPort(host, strconv.Itoa(int(port)))
	c.mu.Lock()
	if ch := c.targets[key]; ch != nil {
		select {
		case ch <- data:
		default:
			traceLog.Warnw("rt_datagram_client_channel_full", "target", key)
		}
	}
	c.mu.Unlock()
}

func (c *RTDatagramClient) receiveLoop(ctx context.Context) {
	for {
		data, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		processIncomingRTDatagram(data, c.receiver, c.deliver)
	}
}

func (c *RTDatagramClient) sweepLoop(ctx context.Context) {
	t := time.NewTicker(rtFECSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.receiver.sweep(c.deliver)
		}
	}
}

func (c *RTDatagramClient) SendUDP(host string, port uint16, payload []byte) error {
	full := append(encodeRTAddr(host, port), payload...)
	for _, pkt := range c.sender.encode(full) {
		if err := c.conn.SendDatagram(pkt); err != nil {
			return err
		}
	}
	return nil
}

func (c *RTDatagramClient) RegisterTarget(host string, port uint16) (<-chan []byte, func()) {
	key := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ch := make(chan []byte, 64)
	c.mu.Lock()
	c.targets[key] = ch
	c.mu.Unlock()
	var once sync.Once
	unregister := func() {
		once.Do(func() {
			c.mu.Lock()
			if c.targets[key] == ch {
				delete(c.targets, key)
				close(ch)
			}
			c.mu.Unlock()
		})
	}
	return ch, unregister
}

func (c *RTDatagramClient) Close() {
	c.cancel()
}


type rtServerSession struct {
	conn     *quicgo.Conn
	sender   *rtFECSender
	receiver *rtFECReceiver
	cancel   context.CancelFunc

	mu      sync.Mutex
	targets map[string]net.Conn
}

func newRTServerSession(conn *quicgo.Conn) *rtServerSession {
	ctx, cancel := context.WithCancel(context.Background())
	s := &rtServerSession{
		conn:     conn,
		sender:   newRTFECSender(),
		receiver: newRTFECReceiver(),
		cancel:   cancel,
		targets:  make(map[string]net.Conn),
	}
	go s.receiveLoop(ctx)
	go s.sweepLoop(ctx)
	return s
}

func (s *rtServerSession) receiveLoop(ctx context.Context) {
	for {
		data, err := s.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		processIncomingRTDatagram(data, s.receiver, s.handlePayload)
	}
}

func (s *rtServerSession) sweepLoop(ctx context.Context) {
	t := time.NewTicker(rtFECSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.receiver.sweep(s.handlePayload)
		}
	}
}

func (s *rtServerSession) handlePayload(payload []byte) {
	host, port, udpPayload, ok := decodeRTAddr(payload)
	if !ok {
		return
	}
	key := net.JoinHostPort(host, strconv.Itoa(int(port)))

	s.mu.Lock()
	uc, exists := s.targets[key]
	if !exists {
		var err error
		uc, err = net.Dial("udp", key)
		if err != nil {
			s.mu.Unlock()
			traceLog.Infow("rt_datagram_target_dial_failed", "target", key, "err", err.Error())
			return
		}
		traceLog.Infow("rt_datagram_target_dial", "target", key)
		s.targets[key] = uc
		go s.pumpTargetResponses(uc, key, host, port)
	}
	s.mu.Unlock()
	_, _ = uc.Write(udpPayload)
}

func (s *rtServerSession) pumpTargetResponses(uc net.Conn, key, host string, port uint16) {
	defer func() {
		s.mu.Lock()
		delete(s.targets, key)
		s.mu.Unlock()
		uc.Close()
	}()
	buf := make([]byte, 65535)
	for {
		_ = uc.SetReadDeadline(time.Now().Add(rtUDPTargetIdle))
		n, err := uc.Read(buf)
		if err != nil {
			return
		}
		payload := append(encodeRTAddr(host, port), buf[:n]...)
		for _, pkt := range s.sender.encode(payload) {
			if err := s.conn.SendDatagram(pkt); err != nil {
				traceLog.Warnw("rt_datagram_target_send_failed", "target", key, "err", err.Error())
			}
		}
	}
}

func (s *rtServerSession) Close() {
	s.cancel()
	s.mu.Lock()
	for _, uc := range s.targets {
		uc.Close()
	}
	s.mu.Unlock()
}

type rtConnCtxKey struct{}

var rtConnContextKey = rtConnCtxKey{}

var (
	rtSessionsMu sync.Mutex
	rtSessions   = make(map[string]*rtServerSession)
)

func RegisterRTQUICConn(sessionID []byte, conn *quicgo.Conn) {
	if conn == nil || len(sessionID) == 0 {
		return
	}
	key := string(sessionID)
	rtSessionsMu.Lock()
	if old, ok := rtSessions[key]; ok {
		old.Close()
	}
	sess := newRTServerSession(conn)
	rtSessions[key] = sess
	rtSessionsMu.Unlock()
	traceLog.Infow("rt_datagram_session_registered", "remote", conn.RemoteAddr().String())

	go func() {
		<-conn.Context().Done()
		rtSessionsMu.Lock()
		if rtSessions[key] == sess {
			delete(rtSessions, key)
		}
		rtSessionsMu.Unlock()
		sess.Close()
	}()
}
