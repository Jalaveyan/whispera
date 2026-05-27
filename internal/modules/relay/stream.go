package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
	"golang.org/x/net/proxy"

	"whispera/internal/dns"
)

var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65536)
	},
}

// streamReadBufPool holds buffers for readFromTarget goroutines (HeaderSize+65536).
var streamReadBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, HeaderSize+65536)
		return &buf
	},
}

// dohResolver resolves upstream hostnames over DNS-over-HTTPS (Cloudflare /
// Google / Yandex, port 443) with its own LRU cache. DoH avoids both the
// flaky systemd-resolved stub and any transparent :53 hijacking by the host
// provider, and is tamper-resistant on the wire.
var dohResolver = dns.NewResolver(dns.DefaultConfig())

// fastResolver is the plaintext-UDP fallback used only when DoH is
// unreachable (e.g. outbound 443 to the DoH providers is blocked).
var fastResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.DialContext(ctx, "udp", "1.1.1.1:53")
		if err != nil {
			conn, err = d.DialContext(ctx, "udp", "8.8.8.8:53")
		}
		return conn, err
	},
}

func lookupIPCached(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ips, err := dohResolver.Resolve(ctx, host); err == nil && len(ips) > 0 {
		return ips, nil
	}

	// DoH unreachable — fall back to plaintext UDP so resolution never
	// regresses below the previous behavior.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	return fastResolver.LookupIP(ctx2, "ip", host)
}

// dialTarget resolves host through the cached resolver (which queries 1.1.1.1
// directly, bypassing a slow/flaky systemd-resolved stub) and dials the
// resulting IPs in order. Only the local Direct dialer benefits — upstream
// proxies resolve remotely, and bare IP targets need no lookup, so both pass
// through untouched. On lookup failure it falls back to the dialer's own
// resolution so behavior never regresses below the previous path.
func dialTarget(dialer proxy.Dialer, network, host string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if dialer != proxy.Direct || net.ParseIP(host) != nil {
		return dialer.Dial(network, addr)
	}
	ips, err := lookupIPCached(host)
	if err != nil || len(ips) == 0 {
		return dialer.Dial(network, addr)
	}
	var lastErr error
	for _, ip := range ips {
		conn, derr := dialer.Dial(network, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

type Stream struct {
	ID         uint16
	fsm        *FSM
	Protocol   uint8
	Profile    uint8
	TargetAddr string
	TargetPort uint16

	writer ResponseWriter

	conn net.Conn

	udpConn *net.UDPConn

	sendWindow int64
	windowCond *sync.Cond

	incoming  chan []byte
	outgoing  chan []byte
	closeChan chan struct{}

	bytesIn  uint64
	bytesOut uint64
	created  time.Time
	lastT    time.Time

	RetryCount int

	dialer proxy.Dialer

	adaptiveTimeout *AdaptiveTimeout

	earlyDataBuf []byte
	earlyDataMu  sync.Mutex

	fecEncoder     *FECEncoder
	fecDecoder     *FECDecoder
	fecEnabled     bool
	packetLossRate float32
	lossCheckTime  time.Time

	sackTracker *SACKTracker
	sackEnabled bool
	seqNum      uint32

	trafficShaper *TrafficShaper

	connPool *ConnectionPool

	closeOnce sync.Once
	mu        sync.RWMutex
}

func NewStream(id uint16, proto uint8, addr string, port uint16, profile uint8, writer ResponseWriter, dialer proxy.Dialer, pool *ConnectionPool) *Stream {
	s := &Stream{
		ID:              id,
		Protocol:        proto,
		Profile:         profile,
		TargetAddr:      addr,
		TargetPort:      port,
		writer:          writer,
		sendWindow:      4 * 1024 * 1024,
		incoming:        make(chan []byte, 65536),
		outgoing:        make(chan []byte, 65536),
		closeChan:       make(chan struct{}),
		created:         time.Now(),
		lastT:           time.Now(),
		dialer:          dialer,
		adaptiveTimeout: NewAdaptiveTimeout(100),
		earlyDataBuf:    make([]byte, 0, 65536),
		fecEncoder:      NewFECEncoder(10, 5),
		fecDecoder:      NewFECDecoder(10, 5),
		fecEnabled:      false,
		sackTracker:     NewSACKTracker(),
		sackEnabled:     true,
		seqNum:          0,
		lossCheckTime:   time.Now(),

		trafficShaper: NewTrafficShaper(2.5),
		connPool:      pool,
	}
	s.windowCond = sync.NewCond(&s.mu)
	s.fsm = NewFSM(s)
	return s
}

func (s *Stream) dialWithHappyEyeballs(ctx context.Context, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}

	ips, err := lookupIPCached(host)
	if err != nil {
		return nil, err
	}

	var ipv4, ipv6 net.IP
	for _, ip := range ips {
		if ipv4 == nil && ip.To4() != nil {
			ipv4 = ip
		} else if ipv6 == nil && ip.To16() != nil && ip.To4() == nil {
			ipv6 = ip
		}
	}

	baseTimeout := 1 * time.Second
	dialTimeout := s.adaptiveTimeout.GetTimeoutFor(baseTimeout)

	if dialTimeout < 100*time.Millisecond {
		dialTimeout = 100 * time.Millisecond
	}
	if dialTimeout > 2*time.Second {
		dialTimeout = 2 * time.Second
	}

	if ipv4 != nil && ipv6 == nil {
		return (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp4", net.JoinHostPort(ipv4.String(), portStr))
	}
	if ipv6 != nil && ipv4 == nil {
		return (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp6", net.JoinHostPort(ipv6.String(), portStr))
	}

	connChan := make(chan net.Conn, 2)
	errChan := make(chan error, 2)
	startTime := time.Now()

	if ipv6 != nil {
		go func() {
			conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp6", net.JoinHostPort(ipv6.String(), portStr))
			if err != nil {
				errChan <- err
			} else {
				connChan <- conn
				s.adaptiveTimeout.Record(time.Since(startTime))
			}
		}()
	}

	if ipv4 != nil {
		go func() {
			conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp4", net.JoinHostPort(ipv4.String(), portStr))
			if err != nil {
				errChan <- err
			} else {
				connChan <- conn
				s.adaptiveTimeout.Record(time.Since(startTime))
			}
		}()
	}

	for i := 0; i < 2; i++ {
		select {
		case conn := <-connChan:
			return conn, nil
		case <-errChan:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("both IPv4 and IPv6 connection attempts failed")
}

func (s *Stream) SetWriter(w ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writer = w
}

func (s *Stream) sendFrame(f *Frame) error {
	writer := s.writer

	if writer == nil {
		return fmt.Errorf("no writer")
	}

	bytes, err := f.Encode()
	if err != nil {
		return err
	}

	return writer.Write(bytes)
}

func (s *Stream) Connect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.fsm.Event(EventStartConnect); err != nil {
		return err
	}

	connectTimeout := 5 * time.Second

	target := net.JoinHostPort(s.TargetAddr, fmt.Sprintf("%d", s.TargetPort))

	var err error
	switch s.Protocol {
	case ProtoTCP:
		if conn := s.connPool.Get(target); conn != nil {
			s.conn = conn
		} else {
			ctx, cancel := context.WithTimeout(ctx, connectTimeout)
			defer cancel()

			var conn net.Conn
			conn, err = s.dialWithHappyEyeballs(ctx, target)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			s.conn = conn
		}

		go s.speculativeConnect(target)

		if tcpConn, ok := s.conn.(*net.TCPConn); ok {
			bufferSize := 8 * 1024 * 1024
			tcpConn.SetReadBuffer(bufferSize)
			tcpConn.SetWriteBuffer(bufferSize)
			tcpConn.SetNoDelay(true)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(15 * time.Second)
		}

		if err := s.fsm.Event(EventConnectOK); err != nil {
			s.conn.Close()
			return err
		}

		s.flushEarlyData()

		go s.readFromTarget()

	case ProtoUDP:
		if s.TargetAddr == "0.0.0.0" || s.TargetAddr == "::" {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			conn.SetReadBuffer(32 * 1024 * 1024)
			conn.SetWriteBuffer(32 * 1024 * 1024)
			s.udpConn = conn

			if err := s.fsm.Event(EventConnectOK); err != nil {
				s.udpConn.Close()
				return err
			}

			go s.readRelayUDP()
		} else {
			var addr *net.UDPAddr
			addr, err = net.ResolveUDPAddr("udp4", target)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			var conn *net.UDPConn
			conn, err = net.DialUDP("udp4", nil, addr)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			conn.SetReadBuffer(32 * 1024 * 1024)
			conn.SetWriteBuffer(32 * 1024 * 1024)
			s.udpConn = conn

			if err := s.fsm.Event(EventConnectOK); err != nil {
				s.udpConn.Close()
				return err
			}

			go s.readUDPFromTarget()
		}
	}

	return nil
}

func (s *Stream) speculativeConnect(target string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := s.dialWithHappyEyeballs(ctx, target)
		if err == nil {
			s.connPool.Put(target, conn)
		}
	}()
}

func (s *Stream) Write(data []byte) error {
	s.mu.RLock()
	state := s.fsm.CurrentState()
	conn := s.conn
	udpConn := s.udpConn
	s.mu.RUnlock()

	if state != StateConnected {
		s.bufferEarlyData(data)
		return nil
	}

	if err := s.fsm.Event(EventData); err != nil {
		return err
	}

	s.lastT = time.Now()

	if s.Protocol == ProtoTCP && conn != nil {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		s.bytesOut += uint64(n)
		return nil
	} else if s.Protocol == ProtoUDP && udpConn != nil {
		s.sackTracker.RecordPacket(s.seqNum)
		s.seqNum++

		n, err := udpConn.Write(data)
		if err != nil {
			return err
		}
		s.bytesOut += uint64(n)
		return nil
	}

	return ErrStreamClosed
}

func (s *Stream) UpdateWindow(increment uint32) {
	s.mu.Lock()
	s.sendWindow += int64(increment)
	if s.sendWindow > 80*1024*1024 {
		s.sendWindow = 80 * 1024 * 1024
	}
	s.windowCond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) HandleUDPData(data []byte) error {
	s.mu.RLock()
	udpConn := s.udpConn
	s.mu.RUnlock()

	if udpConn == nil {
		return ErrStreamClosed
	}

	s.lastT = time.Now()

	if len(data) < 4 {
		return fmt.Errorf("short UDP data")
	}

	offset := 0
	atyp := data[offset]
	offset++

	var addr *net.UDPAddr
	var ip net.IP

	switch atyp {
	case 0x01:
		if len(data) < offset+4 {
			return fmt.Errorf("short IPv4")
		}
		ip = net.IP(data[offset : offset+4])
		offset += 4
	case 0x04:
		if len(data) < offset+16 {
			return fmt.Errorf("short IPv6")
		}
		ip = net.IP(data[offset : offset+16])
		offset += 16
	case 0x03:
		if len(data) < offset+1 {
			return fmt.Errorf("short domain len")
		}
		l := int(data[offset])
		offset++
		if len(data) < offset+l {
			return fmt.Errorf("short domain")
		}
		domain := string(data[offset : offset+l])
		offset += l
		if ips, err := lookupIPCached(domain); err == nil && len(ips) > 0 {
			ip = ips[0]
		} else {
			return err
		}
	default:
		return fmt.Errorf("unknown ATYP %d", atyp)
	}

	if len(data) < offset+2 {
		return fmt.Errorf("short port")
	}
	port := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	addr = &net.UDPAddr{IP: ip, Port: int(port)}
	payload := data[offset:]

	if udpConn.RemoteAddr() != nil {
		n, err := udpConn.Write(payload)
		if err != nil {
			return err
		}
		s.bytesOut += uint64(n)
		return nil
	}

	n, err := udpConn.WriteToUDP(payload, addr)
	if err != nil {
		return err
	}
	s.bytesOut += uint64(n)
	return nil
}

func (s *Stream) readFromTarget() {
	defer func() {
		if r := recover(); r != nil {
		}
		s.Close()
	}()

	bufp := streamReadBufPool.Get().(*[]byte)
	buf := *bufp
	defer streamReadBufPool.Put(bufp)
	s.conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	for {
		n, err := s.conn.Read(buf[HeaderSize:])
		if err != nil {
			if err != io.EOF {
				s.fsm.Event(EventError)
			} else {
				s.fsm.Event(EventPeerClose)
			}
			return
		}

		if n > 0 {
			s.bytesIn += uint64(n)
			now := time.Now()
			s.lastT = now
			s.conn.SetReadDeadline(now.Add(60 * time.Second))

			if s.sackEnabled {
				s.sackTracker.RecordPacket(s.seqNum)
				s.seqNum++
			}

			if s.fecEnabled || s.packetLossRate > 2.0 {
				encodedBuf := s.fecEncoder.EncodeFEC(buf[HeaderSize:HeaderSize+n], s.seqNum, HeaderSize)
				s.seqNum++

				WriteFrameHeader(encodedBuf, s.ID, FrameData, 0, len(encodedBuf)-HeaderSize)

				if err := s.writer.Write(encodedBuf); err != nil {
					packetPool.Put(encodedBuf)
					return
				}
				packetPool.Put(encodedBuf)

				parityPackets := s.fecEncoder.GetParityPackets(s.seqNum, HeaderSize)
				for _, pkt := range parityPackets {
					WriteFrameHeader(pkt, s.ID, FrameData, 0, len(pkt)-HeaderSize)
					s.writer.Write(pkt)
					packetPool.Put(pkt)
					s.seqNum++
				}
			} else {
				WriteFrameHeader(buf, s.ID, FrameData, 0, n)
				if err := s.writer.Write(buf[:HeaderSize+n]); err != nil {
					return
				}
			}

			paddingNeeded := s.trafficShaper.Update(n)
			if paddingNeeded > 0 {
				padBuf := packetPool.Get().([]byte)
				if cap(padBuf) < HeaderSize+paddingNeeded {
					packetPool.Put(padBuf)
					padBuf = make([]byte, HeaderSize+paddingNeeded)
				}
				padBuf = padBuf[:HeaderSize+paddingNeeded]

				WriteFrameHeader(padBuf, s.ID, FramePadding, 0, paddingNeeded)
				s.writer.Write(padBuf)
				packetPool.Put(padBuf)
			}
		}
	}
}

func (s *Stream) readUDPFromTarget() {
	defer func() {
		if r := recover(); r != nil {
		}
		s.Close()
	}()

	const Headroom = 300

	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		buf := packetPool.Get().([]byte)
		if cap(buf) < Headroom+4096 {
			packetPool.Put(buf)
			buf = make([]byte, Headroom+4096)
		}

		s.udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := s.udpConn.Read(buf[Headroom:])
		if err != nil {
			packetPool.Put(buf)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if isClosedConnError(err) {
				return
			}
			s.fsm.Event(EventError)
			return
		}

		if n > 0 {
			s.bytesIn += uint64(n)
			s.lastT = time.Now()

			rAddr := s.udpConn.RemoteAddr()
			udpAddr, ok := rAddr.(*net.UDPAddr)
			if !ok {
				continue
			}

			atyp := uint8(0x01)
			if udpAddr.IP.To4() == nil {
				atyp = 0x04
			}

			packet, err := SealUDPData(buf[:Headroom+n], s.ID, atyp, udpAddr.IP.String(), uint16(udpAddr.Port), Headroom)
			if err != nil {
				packetPool.Put(buf)
				return
			}

			if err := s.writer.Write(packet); err != nil {
				packetPool.Put(buf)
			} else {
				packetPool.Put(buf)
			}
		} else {
			packetPool.Put(buf)
		}
	}
}

func (s *Stream) readRelayUDP() {
	defer func() {
		if r := recover(); r != nil {
		}
		s.Close()
	}()

	const Headroom = 300

	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		buf := packetPool.Get().([]byte)
		if cap(buf) < Headroom+4096 {
			packetPool.Put(buf)
			buf = make([]byte, Headroom+4096)
		}

		s.udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, addr, err := s.udpConn.ReadFromUDP(buf[Headroom:])
		if err != nil {
			packetPool.Put(buf)
			if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
				continue
			}
			if isClosedConnError(err) {
				return
			}
			continue
		}

		if n > 0 {
			s.bytesIn += uint64(n)
			s.lastT = time.Now()

			atyp := uint8(0x01)
			if addr.IP.To4() == nil {
				atyp = 0x04
			}

			packet, err := SealUDPData(buf[:Headroom+n], s.ID, atyp, addr.IP.String(), uint16(addr.Port), Headroom)
			if err != nil {
				fmt.Printf("[RELAY] UDP Seal Error: %v\n", err)
				packetPool.Put(buf)
				return
			}

			if err := s.writer.Write(packet); err != nil {
				packetPool.Put(buf)
				return
			}
			packetPool.Put(buf)
		} else {
			packetPool.Put(buf)
		}
	}
}

func (s *Stream) Close() {
	s.fsm.Event(EventLocalClose)
}

func (s *Stream) cleanupResources() {
	s.closeOnce.Do(func() {
		close(s.closeChan)
		s.windowCond.Broadcast()
	})

	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	if s.udpConn != nil {
		s.udpConn.Close()
		s.udpConn = nil
	}
}

func (s *Stream) IsActive() bool {
	return !s.fsm.IsClosed()
}

type StreamManager struct {
	streams  map[uint16]*Stream
	mu       sync.RWMutex
	idGen    *StreamIDGenerator
	dialer   proxy.Dialer
	connPool *ConnectionPool

	ctx    context.Context
	cancel context.CancelFunc
}

func NewStreamManager(dialer proxy.Dialer) *StreamManager {
	ctx, cancel := context.WithCancel(context.Background())
	sm := &StreamManager{
		streams:  make(map[uint16]*Stream),
		idGen:    NewStreamIDGenerator(),
		dialer:   dialer,
		ctx:      ctx,
		cancel:   cancel,
		connPool: NewConnectionPool(1*time.Second, 64),
	}

	go sm.cleanupLoop()

	return sm
}

func (sm *StreamManager) HandlePreConnect(streamID uint16, payload *ConnectPayload, writer ResponseWriter) (*Stream, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.streams[streamID]; exists {
		return nil, fmt.Errorf("stream id %d collision", streamID)
	}

	stream := NewStream(streamID, payload.Protocol, payload.Addr, payload.Port, ProfileBalanced, writer, sm.dialer, sm.connPool)
	sm.streams[streamID] = stream
	return stream, nil
}

func (sm *StreamManager) HandleConnect(streamID uint16, payload *ConnectPayload, writer ResponseWriter) error {
	stream, err := sm.HandlePreConnect(streamID, payload, writer)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(sm.ctx, 10*time.Second)
	defer cancel()

	if err := stream.Connect(ctx); err != nil {
		sm.RemoveStream(streamID)
		return err
	}

	return nil
}

func (sm *StreamManager) HandleData(streamID uint16, data []byte) error {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if !ok {
		return ErrStreamNotFound
	}

	return stream.Write(data)
}

func (sm *StreamManager) HandleUDPData(streamID uint16, data []byte) error {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if !ok {
		return ErrStreamNotFound
	}

	return stream.HandleUDPData(data)
}

func (sm *StreamManager) HandleWindowUpdate(streamID uint16, increment uint32) {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if ok {
		stream.UpdateWindow(increment)
	}
}

func (sm *StreamManager) HandleClose(streamID uint16) {
	sm.RemoveStream(streamID)
}

func (sm *StreamManager) GetStream(id uint16) (*Stream, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	stream, ok := sm.streams[id]
	return stream, ok
}

func (sm *StreamManager) RemoveStream(id uint16) {
	sm.mu.Lock()
	stream, ok := sm.streams[id]
	if ok {
		delete(sm.streams, id)
	}
	sm.mu.Unlock()

	if stream != nil {
		stream.Close()
	}
}

func (sm *StreamManager) CloseAll() {
	sm.cancel()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, stream := range sm.streams {
		stream.Close()
		delete(sm.streams, id)
	}
}

func (sm *StreamManager) Stats() (activeStreams int, totalBytesIn, totalBytesOut uint64) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	activeStreams = len(sm.streams)
	for _, stream := range sm.streams {
		totalBytesIn += stream.bytesIn
		totalBytesOut += stream.bytesOut
	}
	return
}

func (sm *StreamManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.cleanup()
		}
	}
}

func (sm *StreamManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	staleTimeout := 5 * time.Minute

	for id, stream := range sm.streams {
		state := stream.fsm.CurrentState()

		if state == StateClosed {
			delete(sm.streams, id)
			continue
		}

		if now.Sub(stream.lastT) > staleTimeout {
			stream.Close()
			delete(sm.streams, id)
		}
	}
}

func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

func (s *Stream) bufferEarlyData(data []byte) {
	s.earlyDataMu.Lock()
	defer s.earlyDataMu.Unlock()

	available := cap(s.earlyDataBuf) - len(s.earlyDataBuf)
	if available <= 0 {
		return
	}
	if len(data) > available {
		data = data[:available]
	}
	s.earlyDataBuf = append(s.earlyDataBuf, data...)
}

func (s *Stream) flushEarlyData() {
	s.earlyDataMu.Lock()
	defer s.earlyDataMu.Unlock()

	if len(s.earlyDataBuf) == 0 {
		return
	}

	conn := s.conn
	if conn == nil {
		return
	}

	_, err := conn.Write(s.earlyDataBuf)
	if err != nil {
		fmt.Printf("[0-RTT] Early data flush error: %v\n", err)
	}

	s.bytesOut += uint64(len(s.earlyDataBuf))
	s.earlyDataBuf = s.earlyDataBuf[:0]
}

func (s *Stream) GetAdaptiveTimeout() time.Duration {
	return s.adaptiveTimeout.GetTimeoutFor(3 * time.Second)
}

func (s *Stream) RecordRTT(rtt time.Duration) {
	s.adaptiveTimeout.Record(rtt)
}

func (s *Stream) GetRTTStats() TimeoutStats {
	return s.adaptiveTimeout.GetStats()
}

type TrafficShaper struct {
	lastCheck  time.Time
	bytesSince int

	targetRate float64
	minPadding int
	maxPadding int

	totalBytes uint64
}

func NewTrafficShaper(targetRateMBps float64) *TrafficShaper {
	return &TrafficShaper{
		lastCheck:  time.Now(),
		targetRate: targetRateMBps * 1024 * 1024,
		minPadding: 128,
		maxPadding: 1400,
	}
}

func (ts *TrafficShaper) Update(n int) int {
	now := time.Now()
	dt := now.Sub(ts.lastCheck).Seconds()

	ts.bytesSince += n
	ts.totalBytes += uint64(n)

	if dt < 0.05 {
		return 0
	}

	currentRate := float64(ts.bytesSince) / dt

	ts.lastCheck = now
	ts.bytesSince = 0

	if currentRate < ts.targetRate {
		needed := (ts.targetRate * dt) - float64(n)

		if needed > float64(ts.minPadding) {
			pad := int(needed)
			if pad > ts.maxPadding {
				pad = ts.maxPadding
			}
			return pad
		}
	}

	return 0
}

type FECEncoder struct {
	k         int
	m         int
	enc       reedsolomon.Encoder
	shards    [][]byte
	shardSize int
	idx       int
}

func NewFECEncoder(k, m int) *FECEncoder {
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		log.Printf("[FEC] Failed to create encoder (k=%d, m=%d): %v", k, m, err)
		return nil
	}
	return &FECEncoder{
		k:      k,
		m:      m,
		enc:    enc,
		shards: make([][]byte, k+m),
	}
}

func (fe *FECEncoder) EncodeFEC(data []byte, seqNum uint32, headroom int) []byte {
	payloadLen := 7 + len(data)
	totalLen := headroom + payloadLen

	buf := packetPool.Get().([]byte)

	if cap(buf) < totalLen {
		packetPool.Put(buf)
		buf = make([]byte, totalLen)
	}

	buf = buf[:totalLen]

	ptr := headroom
	buf[ptr] = 0xFF
	binary.BigEndian.PutUint32(buf[ptr+1:ptr+5], seqNum)
	buf[ptr+5] = byte(fe.k)
	buf[ptr+6] = byte(fe.m)

	copy(buf[ptr+7:], data)

	rsShardLen := 2 + len(data)

	shardBuf := packetPool.Get().([]byte)
	if cap(shardBuf) < rsShardLen {
		packetPool.Put(shardBuf)
		shardBuf = make([]byte, rsShardLen)
	}
	shardBuf = shardBuf[:rsShardLen]

	binary.BigEndian.PutUint16(shardBuf[0:2], uint16(len(data)))
	copy(shardBuf[2:], data)

	fe.shards[fe.idx] = shardBuf
	if rsShardLen > fe.shardSize {
		fe.shardSize = rsShardLen
	}

	fe.idx++
	return buf
}

func (fe *FECEncoder) GetParityPackets(baseSeq uint32, headroom int) [][]byte {
	if fe.idx < fe.k {
		return nil
	}

	for i := 0; i < fe.k; i++ {
		shard := fe.shards[i]
		if len(shard) < fe.shardSize {
			newShard := shard[:fe.shardSize]
			for j := len(shard); j < fe.shardSize; j++ {
				newShard[j] = 0
			}
			fe.shards[i] = newShard
		}
	}

	for i := 0; i < fe.m; i++ {
		buf := packetPool.Get().([]byte)
		if cap(buf) < fe.shardSize {
			packetPool.Put(buf)
			buf = make([]byte, fe.shardSize)
		}
		fe.shards[fe.k+i] = buf[:fe.shardSize]
	}

	if err := fe.enc.Encode(fe.shards); err != nil {
		fe.reset()
		return nil
	}

	parityPackets := make([][]byte, fe.m)
	for i := 0; i < fe.m; i++ {
		parityData := fe.shards[fe.k+i]

		pktLen := 7 + len(parityData)
		totalLen := headroom + pktLen

		buf := packetPool.Get().([]byte)
		if cap(buf) < totalLen {
			packetPool.Put(buf)
			buf = make([]byte, totalLen)
		}
		buf = buf[:totalLen]

		ptr := headroom
		buf[ptr] = 0xFF
		binary.BigEndian.PutUint32(buf[ptr+1:ptr+5], baseSeq+uint32(i))
		buf[ptr+5] = byte(fe.k)
		buf[ptr+6] = byte(fe.m)
		copy(buf[ptr+7:], parityData)

		parityPackets[i] = buf
	}

	for i := 0; i < fe.k+fe.m; i++ {
		if fe.shards[i] != nil {
			packetPool.Put(fe.shards[i])
			fe.shards[i] = nil
		}
	}

	fe.idx = 0
	fe.shardSize = 0

	return parityPackets
}

func (fe *FECEncoder) reset() {
	for i := 0; i < len(fe.shards); i++ {
		if fe.shards[i] != nil {
			packetPool.Put(fe.shards[i])
			fe.shards[i] = nil
		}
	}
	fe.idx = 0
	fe.shardSize = 0
}

type FECDecoder struct {
	k             int
	m             int
	packetBuffer  map[uint32][]byte
	bufferMutex   sync.RWMutex
	recoveryCount int
	totalPackets  int
}

func NewFECDecoder(k, m int) *FECDecoder {
	return &FECDecoder{
		k:            k,
		m:            m,
		packetBuffer: make(map[uint32][]byte),
	}
}

func (fd *FECDecoder) DecodeFEC(packet []byte, seqNum uint32) (recovered []byte, canRecover bool) {
	fd.bufferMutex.Lock()
	defer fd.bufferMutex.Unlock()

	fd.totalPackets++

	if len(packet) < 7 {
		return nil, false
	}

	if packet[0] != 0xFF {
		return packet[7:], false
	}

	recvSeqNum := binary.BigEndian.Uint32(packet[1:5])

	fd.packetBuffer[recvSeqNum] = packet[7:]

	return nil, false
}

func (fd *FECDecoder) Reconstruct(blockStartSeq uint32, k, m int) [][]byte {
	shards := make([][]byte, k+m)
	haveObj := 0

	for i := 0; i < k+m; i++ {
		seq := blockStartSeq + uint32(i)
		if data, ok := fd.packetBuffer[seq]; ok {
			shards[i] = data
			haveObj++
		}
	}

	if haveObj < k {
		return nil
	}

	enc, err := reedsolomon.New(k, m)
	if err != nil {
		return nil
	}

	if err := enc.Reconstruct(shards); err != nil {
		return nil
	}

	var recovered [][]byte
	for i := 0; i < k; i++ {
		seq := blockStartSeq + uint32(i)
		if _, ok := fd.packetBuffer[seq]; !ok {
			shard := shards[i]
			if len(shard) < 2 {
				continue
			}
			dataLen := binary.BigEndian.Uint16(shard[0:2])
			if int(dataLen)+2 > len(shard) {
				continue
			}
			data := shard[2 : 2+dataLen]

			res := packetPool.Get().([]byte)
			if cap(res) < len(data) {
				packetPool.Put(res)
				res = make([]byte, len(data))
			}
			res = res[:len(data)]
			copy(res, data)

			recovered = append(recovered, res)
		}
	}

	return recovered
}

type SACKTracker struct {
	receivedRanges []PacketRange
	mutex          sync.RWMutex
	maxSeqNum      uint32
	packetCount    int
	lossCount      int
}

type PacketRange struct {
	Start uint32
	End   uint32
}

func NewSACKTracker() *SACKTracker {
	return &SACKTracker{
		receivedRanges: make([]PacketRange, 0),
		packetCount:    0,
		lossCount:      0,
	}
}

func (st *SACKTracker) RecordPacket(seqNum uint32) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	st.packetCount++

	if seqNum > st.maxSeqNum {
		for missing := st.maxSeqNum + 1; missing < seqNum; missing++ {
			st.lossCount++
		}
		st.maxSeqNum = seqNum
	}

	st.addToRanges(seqNum)
}

func (st *SACKTracker) addToRanges(seqNum uint32) {
	found := false
	for i := range st.receivedRanges {
		if seqNum >= st.receivedRanges[i].Start-1 && seqNum <= st.receivedRanges[i].End+1 {
			if seqNum < st.receivedRanges[i].Start {
				st.receivedRanges[i].Start = seqNum
			}
			if seqNum > st.receivedRanges[i].End {
				st.receivedRanges[i].End = seqNum
			}
			found = true
			break
		}
	}

	if !found {
		st.receivedRanges = append(st.receivedRanges, PacketRange{Start: seqNum, End: seqNum})
	}
}

func (st *SACKTracker) GetMissingPackets(upTo uint32) []uint32 {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	missing := make([]uint32, 0)

	lastEnd := uint32(0)
	for _, r := range st.receivedRanges {
		for seq := lastEnd + 1; seq < r.Start; seq++ {
			if seq <= upTo {
				missing = append(missing, seq)
			}
		}
		lastEnd = r.End
	}

	for seq := lastEnd + 1; seq <= upTo; seq++ {
		missing = append(missing, seq)
	}

	return missing
}

func (st *SACKTracker) GetPacketLossRate() float32 {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	if st.packetCount == 0 {
		return 0
	}

	return float32(st.lossCount) / float32(st.packetCount+st.lossCount) * 100
}

func (s *Stream) GetFECStats() map[string]interface{} {
	return map[string]interface{}{
		"fecEnabled":     s.fecEnabled,
		"packetLossRate": s.packetLossRate,
		"recoveryCount":  s.fecDecoder.recoveryCount,
		"totalPackets":   s.fecDecoder.totalPackets,
	}
}

func (s *Stream) GetSACKStats() map[string]interface{} {
	return map[string]interface{}{
		"packetCount": s.sackTracker.packetCount,
		"lossCount":   s.sackTracker.lossCount,
		"lossRate":    s.sackTracker.GetPacketLossRate(),
		"rangeCount":  len(s.sackTracker.receivedRanges),
	}
}
