package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"whispera/common/dns"

	"golang.org/x/net/proxy"
)

var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65536)
	},
}

var streamReadBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, HeaderSize+65536)
		return &buf
	},
}

var dohResolver = dns.NewResolver(dns.DefaultConfig())

func lookupIPCached(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dohResolver.Resolve(ctx, host)
}

const targetDialTimeout = 15 * time.Second

func dialTarget(dialer proxy.Dialer, network, host string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ctx, cancel := context.WithTimeout(context.Background(), targetDialTimeout)
	defer cancel()
	dial := func(a string) (net.Conn, error) {
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, a)
		}
		return dialer.Dial(network, a)
	}
	if dialer != proxy.Direct || net.ParseIP(host) != nil {
		return dial(addr)
	}
	ips, err := lookupIPCached(host)
	if err != nil || len(ips) == 0 {
		return dial(addr)
	}
	var lastErr error
	for _, ip := range ips {
		conn, derr := dial(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
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

	bytesIn   uint64
	bytesOut  uint64
	created   time.Time
	lastTNano int64

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
		lastTNano:       time.Now().UnixNano(),
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
			go func() {
				select {
				case c := <-connChan:
					c.Close()
				case <-errChan:
				case <-time.After(5 * time.Second):
				}
			}()
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
	s.mu.RLock()
	writer := s.writer
	s.mu.RUnlock()

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

	target := net.JoinHostPort(s.TargetAddr, strconv.Itoa(int(s.TargetPort)))

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
		defer func() {
			if r := recover(); r != nil {
				connPoolLog.Error("PANIC in speculativeConnect: %v\n%s", r, debug.Stack())
			}
		}()
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

	atomic.StoreInt64(&s.lastTNano, time.Now().UnixNano())

	if s.Protocol == ProtoTCP && conn != nil {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		atomic.AddUint64(&s.bytesOut, uint64(n))
		return nil
	} else if s.Protocol == ProtoUDP && udpConn != nil {
		s.sackTracker.RecordPacket(s.seqNum)
		s.seqNum++

		n, err := udpConn.Write(data)
		if err != nil {
			return err
		}
		atomic.AddUint64(&s.bytesOut, uint64(n))
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

	atomic.StoreInt64(&s.lastTNano, time.Now().UnixNano())

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
		atomic.AddUint64(&s.bytesOut, uint64(n))
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
			connPoolLog.Error("PANIC in readFromTarget: %v\n%s", r, debug.Stack())
		}
		s.Close()
	}()

	bufp := streamReadBufPool.Get().(*[]byte)
	buf := *bufp
	defer streamReadBufPool.Put(bufp)

	s.mu.RLock()
	conn := s.conn
	writer := s.writer
	s.mu.RUnlock()
	if conn == nil || writer == nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	for {
		n, err := conn.Read(buf[HeaderSize:])
		if err != nil {
			if err != io.EOF {
				s.fsm.Event(EventError)
			} else {
				s.fsm.Event(EventPeerClose)
			}
			return
		}

		if n > 0 {
			atomic.AddUint64(&s.bytesIn, uint64(n))
			now := time.Now()
			atomic.StoreInt64(&s.lastTNano, now.UnixNano())
			conn.SetReadDeadline(now.Add(60 * time.Second))

			if s.sackEnabled {
				s.sackTracker.RecordPacket(s.seqNum)
				s.seqNum++
			}

			if s.fecEnabled || s.packetLossRate > 2.0 {
				encodedBuf := s.fecEncoder.EncodeFEC(buf[HeaderSize:HeaderSize+n], s.seqNum, HeaderSize)
				s.seqNum++

				WriteFrameHeader(encodedBuf, s.ID, FrameData, 0, len(encodedBuf)-HeaderSize)

				if err := writer.Write(encodedBuf); err != nil {
					packetPool.Put(encodedBuf)
					return
				}
				packetPool.Put(encodedBuf)

				parityPackets := s.fecEncoder.GetParityPackets(s.seqNum, HeaderSize)
				for _, pkt := range parityPackets {
					WriteFrameHeader(pkt, s.ID, FrameData, 0, len(pkt)-HeaderSize)
					writer.Write(pkt)
					packetPool.Put(pkt)
					s.seqNum++
				}
			} else {
				WriteFrameHeader(buf, s.ID, FrameData, 0, n)
				if err := writer.Write(buf[:HeaderSize+n]); err != nil {
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
				writer.Write(padBuf)
				packetPool.Put(padBuf)
			}
		}
	}
}

func (s *Stream) readUDPFromTarget() {
	defer func() {
		if r := recover(); r != nil {
			connPoolLog.Error("PANIC in readUDPFromTarget: %v\n%s", r, debug.Stack())
		}
		s.Close()
	}()

	const Headroom = 300

	s.mu.RLock()
	udpConn := s.udpConn
	writer := s.writer
	s.mu.RUnlock()
	if udpConn == nil || writer == nil {
		return
	}

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

		udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := udpConn.Read(buf[Headroom:])
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
			atomic.AddUint64(&s.bytesIn, uint64(n))
			atomic.StoreInt64(&s.lastTNano, time.Now().UnixNano())

			rAddr := udpConn.RemoteAddr()
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

			if err := writer.Write(packet); err != nil {
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
			connPoolLog.Error("PANIC in readRelayUDP: %v\n%s", r, debug.Stack())
		}
		s.Close()
	}()

	const Headroom = 300

	s.mu.RLock()
	udpConn := s.udpConn
	writer := s.writer
	s.mu.RUnlock()
	if udpConn == nil || writer == nil {
		return
	}

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

		udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, addr, err := udpConn.ReadFromUDP(buf[Headroom:])
		if err != nil {
			packetPool.Put(buf)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if isClosedConnError(err) {
				return
			}
			continue
		}

		if n > 0 {
			atomic.AddUint64(&s.bytesIn, uint64(n))
			atomic.StoreInt64(&s.lastTNano, time.Now().UnixNano())

			atyp := uint8(0x01)
			if addr.IP.To4() == nil {
				atyp = 0x04
			}

			packet, err := SealUDPData(buf[:Headroom+n], s.ID, atyp, addr.IP.String(), uint16(addr.Port), Headroom)
			if err != nil {
				log.Printf("[RELAY] UDP seal error: %v", err)
				packetPool.Put(buf)
				return
			}

			if err := writer.Write(packet); err != nil {
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

	s.mu.Lock()
	defer s.mu.Unlock()
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
		connPool: NewConnectionPool(30*time.Second, 64),
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
		totalBytesIn += atomic.LoadUint64(&stream.bytesIn)
		totalBytesOut += atomic.LoadUint64(&stream.bytesOut)
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
			sm.cleanupSafe()
		}
	}
}

func (sm *StreamManager) cleanupSafe() {
	defer func() {
		if r := recover(); r != nil {
			connPoolLog.Error("PANIC in stream manager cleanup: %v\n%s", r, debug.Stack())
		}
	}()
	sm.cleanup()
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

		if now.Sub(time.Unix(0, atomic.LoadInt64(&stream.lastTNano))) > staleTimeout {
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

	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()
	if conn == nil {
		return
	}

	_, err := conn.Write(s.earlyDataBuf)
	if err != nil {
		log.Printf("[0-RTT] early data flush error: %v", err)
	}

	atomic.AddUint64(&s.bytesOut, uint64(len(s.earlyDataBuf)))
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
