// Package relay provides stream management for multiplexed connections
package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Stream represents a single multiplexed stream (one TCP/UDP connection)
type Stream struct {
	ID         uint16
	fsm        *FSM  // Replaces ad-hoc State field
	Protocol   uint8 // ProtoTCP or ProtoUDP
	Profile    uint8 // Behavior profile (ProfileBalanced, etc.)
	TargetAddr string
	TargetPort uint16

	// Response writer for sending frames back to client
	writer ResponseWriter

	// TCP connection to target (server-side)
	conn net.Conn

	// UDP connection (for UDP relay)
	udpConn *net.UDPConn

	// Flow Control
	sendWindow int64
	windowCond *sync.Cond

	// Channels
	incoming  chan []byte // Data from tunnel to target
	outgoing  chan []byte // Data from target to tunnel
	closeChan chan struct{}

	// Stats
	bytesIn  uint64 // From client via tunnel
	bytesOut uint64 // To client via tunnel
	created  time.Time
	lastT    time.Time

	// Graceful Degradation
	RetryCount int

	dialer proxy.Dialer

	closeOnce sync.Once
	mu        sync.RWMutex
}

// NewStream creates a new stream
func NewStream(id uint16, proto uint8, addr string, port uint16, profile uint8, writer ResponseWriter, dialer proxy.Dialer) *Stream {
	s := &Stream{
		ID:         id,
		Protocol:   proto,
		Profile:    profile,
		TargetAddr: addr,
		TargetPort: port,
		writer:     writer,
		sendWindow: 2 * 1024 * 1024, // 2MB initial window
		incoming:   make(chan []byte, 16384),
		outgoing:   make(chan []byte, 16384),
		closeChan:  make(chan struct{}),
		created:    time.Now(),
		lastT:      time.Now(),
		dialer:     dialer,
	}
	s.windowCond = sync.NewCond(&s.mu)
	s.fsm = NewFSM(s)
	return s
}

// SetWriter sets the response writer for the stream
func (s *Stream) SetWriter(w ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writer = w
}

// sendFrame encodes and sends a frame to the writer
func (s *Stream) sendFrame(f *Frame) error {
	// NOTE: writer is set once during construction and rarely changes.
	// We avoid locking here to prevent deadlock with Connect() which holds s.mu.Lock()
	// while calling FSM events that trigger sendFrame().
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

// Connect establishes connection to the target
func (s *Stream) Connect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Initial transition
	if err := s.fsm.Event(EventStartConnect); err != nil {
		return err
	}

	// Profile-based adjustment (timeout logic...)
	connectTimeout := 10 * time.Second
	// ... (simplified for brevity, keep basics)

	target := net.JoinHostPort(s.TargetAddr, fmt.Sprintf("%d", s.TargetPort))

	// Action logic
	var err error
	switch s.Protocol {
	case ProtoTCP:
		if s.dialer != nil {
			var conn net.Conn
			// Force "tcp4" to avoid IPv6 issues on servers with restricted network
			conn, err = s.dialer.Dial("tcp4", target)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			s.conn = conn
		} else {
			dialer := &net.Dialer{
				Timeout:   connectTimeout,
				KeepAlive: 30 * time.Second, // Enable TCP Keep-Alive
			}
			var conn net.Conn
			// Force IPv4 to avoid potential IPv6 latency/routing issues
			conn, err = dialer.DialContext(ctx, "tcp4", target)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			s.conn = conn
		}

		// Optimize TCP socket buffers for high throughput
		if tcpConn, ok := s.conn.(*net.TCPConn); ok {
			tcpConn.SetReadBuffer(512 * 1024)  // 512KB read buffer (reduced from 16MB to prevent bufferbloat)
			tcpConn.SetWriteBuffer(512 * 1024) // 512KB write buffer
			tcpConn.SetNoDelay(true)           // Disable Nagle's algorithm
			tcpConn.SetKeepAlive(true)         // Enable TCP Keep-Alive
			tcpConn.SetKeepAlivePeriod(30 * time.Second)

		}

		// Event: ConnectOK
		if err := s.fsm.Event(EventConnectOK); err != nil {
			s.conn.Close()
			return err
		}

		// Start relay goroutines
		go s.readFromTarget()

	case ProtoUDP:
		// Check for Relay Mode (0.0.0.0 or ::)
		if s.TargetAddr == "0.0.0.0" || s.TargetAddr == "::" {
			// Unconnected UDP socket for Relay
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			conn.SetReadBuffer(4 * 1024 * 1024)
			conn.SetWriteBuffer(4 * 1024 * 1024)
			s.udpConn = conn

			if err := s.fsm.Event(EventConnectOK); err != nil {
				s.udpConn.Close()
				return err
			}

			go s.readRelayUDP()
		} else {
			// Connected UDP socket (P2P) - Force IPv4 to avoid IPv6 issues
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
			conn.SetReadBuffer(4 * 1024 * 1024)
			conn.SetWriteBuffer(4 * 1024 * 1024)
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

// Write sends data to the target
func (s *Stream) Write(data []byte) error {
	s.mu.RLock()
	state := s.fsm.CurrentState()
	conn := s.conn
	udpConn := s.udpConn
	s.mu.RUnlock()

	if state != StateConnected {
		return ErrStreamClosed
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
		n, err := udpConn.Write(data)
		if err != nil {
			return err
		}
		s.bytesOut += uint64(n)
		return nil
	}

	return ErrStreamClosed
}

// UpdateWindow increases the flow control window and wakes up blocked writers
func (s *Stream) UpdateWindow(increment uint32) {
	s.mu.Lock()
	s.sendWindow += int64(increment)
	if s.sendWindow > 50*1024*1024 { // Cap at 50MB to prevent overflow
		s.sendWindow = 50 * 1024 * 1024
	}
	s.windowCond.Broadcast() // Wake up writer
	s.mu.Unlock()
}

// HandleUDPData handles incoming UDP_DATA frame (with destination)
func (s *Stream) HandleUDPData(data []byte) error {
	s.mu.RLock()
	udpConn := s.udpConn
	s.mu.RUnlock()

	if udpConn == nil {
		return ErrStreamClosed
	}

	s.lastT = time.Now()

	// Parse payload: [AddrType][Addr][Port][Data]
	// Note: Client uses optimized format without RSV/FRAG headers
	if len(data) < 4 {
		return fmt.Errorf("short UDP data")
	}

	offset := 0
	atyp := data[offset]
	offset++

	var addr *net.UDPAddr
	var ip net.IP

	switch atyp {
	case 0x01: // IPv4
		if len(data) < offset+4 {
			return fmt.Errorf("short IPv4")
		}
		ip = net.IP(data[offset : offset+4])
		offset += 4
	case 0x04: // IPv6
		if len(data) < offset+16 {
			return fmt.Errorf("short IPv6")
		}
		ip = net.IP(data[offset : offset+16])
		offset += 16
	case 0x03: // Domain
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
		// Resolve domain
		if resolved, err := net.ResolveIPAddr("ip", domain); err == nil {
			ip = resolved.IP
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

	// Check if connected
	if udpConn.RemoteAddr() != nil {
		// Connected socket - use Write (ignore explicit addr as it must match connected)
		n, err := udpConn.Write(payload)
		if err != nil {
			return err
		}
		s.bytesOut += uint64(n)
		return nil
	}

	// Unconnected socket - use WriteToUDP
	n, err := udpConn.WriteToUDP(payload, addr)
	if err != nil {
		return err
	}
	s.bytesOut += uint64(n)
	return nil
}

// readFromTarget reads data from TCP target and sends back through tunnel
func (s *Stream) readFromTarget() {
	defer func() {
		if r := recover(); r != nil {
			// Log panic
		}
		s.Close()
	}()

	for {
		// ALLOC PER PACKET: Essential for Safe Zero-Copy with Async Writers (QoS).
		// We cannot reuse a buffer because the writer might queue the slice
		// and return immediately. Reusing would overwrite the queued data.
		// GC handles the cleanup.
		buf := make([]byte, HeaderSize+32*1024)

		// Check if closed (non-blocking)
		select {
		case <-s.closeChan:
			return
		default:
		}

		// Read with deadline
		s.conn.SetReadDeadline(time.Now().Add(180 * time.Second))

		// Read into payload area
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
			s.lastT = time.Now()

			// Flow Control (TCP only)
			if s.Protocol == ProtoTCP {
				s.mu.Lock()
				for s.sendWindow <= 0 {
					select {
					case <-s.closeChan:
						s.mu.Unlock()
						return
					default:
					}
					s.windowCond.Wait()
				}
				s.sendWindow -= int64(n)
				s.mu.Unlock()
			}

			// Zero-Copy Send:
			// Write Header in-place
			WriteFrameHeader(buf, s.ID, FrameData, 0, n)

			// Send the wrapped frame directly to writer
			// s.writer is thread-safe (tunnelWriter)
			if err := s.writer.Write(buf[:HeaderSize+n]); err != nil {
				return
			}
		}
	}
}

// readUDPFromTarget reads data from Connected UDP target
func (s *Stream) readUDPFromTarget() {
	defer func() {
		if r := recover(); r != nil {
			// Log panic
		}
		s.Close()
	}()

	for {
		const Headroom = 300
		select {
		case <-s.closeChan:
			return
		default:
		}

		// ALLOC PER PACKET: Safe Zero-Copy for Async Writers
		buf := make([]byte, Headroom+65535)

		// Optimize: Use longer deadline and check for specific errors
		s.udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute)) // Keepalive is 30s-60s, so 5m is safe
		// Read into payload offset
		n, err := s.udpConn.Read(buf[Headroom:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout is fine for UDP, just check closeChan and loop
				continue
			}
			// Check for closed connection
			if isClosedConnError(err) {
				return
			}
			// Other errors might be temporary, but typically fatal for a connected UDP socket
			s.fsm.Event(EventError)
			return
		}

		if n > 0 {
			// SAFETY CAP (Server Side): Trim large UDP packets (Jumbo/Probe) to 1200 bytes
			// to prevent fragmentation/drops on the client tunnel link.
			if n > 1200 {
				n = 1200
			}

			s.bytesIn += uint64(n)
			s.lastT = time.Now()

			// Resolve Remote Addr for Header
			rAddr := s.udpConn.RemoteAddr()
			udpAddr, ok := rAddr.(*net.UDPAddr)
			if !ok {
				// Should not happen for UDP conn
				continue
			}

			// Determine ATYP
			atyp := uint8(0x01) // IPv4
			if udpAddr.IP.To4() == nil {
				atyp = 0x04 // IPv6
			}

			// SealUDPData writes headers BEFORE buf[Headroom]
			// It returns the full frame slice starting from the header
			// Use FrameUDPData so client gets SOCKS5 header info
			// BUGFIX: Slice buf to Headroom+n so we don't send the full capacity (garbage/zeros)
			packet, err := SealUDPData(buf[:Headroom+n], s.ID, atyp, udpAddr.IP.String(), uint16(udpAddr.Port), Headroom)
			if err != nil {
				return
			}

			// Send without Retry (Fire and Forget for UDP)
			// Blocking here would cause huge latency and kill Discord voice.
			_ = s.writer.Write(packet)
		}
	}
}

// readRelayUDP reads from Unconnected UDP socket and sends UDP_DATA frames
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

		// ALLOC PER PACKET: Safe Zero-Copy for Async Writers
		buf := make([]byte, Headroom+65535)

		s.udpConn.SetReadDeadline(time.Now().Add(300 * time.Second))
		n, addr, err := s.udpConn.ReadFromUDP(buf[Headroom:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.fsm.Event(EventError)
			return
		}

		if n > 0 {
			// SAFETY CAP (Server Side - Relay Mode): Trim large UDP packets (Jumbo/Probe)
			if n > 1200 {
				n = 1200
			}

			s.bytesIn += uint64(n)
			s.lastT = time.Now()

			// Determine ATYP
			atyp := uint8(0x01) // IPv4
			if addr.IP.To4() == nil {
				atyp = 0x04 // IPv6
			}

			// SealUDPData writes headers BEFORE buf[Headroom]
			// It returns the full frame slice starting from the header
			packet, err := SealUDPData(buf, s.ID, atyp, addr.IP.String(), uint16(addr.Port), Headroom)
			if err != nil {
				return
			}

			if err := s.writer.Write(packet); err != nil {
				// UDP Strategy: Drop if congested.
				// Do NOT block or retry for long periods. Real-time traffic (Voice/Games)
				// prefers packet loss over high latency (Bufferbloat).

				// Optional: Short retry (e.g. 1ms) just in case of lock contention,
				// but avoiding channel/network checking loop.

				// For now: Just drop. The tunnel (TCP) is likely backing off.
				// Pushing more data will just increase latency.
				return
			}
		}
	}
}

// Close closes the stream (initiated locally)
func (s *Stream) Close() {
	s.fsm.Event(EventLocalClose)
}

// cleanupResources actual cleanup logic (called by FSM action)
func (s *Stream) cleanupResources() {
	s.closeOnce.Do(func() {
		close(s.closeChan)
		s.windowCond.Broadcast() // Wake up any waiters on Flow Control
	})

	// Close connections
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	if s.udpConn != nil {
		s.udpConn.Close()
		s.udpConn = nil
	}
}

// IsActive returns true if the stream is still usable
func (s *Stream) IsActive() bool {
	return !s.fsm.IsClosed()
}

// StreamManager manages all active streams
type StreamManager struct {
	streams map[uint16]*Stream
	mu      sync.RWMutex
	idGen   *StreamIDGenerator
	dialer  proxy.Dialer

	ctx    context.Context
	cancel context.CancelFunc
}

// NewStreamManager creates a new stream manager
func NewStreamManager(dialer proxy.Dialer) *StreamManager {
	ctx, cancel := context.WithCancel(context.Background())
	sm := &StreamManager{
		streams: make(map[uint16]*Stream),
		idGen:   NewStreamIDGenerator(),
		dialer:  dialer,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start cleanup goroutine
	go sm.cleanupLoop()

	return sm
}

// RegisterStream creates and registers a new stream (Synchronous)
func (sm *StreamManager) RegisterStream(streamID uint16, payload *ConnectPayload, writer ResponseWriter) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check for existing
	if _, exists := sm.streams[streamID]; exists {
		return fmt.Errorf("stream id %d collision", streamID)
	}

	// Create stream with default profile (Backward compatibility)
	// Note: We don't dial here.
	stream := NewStream(streamID, payload.Protocol, payload.Addr, payload.Port, ProfileBalanced, writer, sm.dialer)
	sm.streams[streamID] = stream

	return nil
}

// CompleteConnect performs the dialect (Asynchronous)
func (sm *StreamManager) CompleteConnect(streamID uint16, payload *ConnectPayload) error {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if !ok {
		return ErrStreamNotFound
	}

	// Connect to target
	ctx, cancel := context.WithTimeout(sm.ctx, 10*time.Second)
	defer cancel()

	if err := stream.Connect(ctx); err != nil {
		sm.mu.Lock()
		delete(sm.streams, streamID)
		sm.mu.Unlock()
		return err
	}

	return nil
}

// HandleData handles incoming DATA frame
func (sm *StreamManager) HandleData(streamID uint16, data []byte) error {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if !ok {
		return ErrStreamNotFound
	}

	return stream.Write(data)
}

// HandleUDPData handles incoming UDP_DATA frame
func (sm *StreamManager) HandleUDPData(streamID uint16, data []byte) error {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if !ok {
		return ErrStreamNotFound
	}

	return stream.HandleUDPData(data)
}

// HandleWindowUpdate handles incoming WINDOW_UPDATE frame
func (sm *StreamManager) HandleWindowUpdate(streamID uint16, increment uint32) {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if ok {
		stream.UpdateWindow(increment)
	}
}

// HandleClose handles incoming CLOSE frame
func (sm *StreamManager) HandleClose(streamID uint16) {
	sm.mu.Lock()
	stream, ok := sm.streams[streamID]
	if ok {
		delete(sm.streams, streamID)
	}
	sm.mu.Unlock()

	if stream != nil {
		stream.Close()
	}
}

// GetStream returns a stream by ID
func (sm *StreamManager) GetStream(id uint16) (*Stream, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	stream, ok := sm.streams[id]
	return stream, ok
}

// RemoveStream removes a stream
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

// CloseAll closes all streams and stops the manager
func (sm *StreamManager) CloseAll() {
	sm.cancel()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, stream := range sm.streams {
		stream.Close()
		delete(sm.streams, id)
	}
}

// Stats returns stream statistics
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

// cleanupLoop periodically cleans up stale streams
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

// cleanup removes stale streams based on FSM state or timeout
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

// isClosedConnError checks if the error is due to a closed connection
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "io: read/write on closed pipe")
}
