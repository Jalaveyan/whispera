// Package relay provides stream management for multiplexed connections
package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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
		incoming:   make(chan []byte, 512),
		outgoing:   make(chan []byte, 512),
		closeChan:  make(chan struct{}),
		created:    time.Now(),
		lastT:      time.Now(),
		dialer:     dialer,
	}
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

	target := fmt.Sprintf("%s:%d", s.TargetAddr, s.TargetPort)

	// Action logic
	var err error
	switch s.Protocol {
	case ProtoTCP:
		if s.dialer != nil {
			var conn net.Conn
			conn, err = s.dialer.Dial("tcp", target)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			s.conn = conn
		} else {
			dialer := &net.Dialer{Timeout: connectTimeout}
			var conn net.Conn
			conn, err = dialer.DialContext(ctx, "tcp", target)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			s.conn = conn
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
			s.udpConn = conn

			if err := s.fsm.Event(EventConnectOK); err != nil {
				s.udpConn.Close()
				return err
			}

			go s.readRelayUDP()
		} else {
			// Connected UDP socket (P2P)
			var addr *net.UDPAddr
			addr, err = net.ResolveUDPAddr("udp", target)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
			var conn *net.UDPConn
			conn, err = net.DialUDP("udp", nil, addr)
			if err != nil {
				s.fsm.Event(EventConnectFail)
				return err
			}
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
	if len(data) < 7 {
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

	// WriteToUDP
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

	buf := make([]byte, 64*1024) // 64KB buffer
	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(300 * time.Second)) // Increased timeout
		n, err := s.conn.Read(buf)
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

			// Send data frame back through tunnel
			frame := NewDataFrame(s.ID, buf[:n])
			if err := s.sendFrame(frame); err != nil {
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

	buf := make([]byte, 65535)
	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(300 * time.Second))
		n, err := s.udpConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.fsm.Event(EventError)
			return
		}

		if n > 0 {
			s.bytesIn += uint64(n)
			s.lastT = time.Now()

			// Connected UDP uses standard DFRAME
			frame := NewDataFrame(s.ID, buf[:n])
			if err := s.sendFrame(frame); err != nil {
				return
			}
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

	buf := make([]byte, 65535)
	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(300 * time.Second))
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.fsm.Event(EventError)
			return
		}

		if n > 0 {
			s.bytesIn += uint64(n)
			s.lastT = time.Now()

			// Determine ATYP
			atyp := uint8(0x01) // IPv4
			if addr.IP.To4() == nil {
				atyp = 0x04 // IPv6
			}

			frame := NewUDPDataFrame(s.ID, atyp, addr.IP.String(), uint16(addr.Port), buf[:n])
			if err := s.sendFrame(frame); err != nil {
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

// HandleConnect handles incoming CONNECT frame (server-side)
func (sm *StreamManager) HandleConnect(streamID uint16, payload *ConnectPayload, writer ResponseWriter) error {
	sm.mu.Lock()

	// Create stream with default profile (Backward compatibility)
	stream := NewStream(streamID, payload.Protocol, payload.Addr, payload.Port, ProfileBalanced, writer, sm.dialer)
	sm.streams[streamID] = stream
	sm.mu.Unlock()

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
