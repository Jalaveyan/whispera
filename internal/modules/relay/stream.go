// Package relay provides stream management for multiplexed connections
package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Stream represents a single multiplexed stream (one TCP/UDP connection)
type Stream struct {
	ID         uint16
	fsm        *FSM  // Replaces ad-hoc State field
	Protocol   uint8 // ProtoTCP or ProtoUDP
	Profile    uint8 // Behavior profile (ProfileBalanced, etc.)
	TargetAddr string
	TargetPort uint16

	// Client address for sending responses back
	ClientAddr net.Addr

	// TCP connection to target (server-side)
	conn net.Conn

	// UDP connection (for UDP relay)
	udpConn *net.UDPConn

	// Callbacks for sending frames back through tunnel (with address)
	onFrameWithAddr func(*Frame, net.Addr) error

	// Channels
	incoming  chan []byte // Data from tunnel to target
	outgoing  chan []byte // Data from target to tunnel
	closeChan chan struct{}

	// Timing
	CreatedAt  time.Time
	LastActive time.Time

	// Stats
	BytesIn  uint64
	BytesOut uint64

	// Graceful Degradation
	RetryCount int

	mu sync.RWMutex
}

// NewStream creates a new stream
func NewStream(id uint16, proto uint8, addr string, port uint16, profile uint8, clientAddr net.Addr, onFrameWithAddr func(*Frame, net.Addr) error) *Stream {
	s := &Stream{
		ID:              id,
		Protocol:        proto,
		Profile:         profile,
		TargetAddr:      addr,
		TargetPort:      port,
		ClientAddr:      clientAddr,
		onFrameWithAddr: onFrameWithAddr,
		incoming:        make(chan []byte, 256),
		outgoing:        make(chan []byte, 256),
		closeChan:       make(chan struct{}),
		CreatedAt:       time.Now(),
		LastActive:      time.Now(),
	}
	s.fsm = NewFSM(s)
	return s
}

// Connect establishes connection to the target
func (s *Stream) Connect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Initial transition
	if err := s.fsm.Event(EventStartConnect); err != nil {
		return err
	}

	// Profile-based adjustment
	connectTimeout := 10 * time.Second
	if s.Profile == ProfileAggressive {
		// Aggressive: Random delay to mimic diverse traffic? Or faster timeout?
		// Let's assume Aggressive means "Harder to block", so maybe use longer timeout or specific handshake tricks
		connectTimeout = 20 * time.Second
		// Artificial delay to vary timing analysis (obfuscation)
		// time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)))
	} else if s.Profile == ProfileLowLatency {
		// LoLatency: Fail fast
		connectTimeout = 3 * time.Second
	} else if s.Profile == ProfilePersonal {
		// Personal: Mimic standard browser behavior (human-like)
		connectTimeout = 15 * time.Second
		// Introduce small jitter to mimic human/network variation
		// time.Sleep(time.Duration(50+rand.Intn(150)) * time.Millisecond) // Requires math/rand
	}

	target := fmt.Sprintf("%s:%d", s.TargetAddr, s.TargetPort)

	// Action logic (could be moved to FSM action, but here for context control)
	var err error
	if s.Protocol == ProtoTCP {
		dialer := &net.Dialer{
			Timeout: connectTimeout,
		}
		var conn net.Conn
		conn, err = dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			s.fsm.Event(EventConnectFail)
			return err
		}
		s.conn = conn

		// Event: ConnectOK
		if err := s.fsm.Event(EventConnectOK); err != nil {
			s.conn.Close()
			return err
		}

		// Start relay goroutines
		go s.readFromTarget()
	} else if s.Protocol == ProtoUDP {
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

		// Event: ConnectOK
		if err := s.fsm.Event(EventConnectOK); err != nil {
			s.udpConn.Close()
			return err
		}

		go s.readUDPFromTarget()
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

	s.LastActive = time.Now()

	if s.Protocol == ProtoTCP && conn != nil {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		s.BytesOut += uint64(n)
		return nil
	} else if s.Protocol == ProtoUDP && udpConn != nil {
		n, err := udpConn.Write(data)
		if err != nil {
			return err
		}
		s.BytesOut += uint64(n)
		return nil
	}

	return ErrStreamClosed
}

// readFromTarget reads data from TCP target and sends back through tunnel
func (s *Stream) readFromTarget() {
	defer func() {
		if r := recover(); r != nil {
			// Log panic but don't crash
			// log.Printf("[Stream] Panic in readFromTarget: %v", r)
		}
		s.Close()
	}()

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
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
			s.BytesIn += uint64(n)
			s.LastActive = time.Now()

			// Send data frame back through tunnel
			frame := NewDataFrame(s.ID, buf[:n])
			if s.onFrameWithAddr != nil && s.ClientAddr != nil {
				if err := s.onFrameWithAddr(frame, s.ClientAddr); err != nil {
					return
				}
			}
		}
	}
}

// readUDPFromTarget reads data from UDP target and sends back through tunnel
func (s *Stream) readUDPFromTarget() {
	defer func() {
		if r := recover(); r != nil {
			// Log panic but don't crash
		}
		s.Close()
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-s.closeChan:
			// Cleanup event is handled by Close() which calls EventLocalClose
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := s.udpConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Don't transition on temporary timeout
				continue
			}
			s.fsm.Event(EventError)
			return
		}

		if n > 0 {
			s.BytesIn += uint64(n)
			s.LastActive = time.Now()

			// Send data frame back through tunnel
			frame := NewDataFrame(s.ID, buf[:n])
			if s.onFrameWithAddr != nil && s.ClientAddr != nil {
				if err := s.onFrameWithAddr(frame, s.ClientAddr); err != nil {
					return
				}
			}
		}
	}
}

// Close closes the stream (initiated locally)
func (s *Stream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Use FSM event
	s.fsm.Event(EventLocalClose)
}

// cleanupResources actual cleanup logic (called by FSM action)
func (s *Stream) cleanupResources() {
	// Signal close
	select {
	case <-s.closeChan:
	default:
		close(s.closeChan)
	}

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
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fsm.CurrentState() == StateConnected
}

// StreamManager manages all active streams
type StreamManager struct {
	streams         map[uint16]*Stream
	mu              sync.RWMutex
	idGen           *StreamIDGenerator
	onFrameWithAddr func(*Frame, net.Addr) error

	ctx    context.Context
	cancel context.CancelFunc
}

// NewStreamManager creates a new stream manager
func NewStreamManager(onFrameWithAddr func(*Frame, net.Addr) error) *StreamManager {
	ctx, cancel := context.WithCancel(context.Background())
	sm := &StreamManager{
		streams:         make(map[uint16]*Stream),
		idGen:           NewStreamIDGenerator(),
		onFrameWithAddr: onFrameWithAddr,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Start cleanup goroutine
	go sm.cleanupLoop()

	return sm
}

// CreateStream creates a new stream for outgoing connections (client-side)
func (sm *StreamManager) CreateStream(proto uint8, addr string, port uint16, profile uint8, clientAddr net.Addr) *Stream {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := sm.idGen.Next()
	stream := NewStream(id, proto, addr, port, profile, clientAddr, sm.onFrameWithAddr)
	sm.streams[id] = stream

	return stream
}

// HandleConnect handles incoming CONNECT frame (server-side)
func (sm *StreamManager) HandleConnect(streamID uint16, payload *ConnectPayload, clientAddr net.Addr) error {
	sm.mu.Lock()

	// Create stream with requested profile and client address
	stream := NewStream(streamID, payload.Protocol, payload.Addr, payload.Port, payload.Profile, clientAddr, sm.onFrameWithAddr)
	sm.streams[streamID] = stream
	sm.mu.Unlock()

	// Connect to target
	ctx, cancel := context.WithTimeout(sm.ctx, 10*time.Second)
	defer cancel()

	if err := stream.Connect(ctx); err != nil {
		sm.mu.Lock()
		delete(sm.streams, streamID)
		sm.mu.Unlock()

		// CONNECT_FAIL is sent by FSM transition or caller, but strict FSM handles state cleanup
		// Note: The FSM transition for ConnectFail already sent the frame in state.go
		return err
	}

	// CONNECT_OK is sent by FSM transition in stream.Connect()

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

// Close closes all streams and stops the manager
func (sm *StreamManager) Close() {
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
		totalBytesIn += stream.BytesIn
		totalBytesOut += stream.BytesOut
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
		// Use FSM state check
		state := stream.fsm.CurrentState()

		if state == StateClosed {
			delete(sm.streams, id)
			continue
		}

		// If stuck in connecting for too long
		if state == StateConnecting && now.Sub(stream.CreatedAt) > 30*time.Second {
			stream.fsm.Event(EventTimeout)
			delete(sm.streams, id)
			continue
		}

		if now.Sub(stream.LastActive) > staleTimeout {
			stream.fsm.Event(EventTimeout)
			delete(sm.streams, id)
		}
	}
}
