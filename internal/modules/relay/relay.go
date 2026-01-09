// Package relay provides the server-side relay module for internet access
package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"
)

const (
	ModuleName    = "relay.server"
	ModuleVersion = "1.0.0"
)

// Config holds relay module configuration
type Config struct {
	MaxStreams int  // Maximum concurrent streams
	EnableTCP  bool // Enable TCP relay
	EnableUDP  bool // Enable UDP relay
	Debug      bool // Enable debug logging
	SafeMode   bool // Force safe profiles (disable Aggressive)
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxStreams: 10000,
		EnableTCP:  true,
		EnableUDP:  true,
		Debug:      false,
		SafeMode:   true, // Default to Safe Mode
	}
}

// Validate validates configuration
func (c *Config) Validate() error {
	if c.MaxStreams <= 0 {
		c.MaxStreams = 10000
	}
	return nil
}

// Server implements the relay server module
type Server struct {
	*base.Module
	config *Config

	// Stream management
	streamManager *StreamManager

	// Transport callback for sending frames to client
	sendFrame func(data []byte, addr net.Addr) error

	// Session to address mapping
	sessionAddrs   map[uint32]net.Addr
	sessionAddrsMu sync.RWMutex

	// Stats
	framesIn       uint64
	framesOut      uint64
	bytesRelayed   uint64
	activeStreams  uint64
	connectSuccess uint64
	connectFailed  uint64

	log *logger.Logger
	mu  sync.RWMutex
}

// New creates a new relay server
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	s := &Server{
		Module:       base.NewModule(ModuleName, ModuleVersion, []string{"transport.udp"}),
		config:       cfg,
		sessionAddrs: make(map[uint32]net.Addr),
		log:          logger.Module("relay"),
	}

	return s, nil
}

// Init initializes the relay server
func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if relayCfg, ok := cfg.(*Config); ok {
		s.config = relayCfg
	}

	return nil
}

// Start starts the relay server
func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	// Create stream manager with callback to send frames (with address)
	s.streamManager = NewStreamManager(s.sendFrameToAddrDirect)

	// Start health monitoring loop
	go s.healthLoop()

	s.SetHealthy(true, "relay server running")
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"max_streams": s.config.MaxStreams,
		"tcp_enabled": s.config.EnableTCP,
		"udp_enabled": s.config.EnableUDP,
	})

	s.log.Info("Server started (max streams: %d)", s.config.MaxStreams)
	return nil
}

// Stop stops the relay server
func (s *Server) Stop() error {
	if s.streamManager != nil {
		s.streamManager.Close()
	}

	s.PublishEvent(events.EventTypeModuleStopped, nil)
	s.log.Info("Server stopped")
	return s.Module.Stop()
}

// SetTransport sets the transport callback for sending data back to client
func (s *Server) SetTransport(sendFunc func(data []byte, addr net.Addr) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendFrame = sendFunc
}

// RegisterSession registers a session address for response routing
func (s *Server) RegisterSession(sessionID uint32, addr net.Addr) {
	s.sessionAddrsMu.Lock()
	defer s.sessionAddrsMu.Unlock()
	s.sessionAddrs[sessionID] = addr
}

// UnregisterSession removes a session
func (s *Server) UnregisterSession(sessionID uint32) {
	s.sessionAddrsMu.Lock()
	defer s.sessionAddrsMu.Unlock()
	delete(s.sessionAddrs, sessionID)
}

// ProcessFrame processes an incoming frame from client
func (s *Server) ProcessFrame(data []byte, session interfaces.Session, addr net.Addr) error {
	atomic.AddUint64(&s.framesIn, 1)

	// Register session address for responses
	if session != nil {
		s.RegisterSession(session.ID(), addr)
	}

	// Decode frame
	frame, err := Decode(data)
	if err != nil {
		if s.config.Debug {
			s.log.Debug("Failed to decode frame: %v", err)
		}
		return err
	}

	if s.config.Debug {
		s.log.Debug("Received frame: type=%s streamID=%d len=%d",
			FrameTypeName(frame.Type), frame.StreamID, len(frame.Payload))
	}

	// Handle frame by type
	switch frame.Type {
	case FrameConnect:
		return s.handleConnect(frame, addr)
	case FrameData:
		return s.handleData(frame)
	case FrameClose:
		s.handleClose(frame)
		return nil
	case FramePing:
		return s.handlePing(addr)
	case FrameUDPData:
		return s.handleUDPData(frame)
	default:
		if s.config.Debug {
			s.log.Debug("Unknown frame type: %d", frame.Type)
		}
		return nil
	}
}

// handleConnect handles CONNECT frame - establishes connection to target
func (s *Server) handleConnect(frame *Frame, addr net.Addr) error {
	payload, err := DecodeConnectPayload(frame.Payload)
	if err != nil {
		atomic.AddUint64(&s.connectFailed, 1)
		s.sendFrameToAddr(NewConnectFailFrame(frame.StreamID, "connection refused"), addr)
		return err
	}

	// Safe Mode Enforcement
	if s.config.SafeMode && payload.Profile == ProfileAggressive {
		if s.config.Debug {
			s.log.Debug("SafeMode: Downgrading stream %d from Aggressive to Personal", frame.StreamID)
		}
		payload.Profile = ProfilePersonal
	}

	// Check protocol support
	if payload.Protocol == ProtoTCP && !s.config.EnableTCP {
		atomic.AddUint64(&s.connectFailed, 1)
		s.sendFrameToAddr(NewConnectFailFrame(frame.StreamID, "connection refused"), addr)
		return fmt.Errorf("TCP relay not enabled")
	}
	if payload.Protocol == ProtoUDP && !s.config.EnableUDP {
		atomic.AddUint64(&s.connectFailed, 1)
		s.sendFrameToAddr(NewConnectFailFrame(frame.StreamID, "connection refused"), addr)
		return fmt.Errorf("UDP relay not enabled")
	}

	if s.config.Debug {
		protoName := "TCP"
		if payload.Protocol == ProtoUDP {
			protoName = "UDP"
		}
		s.log.Debug("CONNECT streamID=%d %s -> %s:%d",
			frame.StreamID, protoName, payload.Addr, payload.Port)
	}

	// Handle connect in stream manager (async)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Silently recover from panic
			}
		}()

		if err := s.streamManager.HandleConnect(frame.StreamID, payload, addr); err != nil {
			atomic.AddUint64(&s.connectFailed, 1)
			if s.config.Debug {
				s.log.Debug("Connect failed streamID=%d: %v", frame.StreamID, err)
			}
		} else {
			atomic.AddUint64(&s.connectSuccess, 1)
			atomic.AddUint64(&s.activeStreams, 1)
			if s.config.Debug {
				s.log.Debug("Connect success streamID=%d", frame.StreamID)
			}
		}
	}()

	return nil
}

// handleData handles DATA frame - forwards data to target
func (s *Server) handleData(frame *Frame) error {
	if err := s.streamManager.HandleData(frame.StreamID, frame.Payload); err != nil {
		if s.config.Debug {
			s.log.Debug("Data forward failed streamID=%d: %v", frame.StreamID, err)
		}
		return err
	}

	atomic.AddUint64(&s.bytesRelayed, uint64(len(frame.Payload)))
	return nil
}

// handleClose handles CLOSE frame
func (s *Server) handleClose(frame *Frame) {
	s.streamManager.HandleClose(frame.StreamID)
	atomic.AddUint64(&s.activeStreams, ^uint64(0)) // Decrement

	if s.config.Debug {
		s.log.Debug("Stream closed streamID=%d", frame.StreamID)
	}
}

// handlePing handles PING frame
func (s *Server) handlePing(addr net.Addr) error {
	return s.sendFrameToAddr(NewPongFrame(), addr)
}

// handleUDPData handles UDP_DATA frame for stateless UDP relay
func (s *Server) handleUDPData(frame *Frame) error {
	// Parse UDP data payload: [AddrType:1][Addr:N][Port:2][Data:N]
	if len(frame.Payload) < 4 {
		return ErrInvalidFrame
	}

	addrType := frame.Payload[0]
	offset := 1
	var targetAddr string
	var targetPort uint16

	switch addrType {
	case AddrTypeIPv4:
		if len(frame.Payload) < offset+4+2+1 {
			return ErrInvalidFrame
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d",
			frame.Payload[offset], frame.Payload[offset+1],
			frame.Payload[offset+2], frame.Payload[offset+3])
		offset += 4
	case AddrTypeDomain:
		domainLen := int(frame.Payload[offset])
		offset++
		if len(frame.Payload) < offset+domainLen+2+1 {
			return ErrInvalidFrame
		}
		targetAddr = string(frame.Payload[offset : offset+domainLen])
		offset += domainLen
	default:
		return ErrInvalidFrame
	}

	targetPort = uint16(frame.Payload[offset])<<8 | uint16(frame.Payload[offset+1])
	offset += 2

	data := frame.Payload[offset:]

	// Send UDP packet
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if s.config.Debug {
		s.log.Debug("UDP sent to %s (%d bytes)", target, len(data))
	}

	atomic.AddUint64(&s.bytesRelayed, uint64(len(data)))
	return err
}

// handleOutgoingFrame is called when stream has data to send back to client
func (s *Server) handleOutgoingFrame(frame *Frame) error {
	s.mu.RLock()
	sendFunc := s.sendFrame
	s.mu.RUnlock()

	if sendFunc == nil {
		return fmt.Errorf("transport not set")
	}

	// Encode frame
	data, err := frame.Encode()
	if err != nil {
		return err
	}

	atomic.AddUint64(&s.framesOut, 1)
	atomic.AddUint64(&s.bytesRelayed, uint64(len(frame.Payload)))

	// Get any active session address (simplified - in production would track per-stream)
	s.sessionAddrsMu.RLock()
	var addr net.Addr
	for _, a := range s.sessionAddrs {
		addr = a
		break
	}
	s.sessionAddrsMu.RUnlock()

	if addr == nil {
		return fmt.Errorf("no session address available")
	}

	if s.config.Debug {
		s.log.Debug("Sending frame: type=%s streamID=%d len=%d",
			FrameTypeName(frame.Type), frame.StreamID, len(frame.Payload))
	}

	return sendFunc(data, addr)
}

// sendFrameToAddr sends a frame to a specific address
func (s *Server) sendFrameToAddr(frame *Frame, addr net.Addr) error {
	s.mu.RLock()
	sendFunc := s.sendFrame
	s.mu.RUnlock()

	if sendFunc == nil {
		return fmt.Errorf("transport not set")
	}

	data, err := frame.Encode()
	if err != nil {
		return err
	}

	atomic.AddUint64(&s.framesOut, 1)
	return sendFunc(data, addr)
}

// sendFrameToAddrDirect is a callback for StreamManager that sends frames directly to client address
func (s *Server) sendFrameToAddrDirect(frame *Frame, addr net.Addr) error {
	if s.config.Debug {
		s.log.Debug("Sending frame: type=%s streamID=%d len=%d",
			FrameTypeName(frame.Type), frame.StreamID, len(frame.Payload))
	}
	return s.sendFrameToAddr(frame, addr)
}

// HealthCheck returns health status
func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()

	status.Details["frames_in"] = atomic.LoadUint64(&s.framesIn)
	status.Details["frames_out"] = atomic.LoadUint64(&s.framesOut)
	status.Details["bytes_relayed"] = atomic.LoadUint64(&s.bytesRelayed)
	status.Details["active_streams"] = atomic.LoadUint64(&s.activeStreams)
	status.Details["connect_success"] = atomic.LoadUint64(&s.connectSuccess)
	status.Details["connect_failed"] = atomic.LoadUint64(&s.connectFailed)

	if s.streamManager != nil {
		active, bytesIn, bytesOut := s.streamManager.Stats()
		status.Details["stream_count"] = active
		status.Details["stream_bytes_in"] = bytesIn
		status.Details["stream_bytes_out"] = bytesOut
	}

	return status
}

// Factory creates relay server modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}

// healthLoop runs periodic health checks
func (s *Server) healthLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.Context().Done():
			return
		case <-ticker.C:
			// Collect stats
			activeStreams := atomic.LoadUint64(&s.activeStreams)
			bytesRelayed := atomic.LoadUint64(&s.bytesRelayed)

			// Check thresholds
			if activeStreams > uint64(s.config.MaxStreams) {
				s.log.Warn("Active streams (%d) exceeds max (%d)",
					activeStreams, s.config.MaxStreams)
			}

			if s.config.Debug {
				s.log.Debug("Health: Streams=%d, Bytes=%d", activeStreams, bytesRelayed)
			}

			// Run FSM self-checks on streams
			if s.streamManager != nil {
				// Could iterate streams and call fsm.SelfCheck()
			}
		}
	}
}
