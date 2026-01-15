// Package relay provides the relay server module
package relay

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"

	"golang.org/x/net/proxy"
)

const (
	ModuleName    = "relay.server"
	ModuleVersion = "1.0.0"
)

// ResponseWriter abstracts the underlying transport (UDP/TCP)
type ResponseWriter interface {
	Write(data []byte) error
	RemoteAddr() net.Addr
}

// Config holds relay module configuration
type Config struct {
	MaxStreams    int    // Maximum concurrent streams
	EnableTCP     bool   // Enable TCP relay
	EnableUDP     bool   // Enable UDP relay
	Debug         bool   // Enable debug logging
	SafeMode      bool   // Force safe profiles
	UpstreamProxy string // Upstream SOCKS5 proxy (optional)
}

// DefaultConfig returns default relay configuration
func DefaultConfig() *Config {
	return &Config{
		MaxStreams: 10000,
		EnableTCP:  true,
		EnableUDP:  true,
		Debug:      false,
		SafeMode:   true,
	}
}

// Validate validates the configuration
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
	proxyDialer   proxy.Dialer

	// Transport callback for sending frames to client (Legacy/UDP)
	sendFrame func(data []byte, addr net.Addr) error

	// Session to writer mapping
	sessionWriters   map[uint32]ResponseWriter
	sessionWritersMu sync.RWMutex

	// Raw packet tracking (packetID -> ResponseWriter for response routing)
	// We need generic ResponseWriter here, not just net.Addr
	rawPackets   map[uint32]ResponseWriter
	rawPacketsMu sync.RWMutex

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
		Module:         base.NewModule(ModuleName, ModuleVersion, []string{"transport.udp"}),
		config:         cfg,
		sessionWriters: make(map[uint32]ResponseWriter),
		rawPackets:     make(map[uint32]ResponseWriter),
		log:            logger.Module("relay"),
	}

	// Default proxy dialer (direct)
	s.proxyDialer = proxy.Direct
	if cfg.UpstreamProxy != "" {
		u, err := url.Parse(cfg.UpstreamProxy)
		if err != nil {
			s.log.Error("Invalid upstream proxy URL: %v", err)
			return nil, fmt.Errorf("invalid upstream proxy URL: %v", err)
		}
		dialer, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			s.log.Error("Failed to create proxy dialer: %v", err)
			return nil, fmt.Errorf("failed to create proxy dialer: %v", err)
		}
		s.proxyDialer = dialer
		s.log.Info("Using upstream proxy: %s", u.Redacted())
	}

	// Initialize stream manager
	s.streamManager = NewStreamManager(s.proxyDialer)

	return s, nil
}

// Init initializes the module
func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}
	return nil
}

// Start starts the relay server
func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	s.log.Info("Server started (max streams: %d)", s.config.MaxStreams)
	return nil
}

// Stop stops the relay server
func (s *Server) Stop() error {
	s.streamManager.CloseAll()
	return s.Module.Stop()
}

// SetTransport sets the transport callback for sending frames (Legacy)
func (s *Server) SetTransport(sendFrame func(data []byte, addr net.Addr) error) {
	s.sendFrame = sendFrame
}

// RegisterSessionWriter registers a session ID with a response writer
func (s *Server) RegisterSessionWriter(sessionID uint32, writer ResponseWriter) {
	s.sessionWritersMu.Lock()
	defer s.sessionWritersMu.Unlock()
	s.sessionWriters[sessionID] = writer
}

// GetSessionWriter returns the response writer for a session
func (s *Server) GetSessionWriter(sessionID uint32) ResponseWriter {
	s.sessionWritersMu.RLock()
	defer s.sessionWritersMu.RUnlock()
	return s.sessionWriters[sessionID]
}

// ProcessFrame processes an incoming frame from client
func (s *Server) ProcessFrame(data []byte, session interfaces.Session, writer ResponseWriter) error {
	atomic.AddUint64(&s.framesIn, 1)

	// Register session writer for responses
	if session != nil {
		s.RegisterSessionWriter(session.ID(), writer)
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
		return s.handleConnect(frame, writer)
	case FrameData:
		return s.handleData(frame)
	case FrameClose:
		s.handleClose(frame)
		return nil
	case FramePing:
		return s.handlePing(writer)
	case FrameUDPData:
		return s.handleUDPData(frame, writer)
	case FrameRawPacket:
		return s.handleRawPacket(frame, writer)
	default:
		if s.config.Debug {
			s.log.Debug("Unknown frame type: %d", frame.Type)
		}
		return nil
	}
}

// handleConnect handles CONNECT frame
func (s *Server) handleConnect(frame *Frame, writer ResponseWriter) error {
	payload, err := DecodeConnectPayload(frame.Payload)
	if err != nil {
		atomic.AddUint64(&s.connectFailed, 1)
		s.sendFrameToWriter(NewConnectFailFrame(frame.StreamID, "connection refused"), writer)
		return err
	}

	if s.config.Debug {
		s.log.Debug("CONNECT request: streamID=%d target=%s:%d proto=%d",
			frame.StreamID, payload.Addr, payload.Port, payload.Protocol)
	}

	// Permission checks
	if payload.Protocol == ProtoUDP && !s.config.EnableUDP {
		s.sendFrameToWriter(NewConnectFailFrame(frame.StreamID, "UDP relay disabled"), writer)
		return nil
	}
	if payload.Protocol == ProtoTCP && !s.config.EnableTCP {
		s.sendFrameToWriter(NewConnectFailFrame(frame.StreamID, "TCP relay disabled"), writer)
		return nil
	}

	// Delegate connection handling to StreamManager
	if err := s.streamManager.HandleConnect(frame.StreamID, payload, writer); err != nil {
		atomic.AddUint64(&s.connectFailed, 1)
		if s.config.Debug {
			s.log.Debug("Failed to connect stream %d: %v", frame.StreamID, err)
		}
		return err
	}

	atomic.AddUint64(&s.connectSuccess, 1)
	return nil
}

// handleData handles DATA frame
func (s *Server) handleData(frame *Frame) error {
	return s.streamManager.HandleData(frame.StreamID, frame.Payload)
}

// handleClose handles CLOSE frame
func (s *Server) handleClose(frame *Frame) {
	s.streamManager.HandleClose(frame.StreamID)
}

// handlePing handles PING frame
func (s *Server) handlePing(writer ResponseWriter) error {
	return s.sendFrameToWriter(NewPongFrame(), writer) // Send PONG, not PING
}

// handleUDPData handles UDP data frame
func (s *Server) handleUDPData(frame *Frame, _ ResponseWriter) error {
	// For UDP streams managed by StreamManager
	return s.streamManager.HandleData(frame.StreamID, frame.Payload)
}

// handleRawPacket handles RAW_PACKET frames
func (s *Server) handleRawPacket(frame *Frame, writer ResponseWriter) error {
	packetID, rawPacket, err := ParseRawPacketFrame(frame)
	if err != nil {
		return err
	}

	s.rawPacketsMu.Lock()
	s.rawPackets[packetID] = writer
	s.rawPacketsMu.Unlock()

	// Process raw packet... (placeholder)
	// For now just echo for testing if needed or drop
	if s.config.Debug {
		s.log.Debug("Received RAW packet ID=%d len=%d", packetID, len(rawPacket))
	}
	return nil
}

// sendFrameToWriter sends a frame using the specific writer
func (s *Server) sendFrameToWriter(frame *Frame, writer ResponseWriter) error {
	encoded, err := frame.Encode()
	if err != nil {
		return err
	}
	atomic.AddUint64(&s.framesOut, 1)
	atomic.AddUint64(&s.bytesRelayed, uint64(len(encoded)))
	return writer.Write(encoded)
}

// Unused methods maintained for interface compatibility if needed, or helper
func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()
	status.Details["active_streams"] = atomic.LoadUint64(&s.activeStreams)
	if s.streamManager != nil {
		active, bin, bout := s.streamManager.Stats()
		status.Details["streams"] = active
		status.Details["bytes_in"] = bin
		status.Details["bytes_out"] = bout
	}
	return status
}
