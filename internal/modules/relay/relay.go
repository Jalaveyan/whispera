// Package relay provides the relay server module
package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

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
	return s.streamManager.HandleUDPData(frame.StreamID, frame.Payload)
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

// tunnelWriter implements ResponseWriter for ServeTunnel
type tunnelWriter struct {
	conn       net.Conn
	obfuscator interfaces.Obfuscator
	mu         *sync.Mutex
}

func (w *tunnelWriter) Write(data []byte) error {
	// Apply obfuscation OUTSIDE the lock to reduce contention
	if w.obfuscator != nil {
		obfuscated, _, err := w.obfuscator.Process(data, interfaces.DirectionOutbound)
		if err != nil {
			return err
		}
		data = obfuscated
	}

	w.mu.Lock()
	_, err := w.conn.Write(data)
	w.mu.Unlock()
	return err
}

func (w *tunnelWriter) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

// ServeTunnel handles a persistent tunnel connection (e.g. TCP or Phantom)
// It manages streams, applies obfuscation, and routes frames via the Relay Protocol.
func (s *Server) ServeTunnel(conn net.Conn, obfuscator interfaces.Obfuscator) {
	defer conn.Close()

	// Connection context
	clientID := conn.RemoteAddr().String()
	s.log.Info("Starting tunnel session for %s", clientID)

	// Write lock for the tunnel
	var writeMu sync.Mutex

	// Create ResponseWriter wrapper for this tunnel
	writer := &tunnelWriter{
		conn:       conn,
		obfuscator: obfuscator,
		mu:         &writeMu,
	}

	// Create LOCAL StreamManager for this tunnel to ensure isolation and features (UDP)
	sm := NewStreamManager(s.proxyDialer)
	defer sm.CloseAll()
	defer func() {
		s.log.Info("Tunnel closed for %s", clientID)
	}()

	// Helper to send frame
	sendFrame := func(f *Frame) error {
		encoded, err := f.Encode()
		if err != nil {
			return err
		}
		return writer.Write(encoded)
	}

	// Read buffer
	buf := make([]byte, 64*1024)
	var packetBuf []byte // Accumulator for partial frames

	// Send immediate PONG to break potential deadlock
	// Client's readLoop is waiting for data, and we're waiting for client data
	// By sending PONG first, we unblock the client's readLoop
	welcomeFrame := NewPongFrame()
	if err := sendFrame(welcomeFrame); err != nil {
		s.log.Warn("Failed to send welcome PONG: %v", err)
		// Continue anyway - client might send PING first
	} else {
		s.log.Debug("Sent welcome PONG to %s", clientID)
	}

	for {
		conn.SetReadDeadline(time.Now().Add(300 * time.Second)) // 5 min idle
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				s.log.Debug("Tunnel read error from %s: %v", clientID, err)
			}
			return
		}

		data := buf[:n]

		// DEBUG: Log first bytes of incoming data
		if n >= 8 {
			s.log.Debug("Tunnel data from %s: first 8 bytes = [%02x %02x %02x %02x %02x %02x %02x %02x]",
				clientID, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7])
		}

		// Check for TLS data (leftover from masquerade handshake)
		// TLS record types: 0x14 (ChangeCipherSpec), 0x15 (Alert), 0x16 (Handshake), 0x17 (ApplicationData)
		if n >= 5 && data[0] >= 0x14 && data[0] <= 0x17 && data[1] == 0x03 {
			tlsLen := int(data[3])<<8 | int(data[4])
			s.log.Warn("Detected TLS data from %s (type=0x%02x, len=%d), skipping...", clientID, data[0], tlsLen)
			// Skip this TLS record - don't add to packetBuf
			continue
		}

		// De-obfuscate
		if obfuscator != nil {
			deobfuscated, _, err := obfuscator.Process(data, interfaces.DirectionInbound)
			if err != nil {
				s.log.Warn("Deobfuscation failed from %s: %v", clientID, err)
				return
			}
			data = deobfuscated
		}

		// Append to accumulator
		packetBuf = append(packetBuf, data...)

		// Process frames
		for len(packetBuf) >= HeaderSize {
			// Check for TLS data in accumulated buffer
			if packetBuf[0] >= 0x14 && packetBuf[0] <= 0x17 && packetBuf[1] == 0x03 && len(packetBuf) >= 5 {
				tlsLen := int(packetBuf[3])<<8 | int(packetBuf[4])
				skipLen := 5 + tlsLen
				if skipLen <= len(packetBuf) {
					s.log.Warn("Skipping TLS record in buffer from %s (len=%d)", clientID, tlsLen)
					packetBuf = packetBuf[skipLen:]
					continue
				}
				break // Wait for more data
			}

			// Check potential frame length
			payloadLen := binary.BigEndian.Uint32(packetBuf[4:8])
			frameSize := HeaderSize + int(payloadLen)

			// Sanity check for frame size
			if frameSize > MaxPayloadLen+HeaderSize {
				s.log.Error("Frame too large from %s: %d", clientID, frameSize)
				return
			}

			if len(packetBuf) < frameSize {
				// Wait for more data
				break
			}

			// Extract frame data
			frameData := packetBuf[:frameSize]
			packetBuf = packetBuf[frameSize:] // Shift buffer

			f, err := Decode(frameData)
			if err != nil {
				s.log.Error("Frame decode error from %s: %v", clientID, err)
				return // Protocol violation
			}

			// Handle Frame via StreamManager
			switch f.Type {
			case FrameConnect:
				// Handle Connect Async to avoid blocking the tunnel read loop
				// Payload parsing and stream creation happens here
				go func(fr *Frame) {
					// Recover from panic to prevent crashing the server
					defer func() {
						if r := recover(); r != nil {
							s.log.Error("Panic in Connect handler: %v", r)
							sendFrame(NewConnectFailFrame(fr.StreamID, "Internal Error"))
						}
					}()

					// Deep copy payload as the buffer is reused
					payloadCopy := make([]byte, len(fr.Payload))
					copy(payloadCopy, fr.Payload)
					fr.Payload = payloadCopy // Swap with copy

					connPayload, err := DecodeConnectPayload(fr.Payload)
					if err != nil {
						sendFrame(NewConnectFailFrame(fr.StreamID, "InvPayload: "+err.Error()))
						return
					}
					// Permission check (optional, but good practice)
					if connPayload.Protocol == ProtoUDP && !s.config.EnableUDP {
						sendFrame(NewConnectFailFrame(fr.StreamID, "UDP disabled"))
						return
					}

					// Delegate to SM
					if err := sm.HandleConnect(fr.StreamID, connPayload, writer); err != nil {
						s.log.Warn("Stream %d connect failed: %v", fr.StreamID, err)
						sendFrame(NewConnectFailFrame(fr.StreamID, err.Error()))
					}
				}(f)

			case FrameData:
				sm.HandleData(f.StreamID, f.Payload)

			case FrameUDPData:
				// UDP Support!
				sm.HandleUDPData(f.StreamID, f.Payload)

			case FrameClose:
				sm.HandleClose(f.StreamID)

			case FramePing:
				sendFrame(NewPongFrame())

			case FrameWindowUpdate:
				if len(f.Payload) >= 4 {
					increment := binary.BigEndian.Uint32(f.Payload)
					sm.HandleWindowUpdate(f.StreamID, increment)
				}
			}
		}

		// Protection against buffer bloat attack
		if len(packetBuf) > 80*1024*1024 {
			s.log.Warn("Buffer overflow from %s, disconnecting", clientID)
			return
		}
	}
}
