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
	"whispera/internal/mux"

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

	// OPTIMIZATION: Tune TCP connection for low latency (VoIP/Gaming)
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// Disable Nagle's algorithm (Critical for real-time protocols)
		if err := tcpConn.SetNoDelay(true); err != nil {
			s.log.Debug("Failed to set NoDelay on tunnel: %v", err)
		}
		// Increase TCP buffers to 20MB to thoroughly match client capabilities
		// 20MB allows for full utilization of gigabit links over high latency
		_ = tcpConn.SetReadBuffer(20 * 1024 * 1024)
		_ = tcpConn.SetWriteBuffer(20 * 1024 * 1024)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// SMUX UPGRADE: Wrap connection in SMUX Session
	// The client is now configured to ALWAYS use SMUX. We must accept it.
	// Note: We use default config for now or a tuned one similar to client.
	muxCfg := &mux.Config{
		MaxFrameSize:         65535,
		MaxReceiveBuffer:     128 * 1024 * 1024,
		MaxStreamBuffer:      20 * 1024 * 1024, // 20MB (Ultra Aggressive buffering for 8K)
		KeepAliveInterval:    4 * time.Second,  // Sync with client
		KeepAliveTimeout:     60 * time.Second, // Sync with client
		MaxConcurrentStreams: 8,
	}

	session, err := mux.Server(conn, muxCfg)
	if err != nil {
		s.log.Error("Failed to create SMUX session for %s: %v", clientID, err)
		return
	}
	defer session.Close()

	// Accept the main stream (Transport Stream)
	// The client opens exactly one stream immediately after connecting.
	stream, err := session.AcceptStream()
	if err != nil {
		s.log.Error("Failed to accept SMUX stream from %s: %v", clientID, err)
		return
	}
	// Use the stream as the carrier connection
	conn = stream

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
	// Track exit reason for logging
	var exitReason string = "clean exit"
	var exitLevel logger.Level = logger.LevelInfo

	defer func() {
		if exitLevel == logger.LevelWarn {
			s.log.Warn("Tunnel closed for %s (Reason: %s)", clientID, exitReason)
		} else if exitLevel == logger.LevelError {
			s.log.Error("Tunnel closed for %s (Reason: %s)", clientID, exitReason)
		} else {
			s.log.Info("Tunnel closed for %s (Reason: %s)", clientID, exitReason)
		}
	}()

	// Helper to send frame
	sendFrame := func(f *Frame) error {
		encoded, err := f.Encode()
		if err != nil {
			return err
		}
		return writer.Write(encoded)
	}

	// READ BUFFER: Fixed size sliding window to prevent "append" allocations (Zero Copy)
	// 128KB + 64KB headroom for read
	const bufSize = 256 * 1024
	packetBuf := make([]byte, bufSize)
	bufOffset := 0 // Current write position in packetBuf

	// Temp buffer for socket reads (before obfuscation/copy)
	readBuf := make([]byte, 64*1024)

	// Send immediate PONG to break potential deadlock
	welcomeFrame := NewPongFrame()
	if err := sendFrame(welcomeFrame); err != nil {
		s.log.Warn("Failed to send welcome PONG: %v", err)
	} else {
		s.log.Debug("Sent welcome PONG to %s", clientID)
	}

	for {
		conn.SetReadDeadline(time.Now().Add(300 * time.Second)) // 5 min idle
		n, err := conn.Read(readBuf)
		if err != nil {
			if err == io.EOF {
				exitReason = "client disconnected (EOF)"
				return
			}
			exitReason = fmt.Sprintf("read error: %v", err)
			exitLevel = logger.LevelWarn
			return
		}

		data := readBuf[:n]

		// DEBUG: Log first bytes
		if n >= 8 && s.config.Debug {
			s.log.Debug("Tunnel data from %s: first 8 bytes = [%02x %02x %02x %02x %02x %02x %02x %02x]",
				clientID, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7])
		}

		// Check for TLS data (leftover) - on the FRESH read buffer
		if n >= 5 && data[0] >= 0x14 && data[0] <= 0x17 && data[1] == 0x03 {
			tlsLen := int(data[3])<<8 | int(data[4])
			s.log.Warn("Detected TLS data from %s (type=0x%02x, len=%d), skipping...", clientID, data[0], tlsLen)
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

		// Sliding Window: Copy data to packetBuf
		if bufOffset+len(data) > len(packetBuf) {
			s.log.Warn("Buffer overflow from %s (offset=%d, len=%d), disconnecting", clientID, bufOffset, len(data))
			return
		}
		copy(packetBuf[bufOffset:], data)
		bufOffset += len(data)

		// Process frames from packetBuf
		processed := 0
		currentBuf := packetBuf[:bufOffset]

		for len(currentBuf) >= HeaderSize {
			// Check for TLS data in accumulated buffer
			if currentBuf[0] >= 0x14 && currentBuf[0] <= 0x17 && currentBuf[1] == 0x03 && len(currentBuf) >= 5 {
				tlsLen := int(currentBuf[3])<<8 | int(currentBuf[4])
				skipLen := 5 + tlsLen
				if skipLen <= len(currentBuf) {
					s.log.Warn("Skipping TLS record in buffer from %s (len=%d)", clientID, tlsLen)
					processed += skipLen
					currentBuf = currentBuf[skipLen:]
					continue
				}
				break // Wait for more data
			}

			// Check frame length
			payloadLen := binary.BigEndian.Uint32(currentBuf[4:8])
			frameSize := HeaderSize + int(payloadLen)

			if frameSize > MaxPayloadLen+HeaderSize {
				s.log.Error("Frame too large from %s: %d", clientID, frameSize)
				return
			}

			if len(currentBuf) < frameSize {
				break // Wait for more data
			}

			// Extract frame (ZERO COPY: slice of packetBuf)
			frameData := currentBuf[:frameSize]

			// Decode (ZERO COPY: uses slice)
			fr, err := Decode(frameData)
			if err != nil {
				s.log.Error("Frame decode error from %s: %v", clientID, err)
				return
			}

			// Handle Frame
			switch fr.Type {
			case FrameConnect:
				go func(f *Frame) {
					defer func() {
						if r := recover(); r != nil {
							s.log.Error("Panic in Connect handler: %v", r)
							sendFrame(NewConnectFailFrame(f.StreamID, "Internal Error"))
						}
					}()

					// Deep copy payload as the buffer WILL be compacted/overwritten
					payloadCopy := make([]byte, len(f.Payload))
					copy(payloadCopy, f.Payload)
					f.Payload = payloadCopy

					connPayload, err := DecodeConnectPayload(f.Payload)
					if err != nil {
						sendFrame(NewConnectFailFrame(f.StreamID, "InvPayload: "+err.Error()))
						return
					}
					if connPayload.Protocol == ProtoUDP && !s.config.EnableUDP {
						sendFrame(NewConnectFailFrame(f.StreamID, "UDP disabled"))
						return
					}
					if err := sm.HandleConnect(f.StreamID, connPayload, writer); err != nil {
						s.log.Warn("Stream %d connect failed: %v", f.StreamID, err)
						sendFrame(NewConnectFailFrame(f.StreamID, err.Error()))
					}
				}(fr)

			case FrameData:
				sm.HandleData(fr.StreamID, fr.Payload)

			case FrameUDPData:
				// ASYNC HANDLING: Vital for VoIP to prevent Head-of-Line Blocking
				// Deep copy payload as the buffer will be compacted
				payload := make([]byte, len(fr.Payload))
				copy(payload, fr.Payload)
				go sm.HandleUDPData(fr.StreamID, payload)

			case FrameClose:
				sm.HandleClose(fr.StreamID)

			case FramePing:
				sendFrame(NewPongFrame())

			case FrameWindowUpdate:
				if len(fr.Payload) >= 4 {
					increment := binary.BigEndian.Uint32(fr.Payload)
					sm.HandleWindowUpdate(fr.StreamID, increment)
				}
			}

			// Advance
			processed += frameSize
			currentBuf = currentBuf[frameSize:]
		}

		// Compact buffer
		if processed > 0 {
			remaining := bufOffset - processed
			if remaining > 0 {
				copy(packetBuf, packetBuf[processed:bufOffset])
			}
			bufOffset = remaining
		}
	}
}
