// Package relay provides the relay server module
package relay

import (
	"bufio"
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
	"whispera/internal/modules/qos"

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
	// Sync creation
	if err := s.streamManager.RegisterStream(frame.StreamID, payload, writer); err != nil {
		atomic.AddUint64(&s.connectFailed, 1)
		if s.config.Debug {
			s.log.Debug("Failed to register stream %d: %v", frame.StreamID, err)
		}
		return err
	}

	// Async dial
	// Note: We launch this in a goroutine because handleConnect itself is called synchronously
	// from ProcessFrame -> handleConnect. We must not block the frame processor.
	go func() {
		if err := s.streamManager.CompleteConnect(frame.StreamID, payload); err != nil {
			atomic.AddUint64(&s.connectFailed, 1)
			if s.config.Debug {
				s.log.Debug("Failed to connect stream %d: %v", frame.StreamID, err)
			}
			s.sendFrameToWriter(NewConnectFailFrame(frame.StreamID, err.Error()), writer)
		}
	}()

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
	baseWriter := &tunnelWriter{
		conn:       conn,
		obfuscator: obfuscator,
		mu:         &writeMu,
	}

	// QoS Integration
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Instance per tunnel
	voipQoS := qos.NewVoIPQoS()
	voipQoS.Enable()

	// Wrap with QoS Writer
	writer := &qosWriter{
		realWriter: baseWriter,
		qos:        voipQoS,
		ctx:        ctx,
	}

	// Start Pump
	go s.pumpQoS(ctx, voipQoS, baseWriter)

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

	// Buffered Reader for strict framing and Peeking
	reader := bufio.NewReaderSize(conn, 128*1024) // 128KB buffer

	// Send immediate PONG to break potential deadlock
	welcomeFrame := NewPongFrame()
	if err := sendFrame(welcomeFrame); err != nil {
		s.log.Warn("Failed to send welcome PONG: %v", err)
	} else {
		s.log.Debug("Sent welcome PONG to %s", clientID)
	}

	headerBuf := make([]byte, HeaderSize)

	for {
		conn.SetReadDeadline(time.Now().Add(300 * time.Second))

		// 1. Peek for TLS (Optimization to drop junk early)
		// We need at least 5 bytes to check TLS header
		peekBuf, err := reader.Peek(5)
		if err == nil {
			if peekBuf[0] >= 0x14 && peekBuf[0] <= 0x17 && peekBuf[1] == 0x03 {
				tlsLen := int(peekBuf[3])<<8 | int(peekBuf[4])
				s.log.Warn("Skipping TLS record from %s (len=%d)", clientID, tlsLen)
				// Discard header + payload
				reader.Discard(5 + tlsLen)
				continue
			}
		}

		// 2. Read Frame Header
		_, err = io.ReadFull(reader, headerBuf)
		if err != nil {
			if err != io.EOF {
				s.log.Debug("Tunnel header read error from %s: %v", clientID, err)
			}
			return
		}

		// 3. Parse Header to get Length
		payloadLen := binary.BigEndian.Uint32(headerBuf[4:8])
		frameSize := HeaderSize + int(payloadLen)

		if frameSize > MaxPayloadLen+HeaderSize {
			s.log.Error("Frame too large from %s: %d", clientID, frameSize)
			return
		}

		// 4. Allocate EXACT size buffer (One allocation per frame)
		// Optimization: We could use a sync.Pool here for common sizes (e.g. up to 64KB)
		// but simple make() is already much better than append().
		frameBuf := make([]byte, frameSize)

		// Copy header back (Zero cost practically)
		copy(frameBuf[:HeaderSize], headerBuf)

		// 5. Read Payload
		if payloadLen > 0 {
			_, err = io.ReadFull(reader, frameBuf[HeaderSize:])
			if err != nil {
				s.log.Error("Tunnel payload read error from %s: %v", clientID, err)
				return
			}
		}

		// 6. Decode (Zero Copy from frameBuf)
		f, err := Decode(frameBuf)
		if err != nil {
			s.log.Error("Frame decode error from %s: %v", clientID, err)
			return
		}

		// Handle Frame
		switch f.Type {
		case FrameConnect:
			// Handle connect...
			// (Use code from original block, simplified re-insertion)

			// Deep copy is implicit because 'frameBuf' is fresh for this iteration
			// But careful: f.Payload references frameBuf.
			// Async handlers MUST copy if they use payload later.
			// Currently Relay has:
			// FrameConnect -> Async Dial -> references payload.Addr/Port strings. Strings copy?
			// Strings are headers+ptr. If strings created from slice, they might reference underlying array?
			// Go strings are immutable but usually copy bytes.
			// 'DecodeConnectPayload' creates new strings.

			// Let's decode payload
			connPayload, err := DecodeConnectPayload(f.Payload)
			if err != nil {
				sendFrame(NewConnectFailFrame(f.StreamID, "InvPayload: "+err.Error()))
				continue
			}

			// Checks
			if connPayload.Protocol == ProtoUDP && !s.config.EnableUDP {
				sendFrame(NewConnectFailFrame(f.StreamID, "UDP disabled"))
				continue
			}
			if connPayload.Protocol == ProtoTCP && !s.config.EnableTCP {
				sendFrame(NewConnectFailFrame(f.StreamID, "TCP disabled"))
				continue
			}

			if err := sm.RegisterStream(f.StreamID, connPayload, writer); err != nil {
				sendFrame(NewConnectFailFrame(f.StreamID, "RegFail: "+err.Error()))
				continue
			}

			// Fast Path UDP
			isFastPath := (connPayload.Protocol == ProtoUDP && (connPayload.Addr == "0.0.0.0" || connPayload.Addr == "::"))
			if isFastPath {
				if err := sm.CompleteConnect(f.StreamID, connPayload); err != nil {
					sendFrame(NewConnectFailFrame(f.StreamID, err.Error()))
				}
			} else {
				// Async Dial
				// SAFE: connPayload strings are copies.
				go func(sid uint16, cp *ConnectPayload) {
					defer func() {
						if r := recover(); r != nil {
							sm.HandleClose(sid)
						}
					}()
					if err := sm.CompleteConnect(sid, cp); err != nil {
						sendFrame(NewConnectFailFrame(sid, err.Error()))
					}
				}(f.StreamID, connPayload)
			}

		case FrameData:
			sm.HandleData(f.StreamID, f.Payload)

		case FrameUDPData:
			// ZERO-COPY: f.Payload references 'frameBuf'.
			// Since we allocate a NEW 'frameBuf' for every frame in this loop,
			// we can safely pass this slice to the async handler.
			// The Garbage Collector will keep 'frameBuf' alive as long as the goroutine uses it.
			// No copy needed!

			go func(sid uint16, pay []byte) {
				sm.HandleUDPData(sid, pay)
			}(f.StreamID, f.Payload)

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
}

// --- QoS Integration ---

type qosWriter struct {
	realWriter ResponseWriter
	qos        *qos.VoIPQoS
	ctx        context.Context
}

func (w *qosWriter) Write(data []byte) error {
	// Parse Frame to find payload for inspection
	var payload []byte

	if len(data) >= 8 {
		frameType := data[2]
		if frameType == FrameUDPData {
			// Find UDP payload
			// Header(8) + ATYP(1) + ADDR(?) + PORT(2)
			offset := 8 + 1
			if len(data) > offset {
				atyp := data[8]
				switch atyp {
				case AddrTypeIPv4:
					offset += 4
				case AddrTypeIPv6:
					offset += 16
				case AddrTypeDomain:
					if len(data) > offset {
						l := int(data[offset])
						offset += 1 + l
					}
				}

				offset += 2 // Port

				if len(data) > offset {
					payload = data[offset:]
				}
			}
		}
	}

	// Process and Enqueue
	qp, err := w.qos.ProcessPacket(w.ctx, data, payload, w.realWriter.RemoteAddr())
	if err != nil {
		return err
	}

	w.qos.EnqueuePacket(qp)
	return nil
}

func (w *qosWriter) RemoteAddr() net.Addr {
	return w.realWriter.RemoteAddr()
}

func (s *Server) pumpQoS(ctx context.Context, voipQoS *qos.VoIPQoS, writer ResponseWriter) {
	for {
		qp, err := voipQoS.ReadPacket(ctx)
		if err != nil {
			return
		}

		if qp != nil {
			writer.Write(qp.Data)
		}
	}
}
