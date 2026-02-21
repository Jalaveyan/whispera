package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
	"whispera/internal/mux"

	"golang.org/x/net/proxy"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "relay.server"
	ModuleVersion = "1.0.0"
)

type ResponseWriter interface {
	Write(data []byte) error
	RemoteAddr() net.Addr
}
type Config struct {
	MaxStreams    int
	EnableTCP     bool
	EnableUDP     bool
	Debug         bool
	SafeMode      bool
	UpstreamProxy string
}

func DefaultConfig() *Config {
	return &Config{
		MaxStreams: 10000,
		EnableTCP:  true,
		EnableUDP:  true,
		Debug:      false,
		SafeMode:   true,
	}
}

func (c *Config) Validate() error {
	if c.MaxStreams <= 0 {
		c.MaxStreams = 10000
	}
	return nil
}

type Server struct {
	*base.Module
	config           *Config
	streamManager    *StreamManager
	proxyDialer      proxy.Dialer
	sendFrame        func(data []byte, addr net.Addr) error
	rawPacketHandler func(data []byte) error
	sessionWriters   map[uint32]ResponseWriter
	sessionWritersMu sync.RWMutex
	rawPackets       map[uint32]ResponseWriter
	rawPacketsMu     sync.RWMutex

	framesIn       uint64
	framesOut      uint64
	bytesRelayed   uint64
	activeStreams  uint64
	connectSuccess uint64
	connectFailed  uint64

	log *logger.Logger
	mu  sync.RWMutex
}

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

	s.streamManager = NewStreamManager(s.proxyDialer)

	return s, nil
}

func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}
	return nil
}

func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	s.log.Info("Server started (max streams: %d)", s.config.MaxStreams)
	return nil
}

func (s *Server) Stop() error {
	s.streamManager.CloseAll()
	return s.Module.Stop()
}

func (s *Server) SetTransport(sendFrame func(data []byte, addr net.Addr) error) {
	s.sendFrame = sendFrame
}
func (s *Server) SetRawPacketHandler(handler func(data []byte) error) {
	s.rawPacketHandler = handler
}

func (s *Server) RegisterSessionWriter(sessionID uint32, writer ResponseWriter) {
	s.sessionWritersMu.Lock()
	defer s.sessionWritersMu.Unlock()
	s.sessionWriters[sessionID] = writer
}

func (s *Server) GetSessionWriter(sessionID uint32) ResponseWriter {
	s.sessionWritersMu.RLock()
	defer s.sessionWritersMu.RUnlock()
	return s.sessionWriters[sessionID]
}

func (s *Server) ProcessFrame(data []byte, session interfaces.Session, writer ResponseWriter) error {
	atomic.AddUint64(&s.framesIn, 1)

	if session != nil {
		s.RegisterSessionWriter(session.ID(), writer)
	}

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

	if payload.Protocol == ProtoUDP && !s.config.EnableUDP {
		s.sendFrameToWriter(NewConnectFailFrame(frame.StreamID, "UDP relay disabled"), writer)
		return nil
	}
	if payload.Protocol == ProtoTCP && !s.config.EnableTCP {
		s.sendFrameToWriter(NewConnectFailFrame(frame.StreamID, "TCP relay disabled"), writer)
		return nil
	}

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

func (s *Server) handleData(frame *Frame) error {
	return s.streamManager.HandleData(frame.StreamID, frame.Payload)
}
func (s *Server) handleClose(frame *Frame) {
	s.streamManager.HandleClose(frame.StreamID)
}

func (s *Server) handlePing(writer ResponseWriter) error {
	return s.sendFrameToWriter(NewPongFrame(), writer)
}
func (s *Server) handleUDPData(frame *Frame, _ ResponseWriter) error {
	return s.streamManager.HandleUDPData(frame.StreamID, frame.Payload)
}

func (s *Server) handleRawPacket(frame *Frame, writer ResponseWriter) error {
	_, rawPacket, err := ParseRawPacketFrame(frame)
	if err != nil {
		return err
	}

	if s.rawPacketHandler != nil {
		return s.rawPacketHandler(rawPacket)
	}

	s.rawPacketsMu.Lock()
	s.rawPackets[0] = writer
	s.rawPacketsMu.Unlock()
	if s.config.Debug {
		s.log.Debug("Received RAW packet len=%d (No handler set)", len(rawPacket))
	}
	return nil
}

func (s *Server) sendFrameToWriter(frame *Frame, writer ResponseWriter) error {
	encoded, err := frame.Encode()
	if err != nil {
		return err
	}
	atomic.AddUint64(&s.framesOut, 1)
	atomic.AddUint64(&s.bytesRelayed, uint64(len(encoded)))
	return writer.Write(encoded)
}

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

type tunnelWriter struct {
	conn       net.Conn
	obfuscator interfaces.Obfuscator
	mu         *sync.Mutex
}

func (w *tunnelWriter) Write(data []byte) error {
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

func (s *Server) ServeTunnel(conn net.Conn, obfuscator interfaces.Obfuscator) {
	defer conn.Close()
	clientID := conn.RemoteAddr().String()
	s.log.Info("Starting tunnel session for %s", clientID)

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetNoDelay(true); err != nil {
			s.log.Debug("Failed to set NoDelay on tunnel: %v", err)
		}
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	muxCfg := &mux.Config{
		MaxFrameSize:         32768,
		MaxReceiveBuffer:     256 * 1024 * 1024,
		MaxStreamBuffer:      32 * 1024 * 1024,
		KeepAliveInterval:    2 * time.Second,
		KeepAliveTimeout:     30 * time.Second,
		MaxConcurrentStreams: 1024,
	}

	session, err := mux.Server(conn, muxCfg)
	if err != nil {
		s.log.Error("Failed to create SMUX session for %s: %v", clientID, err)
		return
	}
	defer session.Close()

	stream, err := session.AcceptStream()
	if err != nil {
		s.log.Error("Failed to accept SMUX stream from %s: %v", clientID, err)
		return
	}
	conn = stream

	var writeMu sync.Mutex

	writer := &tunnelWriter{
		conn:       conn,
		obfuscator: obfuscator,
		mu:         &writeMu,
	}

	sm := NewStreamManager(s.proxyDialer)
	defer sm.CloseAll()
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

	sendFrame := func(f *Frame) error {
		encoded, err := f.Encode()
		if err != nil {
			return err
		}
		return writer.Write(encoded)
	}

	const bufSize = 2 * 1024 * 1024
	packetBuf := make([]byte, bufSize)
	bufOffset := 0

	readBuf := make([]byte, 256*1024)

	welcomeFrame := NewPongFrame()
	if err := sendFrame(welcomeFrame); err != nil {
		s.log.Warn("Failed to send welcome PONG: %v", err)
	} else {
		s.log.Debug("Sent welcome PONG to %s", clientID)
	}

	isFirstRead := true

	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(readBuf)
		if err != nil {
			if err == io.EOF {
				exitReason = "client disconnected (EOF)"
				return
			}

			errStr := err.Error()
			if strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "broken pipe") {
				exitReason = fmt.Sprintf("read error: %v", err)
				exitLevel = logger.LevelWarn
				s.log.Debug("Connection reset from %s, attempting cleanup", clientID)
				return
			}

			if strings.Contains(errStr, "i/o timeout") {
				s.log.Debug("Read timeout from %s, resetting deadline and retrying", clientID)
				continue
			}

			exitReason = fmt.Sprintf("read error: %v", err)
			exitLevel = logger.LevelWarn
			return
		}

		data := readBuf[:n]

		if n >= 8 && s.config.Debug {
			s.log.Debug("Tunnel data from %s: first 8 bytes = [%02x %02x %02x %02x %02x %02x %02x %02x]",
				clientID, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7])
		}

		if isFirstRead {
			isFirstRead = false
			if n >= 5 && data[0] >= 0x14 && data[0] <= 0x17 && data[1] == 0x03 {
				tlsLen := int(data[3])<<8 | int(data[4])
				s.log.Warn("Detected TLS data from %s (type=0x%02x, len=%d), skipping...", clientID, data[0], tlsLen)
				continue
			}
		}

		if obfuscator != nil {
			deobfuscated, _, err := obfuscator.Process(data, interfaces.DirectionInbound)
			if err != nil {
				s.log.Warn("Deobfuscation failed from %s: %v", clientID, err)
				return
			}
			data = deobfuscated
		}

		if bufOffset+len(data) > len(packetBuf) {
			s.log.Warn("Buffer overflow from %s (offset=%d, len=%d), disconnecting", clientID, bufOffset, len(data))
			return
		}
		copy(packetBuf[bufOffset:], data)
		bufOffset += len(data)

		processed := 0
		currentBuf := packetBuf[:bufOffset]

		for len(currentBuf) >= HeaderSize {
			if currentBuf[0] >= 0x14 && currentBuf[0] <= 0x17 && currentBuf[1] == 0x03 && len(currentBuf) >= 5 {
				tlsLen := int(currentBuf[3])<<8 | int(currentBuf[4])
				skipLen := 5 + tlsLen
				if skipLen <= len(currentBuf) {
					s.log.Warn("Skipping TLS record in buffer from %s (len=%d)", clientID, tlsLen)
					processed += skipLen
					currentBuf = currentBuf[skipLen:]
					continue
				}
				break
			}
			payloadLen := binary.BigEndian.Uint32(currentBuf[4:8])
			frameSize := HeaderSize + int(payloadLen)

			if frameSize > MaxPayloadLen+HeaderSize {
				s.log.Error("Frame too large from %s: %d", clientID, frameSize)
				return
			}

			if len(currentBuf) < frameSize {
				break
			}

			frameData := currentBuf[:frameSize]

			fr, err := Decode(frameData)
			if err != nil {
				s.log.Error("Frame decode error from %s: %v", clientID, err)
				return
			}

			switch fr.Type {
			case FrameConnect:
				// Decode payload and pre-register stream synchronously before spawning
				// the goroutine. This prevents a race where FrameData (e.g. TLS ClientHello)
				// arrives before the goroutine registers the stream, causing HandleData to
				// return ErrStreamNotFound and silently drop early data.
				connPayload, decErr := DecodeConnectPayload(fr.Payload)
				if decErr != nil {
					sendFrame(NewConnectFailFrame(fr.StreamID, "InvPayload: "+decErr.Error()))
					break
				}
				if connPayload.Protocol == ProtoUDP && !s.config.EnableUDP {
					sendFrame(NewConnectFailFrame(fr.StreamID, "UDP disabled"))
					break
				}
				preStream, preErr := sm.HandlePreConnect(fr.StreamID, connPayload, writer)
				if preErr != nil {
					sendFrame(NewConnectFailFrame(fr.StreamID, preErr.Error()))
					break
				}
				streamID := fr.StreamID
				go func() {
					defer func() {
						if r := recover(); r != nil {
							s.log.Error("Panic in Connect handler: %v", r)
							sendFrame(NewConnectFailFrame(streamID, "Internal Error"))
						}
					}()
					ctx, cancel := context.WithTimeout(sm.ctx, 10*time.Second)
					defer cancel()
					if err := preStream.Connect(ctx); err != nil {
						sm.RemoveStream(streamID)
						s.log.Warn("Stream %d connect failed: %v", streamID, err)
						sendFrame(NewConnectFailFrame(streamID, err.Error()))
					} else {
						sendFrame(NewConnectOKFrame(streamID))
					}
				}()

			case FrameData:
				sm.HandleData(fr.StreamID, fr.Payload)

			case FrameUDPData:
				poolBuf := packetPool.Get().([]byte)
				payloadLen := len(fr.Payload)
				if payloadLen > len(poolBuf) {
					payloadLen = len(poolBuf)
				}
				payload := poolBuf[:payloadLen]
				copy(payload, fr.Payload[:payloadLen])
				streamID := fr.StreamID
				go func() {
					defer packetPool.Put(poolBuf)
					sm.HandleUDPData(streamID, payload)
				}()

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

			processed += frameSize
			currentBuf = currentBuf[frameSize:]
		}

		if processed > 0 {
			remaining := bufOffset - processed
			if remaining > 0 {
				copy(packetBuf, packetBuf[processed:bufOffset])
			}
			bufOffset = remaining
		}
	}
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
