package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/adblock"
	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
	"whispera/internal/modules/transport"
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
	router           interfaces.Router
	routerMu         sync.RWMutex
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

	outboundDial func(ctx context.Context, tag, network, addr string) (net.Conn, error)

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

func (s *Server) SetRouter(r interfaces.Router) {
	s.routerMu.Lock()
	s.router = r
	s.routerMu.Unlock()
}

func (s *Server) SetOutboundDial(fn func(ctx context.Context, tag, network, addr string) (net.Conn, error)) {
	s.mu.Lock()
	s.outboundDial = fn
	s.mu.Unlock()
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

	if adblock.Global.IsBlocked(payload.Addr) {
		s.sendFrameToWriter(NewConnectFailFrame(frame.StreamID, "blocked"), writer)
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

func (s *Server) ServeTunnel(conn net.Conn, streamObf bool) {
	defer conn.Close()
	clientID := conn.RemoteAddr().String()
	s.log.Info("Starting tunnel session for %s", clientID)

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	kaBase := 30 + mrand.Intn(61)
	muxCfg := &mux.Config{
		MaxFrameSize:         65535,
		MaxReceiveBuffer:     256 * 1024 * 1024,
		MaxStreamBuffer:      4 * 1024 * 1024,
		KeepAliveInterval:    time.Duration(kaBase) * time.Second,
		KeepAliveTimeout:     120 * time.Second,
		MaxConcurrentStreams: 1024,
	}

	paddedConn := mux.NewPaddedConn(conn, 128)

	session, err := mux.Server(paddedConn, muxCfg)
	if err != nil {
		s.log.Error("Failed to create SMUX session for %s: %v", clientID, err)
		return
	}
	defer session.Close()

	s.log.Info("Tunnel session ready for %s", clientID)

	firstStream := true
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "keepalive timeout") ||
				strings.Contains(errStr, "session closed") ||
				strings.Contains(errStr, "EOF") {
				s.log.Debug("Tunnel session closed for %s: %v", clientID, err)
			} else {
				s.log.Info("Tunnel session closed for %s: %v", clientID, err)
			}
			return
		}
		if firstStream {
			firstStream = false
			if streamObf {
				go io.Copy(io.Discard, transport.WrapStreamTLS(stream))
			} else {
				go io.Copy(io.Discard, stream)
			}
			continue
		}
		var proxyConn net.Conn = stream
		if streamObf {
			proxyConn = transport.WrapStreamTLS(stream)
		}
		go s.handleProxyStream(proxyConn)
	}
}

func (s *Server) handleProxyStream(stream net.Conn) {
	defer stream.Close()

	hdr := make([]byte, 3)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		return
	}
	proto := hdr[0]
	addrLen := binary.BigEndian.Uint16(hdr[1:3])
	if addrLen == 0 || addrLen > 255 {
		return
	}

	rest := make([]byte, int(addrLen)+2)
	if _, err := io.ReadFull(stream, rest); err != nil {
		return
	}
	addr := string(rest[:addrLen])
	port := binary.BigEndian.Uint16(rest[addrLen:])

	network := "tcp"
	if proto == 0x11 {
		network = "udp"
	}

	dialer := s.proxyDialer
	var outboundTag string
	if network == "udp" {
		dialer = proxy.Direct
	} else {
		s.routerMu.RLock()
		rtr := s.router
		s.routerMu.RUnlock()
		if rtr != nil {
			dstAddr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", addr, port))
			pkt := &interfaces.Packet{DstAddr: dstAddr}
			if dest, err := rtr.Route(context.Background(), pkt); err == nil {
				switch dest.Type {
				case interfaces.DestinationDirect:
					dialer = proxy.Direct
				case interfaces.DestinationBlock:
					stream.Write([]byte{0x01})
					s.log.Info("Blocked connection to %s:%d by routing rule", addr, port)
					return
				default:
					if dest.Tag != "" {
						outboundTag = dest.Tag
					}
				}
			}
		}
	}

	targetAddr := fmt.Sprintf("%s:%d", addr, port)
	var target net.Conn
	var err error
	if outboundTag != "" {
		s.mu.RLock()
		dialFn := s.outboundDial
		s.mu.RUnlock()
		if dialFn != nil {
			target, err = dialFn(context.Background(), outboundTag, network, targetAddr)
		} else {
			target, err = dialer.Dial(network, targetAddr)
		}
	} else {
		target, err = dialer.Dial(network, targetAddr)
	}
	if err != nil {
		stream.Write([]byte{0x01})
		s.log.Warn("Dial %s:%d failed: %v", addr, port, err)
		return
	}
	defer target.Close()

	if _, err := stream.Write([]byte{0x00}); err != nil {
		return
	}

	if tcpTarget, ok := target.(*net.TCPConn); ok {
		tcpTarget.SetNoDelay(true)
	}

	errCh := make(chan error, 2)

	if network == "udp" {
		go func() {
			hdr := make([]byte, 2)
			buf := make([]byte, 65535)
			for {
				if _, err := io.ReadFull(stream, hdr); err != nil {
					errCh <- err
					return
				}
				sz := int(binary.BigEndian.Uint16(hdr))
				if sz == 0 || sz > len(buf) {
					errCh <- fmt.Errorf("invalid UDP frame size %d", sz)
					return
				}
				if _, err := io.ReadFull(stream, buf[:sz]); err != nil {
					errCh <- err
					return
				}
				if _, err := target.Write(buf[:sz]); err != nil {
					errCh <- err
					return
				}
			}
		}()
		go func() {
			buf := make([]byte, 2+65535)
			for {
				n, err := target.Read(buf[2:])
				if err != nil {
					errCh <- err
					return
				}
				binary.BigEndian.PutUint16(buf[:2], uint16(n))
				if _, err := stream.Write(buf[:2+n]); err != nil {
					errCh <- err
					return
				}
			}
		}()
	} else {
		go func() {
			buf := make([]byte, 512*1024)
			_, err := io.CopyBuffer(target, stream, buf)
			if tc, ok := target.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
			errCh <- err
		}()
		go func() {
			buf := make([]byte, 512*1024)
			_, err := io.CopyBuffer(stream, target, buf)
			if tc, ok := stream.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
			errCh <- err
		}()
	}
	<-errCh
	<-errCh
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
