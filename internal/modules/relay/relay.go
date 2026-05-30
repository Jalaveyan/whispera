package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/adblock"
	"whispera/internal/buf"
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

// isNormalConnClose returns true for errors that indicate a normal connection
// termination (broken pipe, reset by peer, closed network connection).
// These are expected in a relay and should not pollute INFO logs.
func isNormalConnClose(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "read/write on closed pipe") ||
		strings.Contains(msg, "closed pipe") ||
		strings.Contains(msg, "forcibly closed")
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
	MaxStreams           int
	EnableTCP            bool
	EnableUDP            bool
	Debug                bool
	SafeMode             bool
	UpstreamProxy        string
	MaxConcurrentStreams int
	PaddingMaxSize       int
}

func DefaultConfig() *Config {
	return &Config{
		MaxStreams:           10000,
		EnableTCP:            true,
		EnableUDP:            true,
		Debug:                false,
		SafeMode:             true,
		MaxConcurrentStreams: 1024,
	}
}

func (c *Config) Validate() error {
	if c.MaxStreams <= 0 {
		c.MaxStreams = 10000
	}
	return nil
}

var udpCopyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 2+65535)
		return &buf
	},
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

	streamSem chan struct{}

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

	limit := cfg.MaxConcurrentStreams
	if limit <= 0 {
		limit = 1024
	}
	s := &Server{
		Module:         base.NewModule(ModuleName, ModuleVersion, []string{"transport.udp"}),
		config:         cfg,
		sessionWriters: make(map[uint32]ResponseWriter),
		rawPackets:     make(map[uint32]ResponseWriter),
		streamSem:      make(chan struct{}, limit),
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

// SetProxyDialer replaces the default direct dialer used for untagged connections.
// Use this to inject per-module routing (e.g. WirAid proxy rules).
func (s *Server) SetProxyDialer(d proxy.Dialer) {
	s.mu.Lock()
	s.proxyDialer = d
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
	s.serveTunnel(conn, streamObf, true)
}

func (s *Server) ServeTunnelRaw(conn net.Conn, streamObf bool) {
	s.serveTunnel(conn, streamObf, false)
}

func (s *Server) serveTunnel(conn net.Conn, streamObf bool, usePadding bool) {
	defer conn.Close()
	clientID := conn.RemoteAddr().String()
	s.log.Debug("Starting tunnel session for %s", clientID)

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	kaBase := 30 + mrand.Intn(61)
	muxCfg := &mux.Config{
		MaxFrameSize:         65535,
		MaxReceiveBuffer:     1 << 28,
		MaxStreamBuffer:      1 << 24,
		KeepAliveInterval:    time.Duration(kaBase) * time.Second,
		KeepAliveTimeout:     120 * time.Second,
		MaxConcurrentStreams: s.config.MaxConcurrentStreams,
	}

	var muxConn net.Conn
	if usePadding {
		padMax := s.config.PaddingMaxSize
		if padMax <= 0 {
			padMax = 128
		}
		muxConn = mux.NewPaddedConn(conn, padMax)
	} else {
		muxConn = conn
	}

	session, err := mux.Server(muxConn, muxCfg)
	if err != nil {
		s.log.Error("Failed to create SMUX session for %s: %v", clientID, err)
		return
	}
	defer session.Close()

	s.log.Debug("Tunnel session ready for %s", clientID)

	firstStream := true
	s.log.Debug("waiting for first stream from %s", clientID)
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "keepalive timeout") ||
				strings.Contains(errStr, "session closed") ||
				strings.Contains(errStr, "EOF") ||
				isNormalConnClose(err) {
				s.log.Debug("Tunnel session ended for %s: %v", clientID, err)
			} else {
				s.log.Info("Tunnel session closed for %s: %v", clientID, err)
			}
			return
		}
		if firstStream {
			firstStream = false
			s.log.Debug("control stream (1) accepted from %s", clientID)
			if streamObf {
				go io.Copy(io.Discard, transport.WrapStreamTLS(stream))
			} else {
				go s.serveControlStream(stream)
			}
			continue
		}
		var proxyConn net.Conn = stream
		if streamObf {
			proxyConn = transport.WrapStreamTLS(stream)
		}
		select {
		case s.streamSem <- struct{}{}:
			go func() {
				defer func() { <-s.streamSem }()
				s.handleProxyStream(proxyConn)
			}()
		default:
			s.log.Info("stream limit reached, dropping stream from %s", clientID)
			proxyConn.Close()
		}
	}
}

func (s *Server) serveControlStream(stream net.Conn) {
	defer stream.Close()
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(stream, hdr); err != nil {
			return
		}
		payloadLen := binary.BigEndian.Uint32(hdr[4:8])
		if payloadLen > 131072 {
			return
		}
		if payloadLen > 0 {
			if _, err := io.CopyN(io.Discard, stream, int64(payloadLen)); err != nil {
				return
			}
		}
		if hdr[2] != 0x06 {
			continue
		}
		pong := [8]byte{}
		pong[2] = 0x07
		if _, err := stream.Write(pong[:]); err != nil {
			return
		}
	}
}

func (s *Server) handleProxyStream(stream net.Conn) {
	defer stream.Close()

	hdr := make([]byte, 3)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		s.log.Debug("handleProxyStream: read header failed: %v", err)
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

	s.log.Debug("proxy stream: %s:%d", addr, port)
	streamStart := time.Now()

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
			dstAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(addr, strconv.Itoa(int(port))))
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

	targetAddr := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	dialStart := time.Now()
	var target net.Conn
	var err error
	if outboundTag != "" {
		s.mu.RLock()
		dialFn := s.outboundDial
		s.mu.RUnlock()
		if dialFn != nil {
			dctx, dcancel := context.WithTimeout(context.Background(), targetDialTimeout)
			target, err = dialFn(dctx, outboundTag, network, targetAddr)
			dcancel()
		} else {
			target, err = dialTarget(dialer, network, addr, port)
		}
	} else {
		target, err = dialTarget(dialer, network, addr, port)
	}
	dialDur := time.Since(dialStart)
	if err != nil {
		stream.Write([]byte{0x01})
		s.log.Info("Dial %s:%d failed in %s: %v", addr, port, dialDur, err)
		return
	}
	defer target.Close()
	if dialDur > 500*time.Millisecond {
		s.log.Debug("slow dial %s:%d took %s", addr, port, dialDur)
	}

	ackStart := time.Now()
	if _, err := stream.Write([]byte{0x00}); err != nil {
		s.log.Info("ack write failed for %s:%d after %s: %v", addr, port, time.Since(ackStart), err)
		return
	}
	if d := time.Since(ackStart); d > 200*time.Millisecond {
		s.log.Debug("slow ack write %s:%d took %s", addr, port, d)
	}

	if tcpTarget, ok := target.(*net.TCPConn); ok {
		tcpTarget.SetKeepAlive(true)
		tcpTarget.SetKeepAlivePeriod(45 * time.Second)
	}

	type copyResult struct {
		n   int64
		err error
		dir string
	}
	resCh := make(chan copyResult, 2)

	if network == "udp" {
		go func() {
			defer target.Close()
			bufp := udpCopyBufPool.Get().(*[]byte)
			defer udpCopyBufPool.Put(bufp)
			localBuf := *bufp
			hdr := localBuf[:2]
			data := localBuf[2:]
			var n int64
			for {
				if _, err := io.ReadFull(stream, hdr); err != nil {
					resCh <- copyResult{n, err, "up"}
					return
				}
				sz := int(binary.BigEndian.Uint16(hdr))
				if sz == 0 || sz > len(data) {
					resCh <- copyResult{n, fmt.Errorf("invalid UDP frame size %d", sz), "up"}
					return
				}
				if _, err := io.ReadFull(stream, data[:sz]); err != nil {
					resCh <- copyResult{n, err, "up"}
					return
				}
				if _, err := target.Write(data[:sz]); err != nil {
					resCh <- copyResult{n, err, "up"}
					return
				}
				n += int64(sz)
			}
		}()
		func() {
			defer stream.Close()
			bufp := udpCopyBufPool.Get().(*[]byte)
			defer udpCopyBufPool.Put(bufp)
			localBuf := *bufp
			var n int64
			for {
				r, err := target.Read(localBuf[2:])
				if err != nil {
					resCh <- copyResult{n, err, "down"}
					return
				}
				binary.BigEndian.PutUint16(localBuf[:2], uint16(r))
				if _, err := stream.Write(localBuf[:2+r]); err != nil {
					resCh <- copyResult{n, err, "down"}
					return
				}
				n += int64(r)
			}
		}()
	} else {
		go func() {
			defer target.Close()
			n, err := buf.Copy(buf.NewReader(stream), buf.NewWriter(target))
			if tc, ok := target.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
			resCh <- copyResult{n, err, "up"}
		}()
		n, err := buf.Copy(buf.NewReader(target), buf.NewWriter(stream))
		if tc, ok := stream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		stream.Close()
		resCh <- copyResult{n, err, "down"}
	}
	r1 := <-resCh
	r2 := <-resCh
	var up, down int64
	var firstErr error
	var firstDir string
	for _, r := range [2]copyResult{r1, r2} {
		if r.dir == "up" {
			up = r.n
		} else {
			down = r.n
		}
		if firstErr == nil && r.err != nil && !errors.Is(r.err, io.EOF) {
			firstErr = r.err
			firstDir = r.dir
		}
	}
	dur := time.Since(streamStart)
	if firstErr != nil {
		if isNormalConnClose(firstErr) {
			s.log.Debug("stream done %s:%d up=%d down=%d in %s, %s closed: %v", addr, port, up, down, dur, firstDir, firstErr)
		} else {
			s.log.Debug("stream done %s:%d up=%d down=%d in %s, %s err: %v", addr, port, up, down, dur, firstDir, firstErr)
		}
	} else if dur > 5*time.Second || up+down > 0 {
		s.log.Debug("stream done %s:%d up=%d down=%d in %s", addr, port, up, down, dur)
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
