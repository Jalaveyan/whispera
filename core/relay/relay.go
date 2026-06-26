package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"whispera/common/buf"
	"whispera/common/dns"
	"whispera/common/log"
	mux2 "whispera/common/mux"
	"whispera/common/runtime/base"
	"whispera/common/runtime/interfaces"
	"whispera/common/runtime/registry"
	"whispera/core/transport"

	"golang.org/x/net/proxy"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

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

var dohResolver = dns.NewResolver(dns.DefaultConfig())

func lookupIPCached(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dohResolver.Resolve(ctx, host)
}

const targetDialTimeout = 15 * time.Second

func dialTarget(dialer proxy.Dialer, network, host string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ctx, cancel := context.WithTimeout(context.Background(), targetDialTimeout)
	defer cancel()
	dial := func(a string) (net.Conn, error) {
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, a)
		}
		return dialer.Dial(network, a)
	}
	if dialer != proxy.Direct || net.ParseIP(host) != nil {
		return dial(addr)
	}
	ips, err := lookupIPCached(host)
	if err != nil || len(ips) == 0 {
		return dial(addr)
	}
	var lastErr error
	for _, ip := range ips {
		conn, derr := dial(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

type Server struct {
	*base.Module
	config      *Config
	proxyDialer proxy.Dialer
	router      interfaces.Router
	routerMu    sync.RWMutex

	outboundDial func(ctx context.Context, tag, network, addr string) (net.Conn, error)

	streamSem chan struct{}

	log *logger.Logger
	mu  sync.RWMutex
}

type copyResult struct {
	n   int64
	err error
	dir string
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
		Module:    base.NewModule(ModuleName, ModuleVersion, nil),
		config:    cfg,
		streamSem: make(chan struct{}, limit),
		log:       logger.Module("relay"),
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
	}

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

	return nil
}

func (s *Server) Stop() error {
	return s.Module.Stop()
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

func (s *Server) SetProxyDialer(d proxy.Dialer) {
	s.mu.Lock()
	s.proxyDialer = d
	s.mu.Unlock()
}

func (s *Server) HealthCheck() interfaces.HealthStatus {
	return s.Module.HealthCheck()
}

var tunnelTraceSeq uint64

type byteCountConn struct {
	net.Conn
	n     int64
	first []byte
}

func (c *byteCountConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		total := atomic.AddInt64(&c.n, int64(n))
		if total <= 64 {
			c.first = append(c.first, b[:n]...)
			if len(c.first) > 64 {
				c.first = c.first[:64]
			}
		}
	}
	return n, err
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
	traceID := atomic.AddUint64(&tunnelTraceSeq, 1)
	startedAt := time.Now()
	logger.Trace().Infow("serve_tunnel_enter",
		"trace_id", traceID,
		"client", clientID,
		"conn_type", fmt.Sprintf("%T", conn),
		"stream_obf", streamObf,
		"use_padding", usePadding,
	)

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	const firstStreamTimeout = 3 * time.Second
	_ = conn.SetReadDeadline(time.Now().Add(firstStreamTimeout))

	muxCfg := &mux2.Config{
		MaxFrameSize:         65535,
		MaxReceiveBuffer:     1 << 28,
		MaxStreamBuffer:      1 << 26,
		DisableKeepAlive:     true,
		MaxConcurrentStreams: s.config.MaxConcurrentStreams,
	}

	var muxConn net.Conn
	if usePadding {
		padMax := s.config.PaddingMaxSize
		if padMax <= 0 {
			padMax = 128
		}
		muxConn = mux2.NewPaddedConn(conn, padMax)
	} else {
		muxConn = conn
	}

	bc := &byteCountConn{Conn: muxConn}
	muxConn = bc

	session, err := mux2.Server(muxConn, muxCfg)
	if err != nil {
		s.log.Error("[T%d] Failed to create SMUX session for %s: %v", traceID, clientID, err)
		return
	}
	defer session.Close()

	firstStream := true
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if firstStream {
				readBytes := atomic.LoadInt64(&bc.n)
				logger.Trace().Warnw("ended_before_first_stream",
					"trace_id", traceID,
					"client", clientID,
					"dur_ms", time.Since(startedAt).Milliseconds(),
					"conn_type", fmt.Sprintf("%T", conn),
					"bytes_read", readBytes,
					"first_bytes", fmt.Sprintf("%x", bc.first),
					"err", err.Error(),
					"err_type", fmt.Sprintf("%T", err),
				)
			}
			return
		}
		if firstStream {
			firstStream = false
			_ = conn.SetReadDeadline(time.Time{})
			logger.Trace().Infow("control_stream_accepted",
				"trace_id", traceID,
				"client", clientID,
				"dur_ms", time.Since(startedAt).Milliseconds(),
				"bytes_read", atomic.LoadInt64(&bc.n),
			)
			if streamObf {
				go func() {
					defer func() {
						if r := recover(); r != nil {
							s.log.Error("PANIC in control stream io.Copy: %v\n%s", r, debug.Stack())
						}
					}()
					io.Copy(io.Discard, transport.WrapStreamTLS(stream))
				}()
			} else {
				go s.serveControlStream(stream)
			}
			continue
		}
		var proxyConn net.Conn = stream
		if streamObf {
			proxyConn = transport.WrapStreamTLS(stream)
		}
		logger.Trace().Infow("proxy_stream_accepted",
			"trace_id", traceID,
			"client", clientID,
		)
		select {
		case s.streamSem <- struct{}{}:
			go func() {
				defer func() { <-s.streamSem }()
				s.handleProxyStream(traceID, clientID, proxyConn)
			}()
		default:
			proxyConn.Close()
		}
	}
}

func (s *Server) serveControlStream(stream net.Conn) {
	defer stream.Close()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("PANIC in serveControlStream: %v\n%s", r, debug.Stack())
		}
	}()
	hdr := make([]byte, 8)
	for {
		stream.SetReadDeadline(time.Now().Add(90 * time.Second))
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

func (s *Server) handleProxyStream(tunnelID uint64, clientID string, stream net.Conn) {
	defer stream.Close()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("PANIC in handleProxyStream: %v\n%s", r, debug.Stack())
		}
	}()

	stream.SetReadDeadline(time.Now().Add(10 * time.Second))

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

	stream.SetReadDeadline(time.Time{})

	streamStart := time.Now()
	logger.Trace().Infow("proxy_stream_start",
		"trace_id", tunnelID,
		"client", clientID,
		"target", fmt.Sprintf("%s:%d", addr, port),
		"proto", fmt.Sprintf("0x%02x", proto),
	)

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
		logger.Trace().Warnw("proxy_stream_dial_fail",
			"trace_id", tunnelID,
			"target", targetAddr,
			"dial_ms", dialDur.Milliseconds(),
			"err", err.Error(),
			"err_type", fmt.Sprintf("%T", err),
		)
		return
	}
	defer target.Close()
	logger.Trace().Infow("proxy_stream_dial_ok",
		"trace_id", tunnelID,
		"target", targetAddr,
		"dial_ms", dialDur.Milliseconds(),
	)
	if dialDur > 500*time.Millisecond {
	}

	ackStart := time.Now()
	if _, err := stream.Write([]byte{0x00}); err != nil {
		return
	}
	if d := time.Since(ackStart); d > 200*time.Millisecond {
	}

	if tcpTarget, ok := target.(*net.TCPConn); ok {
		tcpTarget.SetKeepAlive(true)
		tcpTarget.SetKeepAlivePeriod(45 * time.Second)
	}

	resCh := make(chan copyResult, 2)

	if network == "udp" {
		go func() {
			defer target.Close()
			defer func() {
				if r := recover(); r != nil {
					s.log.Error("PANIC in UDP upstream copy: %v\n%s", r, debug.Stack())
				}
			}()
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
			defer func() {
				if r := recover(); r != nil {
					s.log.Error("PANIC in TCP upstream copy: %v\n%s", r, debug.Stack())
				}
			}()
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
	errField := ""
	if firstErr != nil && !isNormalConnClose(firstErr) && !errors.Is(firstErr, io.EOF) {
		errField = firstErr.Error()
	}
	logger.Trace().Infow("proxy_stream_done",
		"trace_id", tunnelID,
		"target", fmt.Sprintf("%s:%d", addr, port),
		"up", up,
		"down", down,
		"dur_ms", dur.Milliseconds(),
		"err_dir", firstDir,
		"err", errField,
	)
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
