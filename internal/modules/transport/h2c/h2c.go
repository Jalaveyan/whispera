package h2c

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("h2c")

const (
	ModuleName    = "transport.h2c"
	ModuleVersion = "1.0.0"
)

type Config struct {
	ListenAddr string

	Path string

	EnablePush bool

	MaxConcurrentStreams uint32

	InitialWindowSize uint32

	MaxFrameSize uint32

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	Headers map[string]string
}

func DefaultConfig() *Config {
	return &Config{
		Path:                 "/",
		MaxConcurrentStreams: 2000,
		InitialWindowSize:    64 * 1024 * 1024,
		MaxFrameSize:         16 * 1024 * 1024,
		ReadTimeout:          120 * time.Second,
		WriteTimeout:         120 * time.Second,
		Headers:              make(map[string]string),
	}
}

func (c *Config) Validate() error {
	if c.MaxConcurrentStreams == 0 {
		c.MaxConcurrentStreams = 100
	}
	if c.MaxFrameSize == 0 {
		c.MaxFrameSize = 16384
	}
	if c.Path == "" {
		c.Path = "/"
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config

	mu       sync.RWMutex
	server   *http.Server
	listener net.Listener

	streams sync.Map

	client *H2CClient

	acceptChan chan net.Conn

	totalConns   uint64
	activeConns  int32
	totalStreams uint64
	bytesIn      uint64
	bytesOut     uint64
}

type H2CStream struct {
	id        uint32
	r         *io.PipeReader
	w         *io.PipeWriter
	transport *Transport
	closed    atomic.Bool
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}

	t := &Transport{
		Module:     base.NewModule(ModuleName, ModuleVersion, nil),
		config:     cfg,
		client:     client,
		acceptChan: make(chan net.Conn, 100),
	}

	return t, nil
}

func (t *Transport) Listen(addr string) error {
	t.config.ListenAddr = addr
	return t.listenInternal(context.Background())
}

func (t *Transport) listenInternal(ctx context.Context) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", t.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	t.mu.Lock()
	t.listener = listener
	t.mu.Unlock()
	return t.startServe(listener)
}

// ServeOn starts H2C on an externally provided listener (shared-port mux).
func (t *Transport) ServeOn(l net.Listener) error {
	t.mu.Lock()
	t.listener = l
	t.mu.Unlock()
	return t.startServe(l)
}

func (t *Transport) startServe(l net.Listener) error {
	h2s := &http2.Server{
		MaxConcurrentStreams:         t.config.MaxConcurrentStreams,
		MaxReadFrameSize:             1 << 20,
		PermitProhibitedCipherSuites: true,
		IdleTimeout:                  120 * time.Second,
		MaxUploadBufferPerConnection: 1 << 24,
		MaxUploadBufferPerStream:     1 << 22,
	}

	handler := http.HandlerFunc(t.handleRequest)
	h2cHandler := h2c.NewHandler(handler, h2s)

	t.server = &http.Server{
		Addr:         t.config.ListenAddr,
		Handler:      h2cHandler,
		ReadTimeout:  t.config.ReadTimeout,
		WriteTimeout: t.config.WriteTimeout,
	}

	log.Info("H2C listening on %s", l.Addr())

	go func() {
		if err := t.server.Serve(l); err != nil && err != http.ErrServerClosed {
			log.Error("Server error: %v", err)
		}
	}()

	return nil
}

func (t *Transport) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != t.config.Path {
		http.NotFound(w, r)
		return
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt32(&t.activeConns, 1)
	defer atomic.AddInt32(&t.activeConns, -1)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	for k, v := range t.config.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	log.Debug("New h2c connection from %s", r.RemoteAddr)

	pr, pw := io.Pipe()

	conn := &h2cConn{
		reader: r.Body,
		writer: pw,
		addr:   r.RemoteAddr,
	}

	select {
	case t.acceptChan <- conn:
	default:
		log.Warn("Accept channel full, dropping connection from %s", r.RemoteAddr)
		return
	}

	buf := make([]byte, 1024*1024)
	io.CopyBuffer(w, pr, buf)
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if t.client == nil {
		return nil, fmt.Errorf("client not initialized")
	}
	return t.client.Dial(ctx, addr)
}

func (t *Transport) Accept() (net.Conn, error) {
	conn, ok := <-t.acceptChan
	if !ok {
		return nil, fmt.Errorf("transport closed")
	}
	return conn, nil
}

func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportH2C
}

func (t *Transport) Close() error {
	return t.Stop()
}

type H2CClient struct {
	config    *Config
	transport *http2.Transport
	client    *http.Client

	mu     sync.RWMutex
	active map[string]net.Conn
}

func NewClient(cfg *Config) (*H2CClient, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	t := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(context.Background(), network, addr)
		},
		MaxHeaderListSize:          1024 * 1024 * 10,
		StrictMaxConcurrentStreams: false,
		ReadIdleTimeout:            15 * time.Second,
		PingTimeout:                15 * time.Second,
		WriteByteTimeout:           120 * time.Second,
	}

	client := &http.Client{
		Transport: t,
		Timeout:   30 * time.Second,
	}

	return &H2CClient{
		config:    cfg,
		transport: t,
		client:    client,
		active:    make(map[string]net.Conn),
	}, nil
}

func (c *H2CClient) Dial(ctx context.Context, addr string) (net.Conn, error) {
	pr, pw := io.Pipe()

	url := fmt.Sprintf("http://%s%s", addr, c.config.Path)

	req, err := http.NewRequestWithContext(ctx, "POST", url, pr)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return &h2cConn{
		reader:   resp.Body,
		writer:   pw,
		response: resp,
		addr:     addr,
	}, nil
}

type h2cConn struct {
	reader   io.ReadCloser
	writer   *io.PipeWriter
	response *http.Response
	addr     string
}

func (c *h2cConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *h2cConn) Write(b []byte) (n int, err error) {
	return c.writer.Write(b)
}

func (c *h2cConn) Close() error {
	c.writer.Close()
	return c.reader.Close()
}

func (c *h2cConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
}

func (c *h2cConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", c.addr)
	return addr
}

func (c *h2cConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *h2cConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *h2cConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type H2CUpgrader struct {
	MaxConcurrentStreams uint32
}

func (u *H2CUpgrader) Upgrade(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	if r.ProtoMajor != 1 {
		return nil, nil, fmt.Errorf("not HTTP/1.1")
	}

	if r.Header.Get("Upgrade") != "h2c" {
		return nil, nil, fmt.Errorf("no h2c upgrade header")
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking not supported")
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("hijack failed: %w", err)
	}

	rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	rw.WriteString("Connection: Upgrade\r\n")
	rw.WriteString("Upgrade: h2c\r\n")
	rw.WriteString("\r\n")
	rw.Flush()

	return conn, rw, nil
}

func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}
	if h2cCfg, ok := cfg.(*Config); ok {
		t.config = h2cCfg
	}
	return nil
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}
	if t.config.ListenAddr != "" {
		return t.listenInternal(context.Background())
	}
	return nil
}

func (t *Transport) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.server.Shutdown(ctx)
	}
	t.server = nil

	close(t.acceptChan)

	return t.Module.Stop()
}

func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_connections":  atomic.LoadUint64(&t.totalConns),
		"active_connections": atomic.LoadInt32(&t.activeConns),
		"total_streams":      atomic.LoadUint64(&t.totalStreams),
		"bytes_in":           atomic.LoadUint64(&t.bytesIn),
		"bytes_out":          atomic.LoadUint64(&t.bytesOut),
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
