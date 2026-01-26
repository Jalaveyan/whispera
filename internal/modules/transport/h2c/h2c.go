// Package h2c implements HTTP/2 cleartext (h2c) transport
// H2C allows HTTP/2 without TLS, useful for trusted networks
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
	"whispera/internal/logger"
)

var log = logger.Module("h2c")

const (
	ModuleName    = "transport.h2c"
	ModuleVersion = "1.0.0"
)

// Config holds h2c configuration
type Config struct {
	// Listen address
	ListenAddr string

	// Path for tunneling (default: /)
	Path string

	// Enable HTTP/2 server push
	EnablePush bool

	// Max concurrent streams
	MaxConcurrentStreams uint32

	// Initial window size
	InitialWindowSize uint32

	// Max frame size
	MaxFrameSize uint32

	// Read/Write timeouts
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// Headers to set
	Headers map[string]string
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Path:                 "/",
		MaxConcurrentStreams: 2000,              // Increased from 100
		InitialWindowSize:    64 * 1024 * 1024,  // 64MB window for high throughput
		MaxFrameSize:         16 * 1024 * 1024,  // 16MB jumbo frames (max allowed)
		ReadTimeout:          120 * time.Second, // Increased timeout
		WriteTimeout:         120 * time.Second, // Increased timeout
		Headers:              make(map[string]string),
	}
}

// Validate validates configuration
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

// Transport implements h2c transport
type Transport struct {
	*base.Module
	config *Config

	mu       sync.RWMutex
	server   *http.Server
	listener net.Listener

	// Active connections
	streams sync.Map // streamID -> *H2CStream

	// Client for Dial
	client *H2CClient

	// Server-side connection acceptance
	acceptChan chan net.Conn

	// Stats
	totalConns   uint64
	activeConns  int32
	totalStreams uint64
	bytesIn      uint64
	bytesOut     uint64
}

// H2CStream represents an HTTP/2 stream
type H2CStream struct {
	id        uint32
	r         *io.PipeReader
	w         *io.PipeWriter
	transport *Transport
	closed    atomic.Bool
}

// New creates a new h2c transport
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

// Listen starts the h2c server on the given address
func (t *Transport) Listen(addr string) error {
	t.config.ListenAddr = addr
	return t.listenInternal(context.Background())
}

// listenInternal starts the listener (internal helper)
func (t *Transport) listenInternal(ctx context.Context) error {
	h2s := &http2.Server{
		MaxConcurrentStreams:         t.config.MaxConcurrentStreams,
		MaxReadFrameSize:             t.config.MaxFrameSize, // Match config
		PermitProhibitedCipherSuites: true,                  // Allow cleartext ciphers if needed
		IdleTimeout:                  120 * time.Second,
		MaxUploadBufferPerConnection: 256 * 1024 * 1024, // 256MB - Maximized for 500Mbps+
		MaxUploadBufferPerStream:     64 * 1024 * 1024,  // 64MB
	}

	handler := http.HandlerFunc(t.handleRequest)
	h2cHandler := h2c.NewHandler(handler, h2s)

	t.server = &http.Server{
		Addr:         t.config.ListenAddr,
		Handler:      h2cHandler,
		ReadTimeout:  t.config.ReadTimeout,
		WriteTimeout: t.config.WriteTimeout,
	}

	listener, err := net.Listen("tcp", t.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	t.mu.Lock()
	t.listener = listener
	t.mu.Unlock()

	log.Info("H2C listening on %s", t.config.ListenAddr)

	go func() {
		if err := t.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Error("Server error: %v", err)
		}
	}()

	return nil
}

// handleRequest handles HTTP/2 requests
func (t *Transport) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Simple check to ensure it's H2C if possible, though handler is h2c wrapped.

	// Check path
	if r.URL.Path != t.config.Path {
		http.NotFound(w, r)
		return
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt32(&t.activeConns, 1)
	defer atomic.AddInt32(&t.activeConns, -1)

	// Get flusher for streaming
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Set response headers
	for k, v := range t.config.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	log.Debug("New h2c connection from %s", r.RemoteAddr)

	// Wrap as net.Conn and send to acceptChan
	// We need a pipe to write to the response writer from the net.Conn.Write
	// And we read from r.Body in net.Conn.Read

	// Create a pipe for the writer
	// The 'remote' side writes to 'pr', we read from 'pr' and write to 'w'
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

	// Keep handler alive and relay data from pipe to response
	// Copy from pipe reader 'pr' to 'w'
	// This blocks until 'conn' is closed or error
	// Use 1MB buffer for high throughput copying
	buf := make([]byte, 1024*1024)
	io.CopyBuffer(w, pr, buf)
}

// Interface implementation

// Dial connects to a target
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if t.client == nil {
		return nil, fmt.Errorf("client not initialized")
	}
	return t.client.Dial(ctx, addr)
}

// Accept returns the next accepted connection
func (t *Transport) Accept() (net.Conn, error) {
	conn, ok := <-t.acceptChan
	if !ok {
		return nil, fmt.Errorf("transport closed")
	}
	return conn, nil
}

// Type returns the transport type
func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportH2C
}

// Close closes the transport
func (t *Transport) Close() error {
	return t.Stop()
}

// Client-side functionality

// H2CClient is an HTTP/2 cleartext client
type H2CClient struct {
	config    *Config
	transport *http2.Transport
	client    *http.Client

	mu     sync.RWMutex
	active map[string]net.Conn
}

// NewClient creates a new h2c client
func NewClient(cfg *Config) (*H2CClient, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	t := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			// For h2c, we use a regular TCP connection
			return net.Dial(network, addr)
		},
		MaxHeaderListSize:          1024 * 1024 * 10, // 10MB
		StrictMaxConcurrentStreams: false,
		ReadIdleTimeout:            120 * time.Second,
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

// Dial connects to an h2c server and returns a bidirectional stream
func (c *H2CClient) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// Create pipe for bidirectional communication
	pr, pw := io.Pipe()

	// Build URL
	url := fmt.Sprintf("http://%s%s", addr, c.config.Path)

	// Create request with body
	req, err := http.NewRequestWithContext(ctx, "POST", url, pr)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	// Perform upgrade
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

// h2cConn wraps an h2c stream as net.Conn
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

// H2CUpgrader handles HTTP/1.1 to HTTP/2 upgrade
type H2CUpgrader struct {
	// Settings
	MaxConcurrentStreams uint32
}

// Upgrade upgrades an HTTP/1.1 connection to HTTP/2
func (u *H2CUpgrader) Upgrade(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	// Check for HTTP/2 upgrade
	if r.ProtoMajor != 1 {
		return nil, nil, fmt.Errorf("not HTTP/1.1")
	}

	// Check upgrade header
	if r.Header.Get("Upgrade") != "h2c" {
		return nil, nil, fmt.Errorf("no h2c upgrade header")
	}

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking not supported")
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("hijack failed: %w", err)
	}

	// Send 101 Switching Protocols
	rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	rw.WriteString("Connection: Upgrade\r\n")
	rw.WriteString("Upgrade: h2c\r\n")
	rw.WriteString("\r\n")
	rw.Flush()

	return conn, rw, nil
}

// Transport interface implementation

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
	t.server = nil // Clear server so we don't try to shutdown again

	close(t.acceptChan) // Close accept channel

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

// Factory creates h2c transport modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		// Try to parse from map if needed, or use default
		config = DefaultConfig()
	}
	return New(config)
}
