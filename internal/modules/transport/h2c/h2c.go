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
		MaxConcurrentStreams: 100,
		InitialWindowSize:    65535,
		MaxFrameSize:         16384,
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
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

	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
	}

	return t, nil
}

// Listen starts the h2c server
func (t *Transport) Listen(ctx context.Context) error {
	h2s := &http2.Server{
		MaxConcurrentStreams: t.config.MaxConcurrentStreams,
		// InitialWindowSize not directly available, handled by transport
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

	// Create bidirectional stream
	ctx := r.Context()

	// Read from request body, write to response
	done := make(chan struct{}, 2)

	// Read from client
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := r.Body.Read(buf)
			if n > 0 {
				atomic.AddUint64(&t.bytesIn, uint64(n))
				// Process incoming data
				// In a real implementation, this would be relayed
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for completion
	<-done
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

func (t *Transport) Init(ctx context.Context) error {
	return nil
}

func (t *Transport) Start(ctx context.Context) error {
	if t.config.ListenAddr != "" {
		return t.Listen(ctx)
	}
	return nil
}

func (t *Transport) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return t.server.Shutdown(ctx)
	}
	return nil
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
