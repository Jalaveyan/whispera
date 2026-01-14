// Package h2 provides HTTP/2 transport module implementation
package h2

import (
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

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "transport.h2"
	ModuleVersion = "1.0.0"
)

// Config holds HTTP/2 transport configuration
type Config struct {
	ListenAddr string
	Path       string
	UseTLS     bool
	CertFile   string
	KeyFile    string
	Host       string // Host header for client
	MaxConns   int
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: ":8443",
		Path:       "/tunnel",
		UseTLS:     true,
		MaxConns:   10000,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.Path == "" {
		c.Path = "/tunnel"
	}
	return nil
}

// Transport implements interfaces.Transport for HTTP/2
type Transport struct {
	*base.Module
	config     *Config
	server     *http.Server
	listener   net.Listener
	mu         sync.RWMutex
	acceptChan chan net.Conn

	// Stats
	connCount   int64
	bytesRx     uint64
	bytesTx     uint64
	activeConns int64
}

// New creates a new HTTP/2 transport module
func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		Module:     base.NewModule(ModuleName, ModuleVersion, nil),
		config:     cfg,
		acceptChan: make(chan net.Conn, 1000),
	}

	return t, nil
}

// Init initializes the transport
func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if h2Cfg, ok := cfg.(*Config); ok {
		t.config = h2Cfg
	}

	return nil
}

// Start starts the HTTP/2 transport
func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc(t.config.Path, t.handleTunnel)

	t.server = &http.Server{
		Addr:    t.config.ListenAddr,
		Handler: mux,
	}

	// Configure HTTP/2
	h2Server := &http2.Server{}
	if err := http2.ConfigureServer(t.server, h2Server); err != nil {
		return fmt.Errorf("failed to configure http2: %w", err)
	}

	listener, err := net.Listen("tcp", t.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	t.listener = listener

	go func() {
		var err error
		if t.config.UseTLS && t.config.CertFile != "" && t.config.KeyFile != "" {
			err = t.server.ServeTLS(listener, t.config.CertFile, t.config.KeyFile)
		} else {
			// For H2C (cleartext), we need a specific handler or h2c support
			// Here assuming TLS is primary use case, or standard Serve for potentially H2C with prior knowledge
			err = t.server.Serve(listener)
		}

		if err != nil && err != http.ErrServerClosed {
			t.SetHealthy(false, fmt.Sprintf("server error: %v", err))
		}
	}()

	t.SetHealthy(true, fmt.Sprintf("listening on %s", t.config.ListenAddr))
	t.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": t.config.ListenAddr,
		"path":        t.config.Path,
	})

	return nil
}

// handleTunnel handles incoming tunnel requests
func (t *Transport) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Flusher is required for streaming
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Create a pipe to bridge HTTP body and net.Conn
	// This simple implementation might need a more complex structure to fully emulate net.Conn
	// For full duplex, we need to read from r.Body and write to w

	conn := &h2ServerConn{
		r:          r.Body,
		w:          w,
		flusher:    flusher,
		localAddr:  t.listener.Addr(),
		remoteAddr: nil, // Can parse r.RemoteAddr
		transport:  t,
		ctx:        r.Context(),
		cancelCtx:  nil, // Managed by server
	}

	// In server mode, we don't return the connection directly from here,
	// checking how to integrate with Accept().
	// Typically, we would send this conn to acceptChan, but HTTP handlers block.
	// So we need to block here until the connection is closed.

	select {
	case t.acceptChan <- conn:
		// Wait for context done (client closed)
		<-r.Context().Done()
	default:
		http.Error(w, "Server busy", http.StatusServiceUnavailable)
	}
}

// Stop stops the transport
func (t *Transport) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.server != nil {
		t.server.Close()
	}
	close(t.acceptChan)

	t.PublishEvent(events.EventTypeModuleStopped, nil)
	return t.Module.Stop()
}

// Type returns transport type
func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportType("h2")
}

// Listen is no-op
func (t *Transport) Listen(addr string) error {
	return nil
}

// Accept accepts a new connection
func (t *Transport) Accept() (net.Conn, error) {
	conn, ok := <-t.acceptChan
	if !ok {
		return nil, fmt.Errorf("transport stopped")
	}
	return conn, nil
}

// Dial connects to a remote server
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// Setup client
	// Note: In a real implementation this should use a persistent client
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For testing, configurable in pruduction
			ServerName:         t.config.Host,
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://%s%s", addr, t.config.Path), pr)
	if err != nil {
		return nil, err
	}

	// We need to start the request in a goroutine because Do blocks until response headers are read
	// Key challenge: getting the response body for reading.
	// For H2 full duplex, we send request body (pw) and read response body.

	// Complex part: How to return a net.Conn that writes to pw and reads from resp.Body?
	// We need 'resp' which is returned by client.Do(req).

	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)

	go func() {
		resp, err := client.Do(req)
		if err != nil {
			errChan <- err
			return
		}
		respChan <- resp
	}()

	// Wait for response headers (connection established)
	select {
	case resp := <-respChan:
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("server returned status: %s", resp.Status)
		}
		return &h2ClientConn{
			r:          resp.Body,
			w:          pw,
			localAddr:  nil,
			remoteAddr: nil,
			transport:  t,
		}, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("timeout waiting for handshake")
	}
}

// Close closes the transport
func (t *Transport) Close() error {
	return t.Stop()
}

// HealthCheck returns health status
func (t *Transport) HealthCheck() interfaces.HealthStatus {
	return t.Module.HealthCheck()
}

// Stats returns stats
func (t *Transport) Stats() interface{} {
	return map[string]interface{}{
		"conn_count": atomic.LoadInt64(&t.connCount),
	}
}

// --- Connection wrappers ---

type h2ServerConn struct {
	r          io.Reader
	w          io.Writer
	flusher    http.Flusher
	localAddr  net.Addr
	remoteAddr net.Addr
	transport  *Transport
	ctx        context.Context
	cancelCtx  context.CancelFunc
}

func (c *h2ServerConn) Read(b []byte) (n int, err error) {
	n, err = c.r.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesRx, uint64(n))
	}
	return
}

func (c *h2ServerConn) Write(b []byte) (n int, err error) {
	n, err = c.w.Write(b)
	if n > 0 {
		c.flusher.Flush()
		atomic.AddUint64(&c.transport.bytesTx, uint64(n))
	}
	return
}

func (c *h2ServerConn) Close() error {
	// Closing on server side usually means returning from handler
	// Logic to signal handler to return
	return nil
}

func (c *h2ServerConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *h2ServerConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *h2ServerConn) SetDeadline(t time.Time) error      { return nil }
func (c *h2ServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *h2ServerConn) SetWriteDeadline(t time.Time) error { return nil }

type h2ClientConn struct {
	r          io.ReadCloser
	w          *io.PipeWriter
	localAddr  net.Addr
	remoteAddr net.Addr
	transport  *Transport
}

func (c *h2ClientConn) Read(b []byte) (n int, err error) {
	n, err = c.r.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesRx, uint64(n))
	}
	return
}

func (c *h2ClientConn) Write(b []byte) (n int, err error) {
	n, err = c.w.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesTx, uint64(n))
	}
	return
}

func (c *h2ClientConn) Close() error {
	c.r.Close()
	c.w.Close()
	return nil
}

func (c *h2ClientConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *h2ClientConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *h2ClientConn) SetDeadline(t time.Time) error      { return nil }
func (c *h2ClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *h2ClientConn) SetWriteDeadline(t time.Time) error { return nil }
