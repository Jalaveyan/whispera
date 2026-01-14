// Package websocket provides WebSocket transport module implementation
package websocket

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"

	"golang.org/x/net/websocket"
)

const (
	ModuleName    = "transport.websocket"
	ModuleVersion = "1.0.0"
)

// Config holds WebSocket transport configuration
type Config struct {
	ListenAddr   string
	Path         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxConns     int
	Origin       string
	Subprotocol  string
	// TLS options
	UseTLS             bool
	ServerName         string
	Fingerprint        string // Browser fingerprint: chrome, firefox, safari, etc.
	InsecureSkipVerify bool
}

// DefaultConfig returns default WebSocket configuration
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:   ":8443",
		Path:         "/ws",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		MaxConns:     10000,
		Origin:       "*",
		Subprotocol:  "whispera",
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.Path == "" {
		c.Path = "/ws"
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 10000
	}
	return nil
}

// Transport implements interfaces.Transport for WebSocket
type Transport struct {
	*base.Module
	config     *Config
	server     *http.Server
	mu         sync.RWMutex
	acceptChan chan net.Conn

	// Active connections
	connections sync.Map

	// Stats
	connCount    int64
	bytesRx      uint64
	bytesTx      uint64
	activeConns  int64
	acceptErrors uint64
}

// New creates a new WebSocket transport module
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

	if wsCfg, ok := cfg.(*Config); ok {
		t.config = wsCfg
	}

	return nil
}

// Start starts the WebSocket transport
func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle(t.config.Path, websocket.Handler(t.handleWebSocket))

	t.server = &http.Server{
		Addr:         t.config.ListenAddr,
		Handler:      mux,
		ReadTimeout:  t.config.ReadTimeout,
		WriteTimeout: t.config.WriteTimeout,
	}

	go func() {
		if err := t.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.SetHealthy(false, fmt.Sprintf("server error: %v", err))
		}
	}()

	t.SetHealthy(true, fmt.Sprintf("listening on %s%s", t.config.ListenAddr, t.config.Path))
	t.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": t.config.ListenAddr,
		"path":        t.config.Path,
	})

	return nil
}

// handleWebSocket handles incoming WebSocket connections
func (t *Transport) handleWebSocket(ws *websocket.Conn) {
	// Check max connections
	if atomic.LoadInt64(&t.activeConns) >= int64(t.config.MaxConns) {
		ws.Close()
		return
	}

	// Track connection
	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)

	id := atomic.LoadInt64(&t.connCount)

	// Wrap connection for stats tracking
	wrapped := &wsConn{
		Conn:      ws,
		transport: t,
		id:        id,
	}

	t.connections.Store(id, wrapped)

	// Send to accept channel
	select {
	case t.acceptChan <- wrapped:
		// Connection accepted
	default:
		// Channel full, close connection
		wrapped.Close()
		return
	}

	t.UpdateActivity()

	// Keep connection alive while it's being used
	// The caller will close it when done
	<-wrapped.closeChan
}

// Stop stops the WebSocket transport
func (t *Transport) Stop() error {
	t.mu.Lock()
	if t.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.server.Shutdown(ctx)
		t.server = nil
	}
	t.mu.Unlock()

	// Close accept channel
	close(t.acceptChan)

	// Close all active connections
	t.connections.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*wsConn); ok {
			conn.Close()
		}
		t.connections.Delete(key)
		return true
	})

	t.PublishEvent(events.EventTypeModuleStopped, nil)
	return t.Module.Stop()
}

// Type returns the transport type
func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportWebSocket
}

// Listen starts listening (already done in Start)
func (t *Transport) Listen(addr string) error {
	return nil
}

// Dial connects to a remote WebSocket server
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return t.DialWithFingerprint(ctx, addr, t.config.Fingerprint)
}

// DialWithFingerprint connects with a specific TLS fingerprint
func (t *Transport) DialWithFingerprint(ctx context.Context, addr string, fingerprint string) (net.Conn, error) {
	var scheme, origin string
	if t.config.UseTLS {
		scheme = "wss://"
		origin = "https://"
	} else {
		scheme = "ws://"
		origin = "http://"
	}

	config, err := websocket.NewConfig(scheme+addr+t.config.Path, origin+addr)
	if err != nil {
		return nil, err
	}
	config.Protocol = []string{t.config.Subprotocol}

	var ws *websocket.Conn

	// NOTE: uTLS fingerprinting temporarily disabled (internal/tls was removed)
	// TODO: Re-implement using crypto/tls or utls directly
	_ = fingerprint // Suppress unused warning

	// Standard dial without fingerprinting
	ws, err = websocket.DialConfig(config)
	if err != nil {
		return nil, err
	}

	// Track connection
	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)

	id := atomic.LoadInt64(&t.connCount)

	// Wrap connection for stats tracking
	wrapped := &wsConn{
		Conn:      ws,
		transport: t,
		id:        id,
	}

	t.connections.Store(id, wrapped)

	return wrapped, nil
}

// Accept accepts a new connection
func (t *Transport) Accept() (net.Conn, error) {
	conn, ok := <-t.acceptChan
	if !ok {
		return nil, fmt.Errorf("transport stopped")
	}
	return conn, nil
}

// Close closes the transport
func (t *Transport) Close() error {
	return t.Stop()
}

// HealthCheck returns detailed health status
func (t *Transport) HealthCheck() interfaces.HealthStatus {
	status := t.Module.HealthCheck()
	status.Details["conn_count"] = atomic.LoadInt64(&t.connCount)
	status.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	status.Details["bytes_rx"] = atomic.LoadUint64(&t.bytesRx)
	status.Details["bytes_tx"] = atomic.LoadUint64(&t.bytesTx)
	status.Details["listen_addr"] = t.config.ListenAddr
	status.Details["path"] = t.config.Path
	return status
}

// wsConn wraps a WebSocket connection
type wsConn struct {
	*websocket.Conn
	transport *Transport
	id        int64
	closed    int32
	closeChan chan struct{}
}

func (c *wsConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesRx, uint64(n))
	}
	return
}

func (c *wsConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesTx, uint64(n))
	}
	return
}

func (c *wsConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		atomic.AddInt64(&c.transport.activeConns, -1)
		c.transport.connections.Delete(c.id)
		if c.closeChan != nil {
			close(c.closeChan)
		}
		return c.Conn.Close()
	}
	return nil
}

// Factory creates WebSocket transport modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
