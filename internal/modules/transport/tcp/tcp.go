package tcp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "transport.tcp"
	ModuleVersion = "1.0.0"
)

type Config struct {
	ListenAddr   string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	KeepAlive    time.Duration
	MaxConns     int
	BufferSize   int
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:   ":8443",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		KeepAlive:    30 * time.Second,
		MaxConns:     10000,
		BufferSize:   32 * 1024 * 1024,
	}
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 10000
	}
	return nil
}

type Transport struct {
	*base.Module
	config   *Config
	listener net.Listener
	mu       sync.RWMutex

	obfuscator interfaces.Obfuscator

	connections sync.Map

	connCount    int64
	bytesRx      uint64
	bytesTx      uint64
	activeConns  int64
	acceptErrors uint64
}

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

func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if tcpCfg, ok := cfg.(*Config); ok {
		t.config = tcpCfg
	}

	return nil
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", t.config.ListenAddr)
	if err != nil {
		t.SetHealthy(false, fmt.Sprintf("failed to listen: %v", err))
		return fmt.Errorf("failed to listen on TCP: %w", err)
	}

	t.mu.Lock()
	t.listener = listener
	t.mu.Unlock()

	t.SetHealthy(true, fmt.Sprintf("listening on %s", t.config.ListenAddr))
	t.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": t.config.ListenAddr,
	})

	return nil
}

func (t *Transport) Stop() error {
	t.mu.Lock()
	if t.listener != nil {
		t.listener.Close()
		t.listener = nil
	}
	t.mu.Unlock()

	t.connections.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
		}
		t.connections.Delete(key)
		return true
	})

	t.PublishEvent(events.EventTypeModuleStopped, nil)
	return t.Module.Stop()
}

func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportTCP
}

func (t *Transport) Listen(addr string) error {
	return nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   t.config.WriteTimeout,
		KeepAlive: t.config.KeepAlive,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(t.config.KeepAlive)
		if t.config.BufferSize > 0 {
			tcpConn.SetReadBuffer(t.config.BufferSize)
			tcpConn.SetWriteBuffer(t.config.BufferSize)
		}
	}

	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)

	wrapped := &trackedConn{
		Conn:      conn,
		transport: t,
		id:        atomic.LoadInt64(&t.connCount),
	}

	t.connections.Store(wrapped.id, wrapped)

	return wrapped, nil
}

func (t *Transport) Accept() (net.Conn, error) {
	t.mu.RLock()
	listener := t.listener
	t.mu.RUnlock()

	if listener == nil {
		return nil, fmt.Errorf("transport not running")
	}

	conn, err := listener.Accept()
	if err != nil {
		atomic.AddUint64(&t.acceptErrors, 1)
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(t.config.KeepAlive)
		if t.config.BufferSize > 0 {
			tcpConn.SetReadBuffer(t.config.BufferSize)
			tcpConn.SetWriteBuffer(t.config.BufferSize)
		}
	}

	if atomic.LoadInt64(&t.activeConns) >= int64(t.config.MaxConns) {
		conn.Close()
		return nil, fmt.Errorf("max connections reached")
	}

	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)

	wrapped := &trackedConn{
		Conn:      conn,
		transport: t,
		id:        atomic.LoadInt64(&t.connCount),
	}

	t.connections.Store(wrapped.id, wrapped)

	t.UpdateActivity()

	return wrapped, nil
}

func (t *Transport) SetObfuscator(obfuscator interfaces.Obfuscator) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.obfuscator = obfuscator
}

func (t *Transport) Close() error {
	return t.Stop()
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	status := t.Module.HealthCheck()
	status.Details["conn_count"] = atomic.LoadInt64(&t.connCount)
	status.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	status.Details["bytes_rx"] = atomic.LoadUint64(&t.bytesRx)
	status.Details["bytes_tx"] = atomic.LoadUint64(&t.bytesTx)
	status.Details["accept_errors"] = atomic.LoadUint64(&t.acceptErrors)
	status.Details["listen_addr"] = t.config.ListenAddr
	return status
}

func (t *Transport) Stats() TransportStats {
	return TransportStats{
		ConnCount:   atomic.LoadInt64(&t.connCount),
		ActiveConns: atomic.LoadInt64(&t.activeConns),
		BytesRx:     atomic.LoadUint64(&t.bytesRx),
		BytesTx:     atomic.LoadUint64(&t.bytesTx),
	}
}

type TransportStats struct {
	ConnCount   int64
	ActiveConns int64
	BytesRx     uint64
	BytesTx     uint64
}

type trackedConn struct {
	net.Conn
	transport *Transport
	id        int64
	closed    int32
}

func (c *trackedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesRx, uint64(n))
	}
	return
}

func (c *trackedConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesTx, uint64(n))
	}
	return
}

func (c *trackedConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		atomic.AddInt64(&c.transport.activeConns, -1)
		c.transport.connections.Delete(c.id)
		return c.Conn.Close()
	}
	return nil
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
