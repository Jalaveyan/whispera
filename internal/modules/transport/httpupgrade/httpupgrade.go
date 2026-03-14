package httpupgrade

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("httpupgrade")

const (
	ModuleName    = "transport.httpupgrade"
	ModuleVersion = "1.0.0"
)

type Config struct {
	Host string
	Path string
}

func DefaultConfig() *Config {
	return &Config{
		Path: "/",
	}
}

func (c *Config) Validate() error {
	return nil
}

type Transport struct {
	*base.Module
	config *Config

	mu       interface{}
	listener net.Listener

	activeConns int64
	totalConns  uint64
	bytesIn     uint64
	bytesOut    uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
	}, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportHTTPUpgrade }

func (t *Transport) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	t.listener = ln
	log.Info("httpupgrade listening on %s", addr)
	return nil
}

func (t *Transport) Accept() (net.Conn, error) {
	if t.listener == nil {
		return nil, fmt.Errorf("not listening")
	}
	conn, err := t.listener.Accept()
	if err != nil {
		return nil, err
	}
	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	wrapped, err := t.serverHandshake(conn)
	if err != nil {
		conn.Close()
		atomic.AddInt64(&t.activeConns, -1)
		return nil, err
	}
	return wrapped, nil
}

func (t *Transport) serverHandshake(conn net.Conn) (net.Conn, error) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("httpupgrade: read request: %w", err)
	}

	if req.Header.Get("Upgrade") != "websocket" && req.Header.Get("Upgrade") != "tcp" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return nil, fmt.Errorf("httpupgrade: missing Upgrade header")
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: tcp\r\n" +
		"Connection: Upgrade\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return nil, err
	}

	log.Info("httpupgrade: server accepted connection from %s", conn.RemoteAddr())
	return &upgradeConn{Conn: conn, t: t}, nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	host := t.config.Host
	if host == "" {
		host = addr
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("httpupgrade dial: %w", err)
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	path := t.config.Path
	if path == "" {
		path = "/"
	}

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n",
		path, host,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("httpupgrade: read response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("httpupgrade: expected 101, got %d", resp.StatusCode)
	}

	conn.SetDeadline(time.Time{})

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	log.Info("httpupgrade: upgraded connection to %s", addr)

	return &upgradeConn{Conn: conn, t: t}, nil
}

func (t *Transport) Close() error {
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	return s
}

type upgradeConn struct {
	net.Conn
	t *Transport
}

func (c *upgradeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesIn, uint64(n))
	}
	return n, err
}

func (c *upgradeConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesOut, uint64(n))
	}
	return n, err
}

func (c *upgradeConn) Close() error {
	atomic.AddInt64(&c.t.activeConns, -1)
	return c.Conn.Close()
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
