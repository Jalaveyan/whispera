package torsocks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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

var log = logger.Module("torsocks")

const (
	ModuleName    = "transport.torsocks"
	ModuleVersion = "1.0.0"

	defaultTorAddr = "127.0.0.1:9050"

	socks5Version = 0x05
	socks5NoAuth  = 0x00
	socks5Domain  = 0x03
	socks5Connect = 0x01
)

type Config struct {
	TorAddr string
}

func DefaultConfig() *Config {
	return &Config{
		TorAddr: defaultTorAddr,
	}
}

func (c *Config) Validate() error {
	if c.TorAddr == "" {
		return fmt.Errorf("torsocks: tor address required")
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config

	activeConns int64
	totalConns  uint64
	bytesIn     uint64
	bytesOut    uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
	}, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportTorSOCKS }

func (t *Transport) Listen(_ string) error     { return fmt.Errorf("torsocks: server mode not supported") }
func (t *Transport) Accept() (net.Conn, error) { return nil, fmt.Errorf("torsocks: server mode not supported") }
func (t *Transport) Close() error              { return nil }

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("torsocks: invalid addr %s: %w", addr, err)
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	d := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", t.config.TorAddr)
	if err != nil {
		return nil, fmt.Errorf("torsocks: connect to Tor at %s: %w", t.config.TorAddr, err)
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})

	if err := t.handshake(conn, host, port); err != nil {
		conn.Close()
		return nil, fmt.Errorf("torsocks: SOCKS5 handshake: %w", err)
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	log.Info("torsocks: connected to %s via Tor", addr)

	return &torConn{Conn: conn, t: t}, nil
}

func (t *Transport) handshake(conn net.Conn, host string, port uint16) error {
	if _, err := conn.Write([]byte{socks5Version, 1, socks5NoAuth}); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != socks5Version || resp[1] != socks5NoAuth {
		return fmt.Errorf("SOCKS5 auth negotiation failed: %v", resp)
	}

	req := []byte{
		socks5Version,
		socks5Connect,
		0x00,
		socks5Domain,
		byte(len(host)),
	}
	req = append(req, []byte(host)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed, code=%d", header[1])
	}

	switch header[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 6))
	case 0x03:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 18))
	}

	return nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["tor_addr"] = t.config.TorAddr
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	return s
}

type torConn struct {
	net.Conn
	t *Transport
}

func (c *torConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesIn, uint64(n))
	}
	return n, err
}

func (c *torConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesOut, uint64(n))
	}
	return n, err
}

func (c *torConn) Close() error {
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
