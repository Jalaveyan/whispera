package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"

	"github.com/quic-go/quic-go"
)

const (
	ModuleName    = "transport.quic"
	ModuleVersion = "1.0.0"
)

type Config struct {
	ListenAddr          string
	MaxStreams          int64
	MaxIdleTimeout      time.Duration
	KeepAlivePeriod     time.Duration
	HandshakeTimeout    time.Duration
	MaxConns            int
	EnableEarlyData     bool
	InitialStreamWindow uint64
	ALPN                string
	ServerName          string
	CertDomains         []string
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:          ":8443",
		MaxStreams:          512,
		MaxIdleTimeout:      90 * time.Second,
		KeepAlivePeriod:     30 * time.Second,
		HandshakeTimeout:    10 * time.Second,
		MaxConns:            10000,
		EnableEarlyData:     true,
		InitialStreamWindow: 32 * 1024 * 1024,
		ALPN:                "h3",
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
	config    *Config
	listener  *quic.Listener
	tlsConfig *tls.Config
	mu        sync.RWMutex

	connections sync.Map

	connCount   int64
	bytesRx     uint64
	bytesTx     uint64
	activeConns int64
	streamCount int64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	} else {
		defaults := DefaultConfig()
		if cfg.MaxIdleTimeout == 0 {
			cfg.MaxIdleTimeout = defaults.MaxIdleTimeout
		}
		if cfg.KeepAlivePeriod == 0 {
			cfg.KeepAlivePeriod = defaults.KeepAlivePeriod
		}
		if cfg.InitialStreamWindow == 0 {
			cfg.InitialStreamWindow = defaults.InitialStreamWindow
		}
		if cfg.HandshakeTimeout == 0 {
			cfg.HandshakeTimeout = defaults.HandshakeTimeout
		}
		if cfg.MaxStreams == 0 {
			cfg.MaxStreams = defaults.MaxStreams
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	tlsConfig, err := generateTLSConfig(cfg.ALPN, cfg.CertDomains)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS config: %w", err)
	}

	t := &Transport{
		Module:    base.NewModule(ModuleName, ModuleVersion, nil),
		config:    cfg,
		tlsConfig: tlsConfig,
	}

	return t, nil
}

func generateTLSConfig(alpn string, domains []string) (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialN, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	notBefore := time.Now().Add(-90 * 24 * time.Hour)
	notAfter := notBefore.Add(2 * 365 * 24 * time.Hour)

	var dnsNames []string
	cn := "localhost"
	if len(domains) > 0 {
		cn = domains[0]
		dnsNames = domains
	}

	template := x509.Certificate{
		SerialNumber: serialN,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	if alpn == "" {
		alpn = "h3"
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{alpn},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if quicCfg, ok := cfg.(*Config); ok {
		t.config = quicCfg
	}

	return nil
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 t.config.MaxIdleTimeout,
		KeepAlivePeriod:                t.config.KeepAlivePeriod,
		MaxIncomingStreams:             t.config.MaxStreams,
		MaxIncomingUniStreams:          t.config.MaxStreams,
		HandshakeIdleTimeout:           t.config.HandshakeTimeout,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     t.config.InitialStreamWindow,
		MaxStreamReceiveWindow:         t.config.InitialStreamWindow * 10,
		InitialConnectionReceiveWindow: t.config.InitialStreamWindow * 10,
		MaxConnectionReceiveWindow:     t.config.InitialStreamWindow * 50,
	}

	listener, err := quic.ListenAddr(t.config.ListenAddr, t.tlsConfig, quicConfig)
	if err != nil {
		t.SetHealthy(false, fmt.Sprintf("failed to listen: %v", err))
		return fmt.Errorf("failed to listen on QUIC: %w", err)
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
		if conn, ok := value.(interface {
			CloseWithError(quic.ApplicationErrorCode, string) error
		}); ok {
			conn.CloseWithError(0, "transport stopped")
		}
		t.connections.Delete(key)
		return true
	})

	t.PublishEvent(events.EventTypeModuleStopped, nil)
	return t.Module.Stop()
}

func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportQUIC
}

func (t *Transport) Listen(addr string) error {
	return nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	alpn := t.config.ALPN
	if alpn == "" {
		alpn = "h3"
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
		ServerName:         t.config.ServerName,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 t.config.MaxIdleTimeout,
		KeepAlivePeriod:                t.config.KeepAlivePeriod,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     t.config.InitialStreamWindow,
		MaxStreamReceiveWindow:         t.config.InitialStreamWindow * 10,
		InitialConnectionReceiveWindow: t.config.InitialStreamWindow * 10,
		MaxConnectionReceiveWindow:     t.config.InitialStreamWindow * 50,
		Allow0RTT:                      true,
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConfig)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "failed to open stream")
		return nil, err
	}

	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)
	atomic.AddInt64(&t.streamCount, 1)

	id := atomic.LoadInt64(&t.connCount)
	t.connections.Store(id, conn)

	wrapped := &quicStreamConn{
		stream:    stream,
		conn:      conn,
		transport: t,
		id:        id,
	}

	return wrapped, nil
}

func (t *Transport) Accept() (net.Conn, error) {
	t.mu.RLock()
	listener := t.listener
	t.mu.RUnlock()

	if listener == nil {
		return nil, fmt.Errorf("transport not running")
	}

	if atomic.LoadInt64(&t.activeConns) >= int64(t.config.MaxConns) {
		return nil, fmt.Errorf("max connections reached")
	}

	ctx := context.Background()
	conn, err := listener.Accept(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		conn.CloseWithError(0, "failed to accept stream")
		return nil, err
	}

	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)
	atomic.AddInt64(&t.streamCount, 1)

	id := atomic.LoadInt64(&t.connCount)
	t.connections.Store(id, conn)

	t.UpdateActivity()

	wrapped := &quicStreamConn{
		stream:    stream,
		conn:      conn,
		transport: t,
		id:        id,
	}

	return wrapped, nil
}

func (t *Transport) Close() error {
	return t.Stop()
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	status := t.Module.HealthCheck()
	status.Details["conn_count"] = atomic.LoadInt64(&t.connCount)
	status.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	status.Details["stream_count"] = atomic.LoadInt64(&t.streamCount)
	status.Details["bytes_rx"] = atomic.LoadUint64(&t.bytesRx)
	status.Details["bytes_tx"] = atomic.LoadUint64(&t.bytesTx)
	status.Details["listen_addr"] = t.config.ListenAddr
	return status
}

type quicConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	CloseWithError(quic.ApplicationErrorCode, string) error
}

type quicStreamConn struct {
	stream    *quic.Stream
	conn      quicConn
	transport *Transport
	id        int64
	closed    int32
}

func (c *quicStreamConn) Read(b []byte) (n int, err error) {
	n, err = c.stream.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesRx, uint64(n))
	}
	return
}

func (c *quicStreamConn) Write(b []byte) (n int, err error) {
	n, err = c.stream.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesTx, uint64(n))
	}
	return
}

func (c *quicStreamConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		atomic.AddInt64(&c.transport.activeConns, -1)
		c.transport.connections.Delete(c.id)
		c.stream.Close()
		return nil
	}
	return nil
}

func (c *quicStreamConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *quicStreamConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *quicStreamConn) SetDeadline(t time.Time) error {
	c.stream.SetDeadline(t)
	return nil
}

func (c *quicStreamConn) SetReadDeadline(t time.Time) error {
	c.stream.SetReadDeadline(t)
	return nil
}

func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	c.stream.SetWriteDeadline(t)
	return nil
}
