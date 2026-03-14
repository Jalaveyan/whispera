package tuic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("tuic")

const (
	ModuleName    = "transport.tuic"
	ModuleVersion = "1.0.0"

	tuicALPN = "tuic"
)

type Config struct {
	UUID              string
	Password          string
	ServerAddr        string
	SNI               string
	CongestionControl string

	ServerMode bool
	TLSCert    string
	TLSKey     string
}

func DefaultConfig() *Config {
	return &Config{
		CongestionControl: "bbr",
		SNI:               "",
	}
}

func (c *Config) Validate() error {
	if !c.ServerMode {
		if c.ServerAddr == "" {
			return fmt.Errorf("tuic: server address required")
		}
		if c.UUID == "" {
			return fmt.Errorf("tuic: UUID required")
		}
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config

	conn *quic.Conn

	listener *quic.Listener
	acceptCh chan net.Conn

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

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportTUIC }


func (t *Transport) Listen(addr string) error {
	tlsCfg, err := t.buildServerTLSConfig()
	if err != nil {
		return fmt.Errorf("tuic: TLS config: %w", err)
	}

	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{
		MaxIdleTimeout:     30 * time.Second,
		KeepAlivePeriod:    10 * time.Second,
		MaxIncomingStreams: 512,
	})
	if err != nil {
		return fmt.Errorf("tuic: listen %s: %w", addr, err)
	}

	t.listener = ln
	t.acceptCh = make(chan net.Conn, 64)
	go t.acceptLoop()
	log.Info("tuic: server listening on %s", addr)
	return nil
}

func (t *Transport) acceptLoop() {
	ctx := context.Background()
	for {
		conn, err := t.listener.Accept(ctx)
		if err != nil {
			close(t.acceptCh)
			return
		}
		go t.handleQUICConn(ctx, conn)
	}
}

func (t *Transport) handleQUICConn(ctx context.Context, conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go t.handleQUICStream(stream)
	}
}

func (t *Transport) handleQUICStream(stream *quic.Stream) {
	hdr := make([]byte, 17)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		stream.Close()
		return
	}
	addrLen := int(hdr[16])
	tail := make([]byte, addrLen+2)
	if _, err := io.ReadFull(stream, tail); err != nil {
		stream.Close()
		return
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	t.acceptCh <- &tuicConn{stream: stream, t: t}
}

func (t *Transport) Accept() (net.Conn, error) {
	conn, ok := <-t.acceptCh
	if !ok {
		return nil, io.EOF
	}
	return conn, nil
}

func (t *Transport) buildServerTLSConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if t.config.TLSCert != "" && t.config.TLSKey != "" {
		cert, err = tls.LoadX509KeyPair(t.config.TLSCert, t.config.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
	} else {
		sni := t.config.SNI
		if sni == "" {
			sni = "www.apple.com"
		}
		cert, err = generateSelfSignedCert(sni)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		log.Info("tuic: using auto-generated self-signed cert for %s", sni)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{tuicALPN},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func generateSelfSignedCert(hostname string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}


func (t *Transport) getConn(ctx context.Context) (*quic.Conn, error) {
	if t.conn != nil {
		return t.conn, nil
	}

	sni := t.config.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(t.config.ServerAddr)
		sni = host
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{tuicALPN},
		InsecureSkipVerify: false,
	}

	conn, err := quic.DialAddr(ctx, t.config.ServerAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("tuic: quic dial: %w", err)
	}

	t.conn = conn
	log.Info("tuic: QUIC connection established to %s", t.config.ServerAddr)
	return conn, nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	qconn, err := t.getConn(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		t.conn = nil
		return nil, fmt.Errorf("tuic: open stream: %w", err)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		stream.Close()
		return nil, err
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	req := make([]byte, 0, 32)
	req = append(req, []byte(t.config.UUID)[:16]...)
	req = append(req, byte(len(host)))
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))

	if _, err := stream.Write(req); err != nil {
		stream.Close()
		return nil, err
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	log.Info("tuic: stream opened to %s", addr)

	return &tuicConn{stream: stream, t: t}, nil
}

func (t *Transport) Close() error {
	if t.conn != nil {
		t.conn.CloseWithError(0, "close")
	}
	if t.listener != nil {
		t.listener.Close()
	}
	return nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	s.Details["congestion"] = t.config.CongestionControl
	s.Details["server_mode"] = t.config.ServerMode
	return s
}


type tuicConn struct {
	stream *quic.Stream
	t      *Transport
}

func (c *tuicConn) Read(b []byte) (int, error) {
	n, err := c.stream.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesIn, uint64(n))
	}
	return n, err
}

func (c *tuicConn) Write(b []byte) (int, error) {
	n, err := c.stream.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesOut, uint64(n))
	}
	return n, err
}

func (c *tuicConn) Close() error {
	atomic.AddInt64(&c.t.activeConns, -1)
	return c.stream.Close()
}

func (c *tuicConn) LocalAddr() net.Addr               { return &net.UDPAddr{} }
func (c *tuicConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *tuicConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *tuicConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *tuicConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

var _ io.ReadWriteCloser = (*tuicConn)(nil)

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: config,
	}
	return t, nil
}
