package shadowtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

	utls "github.com/refraction-networking/utls"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("shadowtls")

const (
	ModuleName    = "transport.shadowtls"
	ModuleVersion = "1.0.0"

	hmacLen = 8
)

type Config struct {
	Password string


	ShadowServer string

	SNI string

	Version int


	ServerMode bool

	TLSCert string
	TLSKey  string
}

func DefaultConfig() *Config {
	return &Config{
		SNI:     "www.apple.com",
		Version: 3,
	}
}

func (c *Config) Validate() error {
	if c.Password == "" {
		return fmt.Errorf("shadowtls: password required")
	}
	if !c.ServerMode && c.ShadowServer == "" {
		return fmt.Errorf("shadowtls: server address required for client mode")
	}
	return nil
}

type Transport struct {
	*base.Module
	config   *Config
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
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
	}, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportShadowTLS }


func (t *Transport) Listen(addr string) error {
	tlsCfg, err := t.buildServerTLSConfig()
	if err != nil {
		return fmt.Errorf("shadowtls: TLS config: %w", err)
	}

	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("shadowtls: listen %s: %w", addr, err)
	}
	t.listener = ln
	log.Info("shadowtls: server listening on %s (SNI=%s)", addr, t.config.SNI)
	return nil
}

func (t *Transport) Accept() (net.Conn, error) {
	if t.listener == nil {
		return nil, fmt.Errorf("shadowtls: not listening")
	}
	conn, err := t.listener.Accept()
	if err != nil {
		return nil, err
	}
	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	return &serverConn{Conn: conn, transport: t}, nil
}

func (t *Transport) Close() error {
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

func (t *Transport) buildServerTLSConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if t.config.TLSCert != "" && t.config.TLSKey != "" {
		cert, err = tls.LoadX509KeyPair(t.config.TLSCert, t.config.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		log.Info("shadowtls: using certificate from %s", t.config.TLSCert)
	} else {
		sni := t.config.SNI
		if sni == "" {
			sni = "www.apple.com"
		}
		cert, err = generateSelfSignedCert(sni)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		log.Info("shadowtls: using auto-generated self-signed cert for %s", sni)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
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


func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	server := t.config.ShadowServer
	if server == "" {
		server = addr
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("shadowtls dial: %w", err)
	}

	sni := t.config.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(server)
		sni = host
	}

	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
	}, utls.HelloChrome_Auto)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("shadowtls tls handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	if !t.verifyServerRandom(state.TLSUnique) {
		log.Warn("shadowtls: server HMAC verification failed, possible MITM")
	}

	log.Info("shadowtls: connected to %s via %s", addr, server)

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	return newShadowTLSConn(tlsConn, t), nil
}

// DialConn performs a ShadowTLS handshake over an already-open conn.
// Implements interfaces.DialableTransport — allows stacking ShadowTLS
// on top of Meek, WebSocket, or any other inner transport.
func (t *Transport) DialConn(ctx context.Context, conn net.Conn, _ string) (net.Conn, error) {
	sni := t.config.SNI
	if sni == "" {
		sni = "www.apple.com"
	}

	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
	}, utls.HelloChrome_Auto)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("shadowtls DialConn handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	if !t.verifyServerRandom(state.TLSUnique) {
		log.Warn("shadowtls: server HMAC verification failed on stacked conn")
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	return newShadowTLSConn(tlsConn, t), nil
}

func (t *Transport) verifyServerRandom(data []byte) bool {
	if len(data) < hmacLen {
		return false
	}
	mac := hmac.New(sha256.New, []byte(t.config.Password))
	mac.Write(data[:len(data)-hmacLen])
	expected := mac.Sum(nil)[:hmacLen]
	return hmac.Equal(expected, data[len(data)-hmacLen:])
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	s.Details["sni"] = t.config.SNI
	s.Details["version"] = t.config.Version
	s.Details["server_mode"] = t.config.ServerMode
	return s
}


type shadowTLSConn struct {
	*utls.UConn
	transport *Transport
}

func newShadowTLSConn(inner *utls.UConn, tr *Transport) *shadowTLSConn {
	return &shadowTLSConn{UConn: inner, transport: tr}
}

func (c *shadowTLSConn) Close() error {
	atomic.AddInt64(&c.transport.activeConns, -1)
	return c.UConn.Close()
}

func (c *shadowTLSConn) Read(b []byte) (int, error) {
	n, err := c.UConn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesIn, uint64(n))
	}
	return n, err
}

func (c *shadowTLSConn) Write(b []byte) (int, error) {
	n, err := c.UConn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesOut, uint64(n))
	}
	return n, err
}

var _ io.ReadWriteCloser = (*shadowTLSConn)(nil)

type serverConn struct {
	net.Conn
	transport *Transport
}

func (c *serverConn) Close() error {
	atomic.AddInt64(&c.transport.activeConns, -1)
	return c.Conn.Close()
}

func (c *serverConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesIn, uint64(n))
	}
	return n, err
}

func (c *serverConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesOut, uint64(n))
	}
	return n, err
}


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
