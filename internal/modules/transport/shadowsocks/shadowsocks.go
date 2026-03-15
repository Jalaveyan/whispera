package shadowsocks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("shadowsocks")

const (
	ModuleName    = "transport.shadowsocks"
	ModuleVersion = "1.0.0"

	payloadSizeMask = 0x3FFF
	maxPayloadSize  = payloadSizeMask
)

type Method string

const (
	MethodAES256GCM       Method = "aes-256-gcm"
	MethodChaCha20Poly1305 Method = "chacha20-poly1305"
)

type Config struct {
	Password string
	Method   Method
	Server   string
}

func DefaultConfig() *Config {
	return &Config{
		Method: MethodAES256GCM,
	}
}

func (c *Config) Validate() error {
	if c.Password == "" {
		return fmt.Errorf("shadowsocks: password required")
	}
	if c.Server == "" {
		return fmt.Errorf("shadowsocks: server required")
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config

	listener    net.Listener
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

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportShadowsocks }

func (t *Transport) Listen(addr string) error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	t.listener = ln
	log.Info("shadowsocks listening on %s (method=%s)", addr, t.config.Method)
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

	ssConn, err := t.newServerConn(conn)
	if err != nil {
		conn.Close()
		atomic.AddInt64(&t.activeConns, -1)
		return nil, err
	}
	return ssConn, nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	server := t.config.Server
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks dial: %w", err)
	}

	ssConn, err := t.newClientConn(conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	log.Info("shadowsocks: connected to %s via %s", addr, server)
	return ssConn, nil
}

// DialConn выполняет Shadowsocks handshake поверх уже установленного conn.
// Позволяет стекировать SS поверх другого транспорта (Meek, Obfs4 и т.д.).
// Реализует interfaces.DialableTransport.
func (t *Transport) DialConn(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	ssConn, err := t.newClientConn(conn, addr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("shadowsocks DialConn: %w", err)
	}
	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	log.Info("shadowsocks: handshake on existing conn -> %s", addr)
	return ssConn, nil
}

func (t *Transport) deriveKey() []byte {
	h := sha256.Sum256([]byte(t.config.Password))
	return h[:]
}

func (t *Transport) newAEAD(subkey []byte) (cipher.AEAD, error) {
	switch t.config.Method {
	case MethodAES256GCM:
		block, err := aes.NewCipher(subkey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case MethodChaCha20Poly1305:
		return chacha20poly1305.New(subkey)
	default:
		block, err := aes.NewCipher(subkey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
}

func deriveSubkey(psk, salt []byte, keyLen int) []byte {
	r := hkdf.New(sha256.New, psk, salt, []byte("ss-subkey"))
	key := make([]byte, keyLen)
	_, _ = io.ReadFull(r, key)
	return key
}

func (t *Transport) newClientConn(conn net.Conn, target string) (*ssConn, error) {
	psk := t.deriveKey()
	saltLen := 32

	salt := make([]byte, saltLen)
	rand.Read(salt)

	subkey := deriveSubkey(psk, salt, len(psk))
	aead, err := t.newAEAD(subkey)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(salt); err != nil {
		return nil, err
	}

	host, portStr, _ := net.SplitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	addrBuf := make([]byte, 0, 32)
	addrBuf = append(addrBuf, 0x03)
	addrBuf = append(addrBuf, byte(len(host)))
	addrBuf = append(addrBuf, []byte(host)...)
	addrBuf = append(addrBuf, byte(port>>8), byte(port))

	c := &ssConn{
		Conn:      conn,
		t:         t,
		encAEAD:   aead,
		encNonce:  make([]byte, aead.NonceSize()),
		psk:       psk,
		saltLen:   saltLen,
		addrBytes: addrBuf,
		isClient:  true,
	}

	if err := c.writeEncrypted(addrBuf); err != nil {
		return nil, err
	}

	return c, nil
}

func (t *Transport) newServerConn(conn net.Conn) (*ssConn, error) {
	psk := t.deriveKey()
	saltLen := 32

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, err
	}

	subkey := deriveSubkey(psk, salt, len(psk))
	aead, err := t.newAEAD(subkey)
	if err != nil {
		return nil, err
	}

	return &ssConn{
		Conn:     conn,
		t:        t,
		decAEAD:  aead,
		decNonce: make([]byte, aead.NonceSize()),
		psk:      psk,
		saltLen:  saltLen,
		isClient: false,
	}, nil
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
	s.Details["method"] = string(t.config.Method)
	return s
}

type ssConn struct {
	net.Conn
	t *Transport

	encMu    sync.Mutex
	encAEAD  cipher.AEAD
	encNonce []byte

	decMu    sync.Mutex
	decAEAD  cipher.AEAD
	decNonce []byte

	psk       []byte
	saltLen   int
	addrBytes []byte
	isClient  bool

	rbuf []byte
}

func incrementNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

func (c *ssConn) writeEncrypted(data []byte) error {
	c.encMu.Lock()
	defer c.encMu.Unlock()

	for len(data) > 0 {
		chunk := data
		if len(chunk) > maxPayloadSize {
			chunk = chunk[:maxPayloadSize]
		}
		data = data[len(chunk):]

		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(chunk)))
		encLen := c.encAEAD.Seal(nil, c.encNonce, lenBuf, nil)
		incrementNonce(c.encNonce)

		encData := c.encAEAD.Seal(nil, c.encNonce, chunk, nil)
		incrementNonce(c.encNonce)

		if _, err := c.Conn.Write(append(encLen, encData...)); err != nil {
			return err
		}
	}
	return nil
}

func (c *ssConn) Write(b []byte) (int, error) {
	if err := c.writeEncrypted(b); err != nil {
		return 0, err
	}
	atomic.AddUint64(&c.t.bytesOut, uint64(len(b)))
	return len(b), nil
}

func (c *ssConn) readDecrypted() ([]byte, error) {
	c.decMu.Lock()
	defer c.decMu.Unlock()

	overhead := c.decAEAD.Overhead()

	encLen := make([]byte, 2+overhead)
	if _, err := io.ReadFull(c.Conn, encLen); err != nil {
		return nil, err
	}
	lenBuf, err := c.decAEAD.Open(nil, c.decNonce, encLen, nil)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: decrypt length: %w", err)
	}
	incrementNonce(c.decNonce)

	payloadLen := int(binary.BigEndian.Uint16(lenBuf)) & payloadSizeMask

	encPayload := make([]byte, payloadLen+overhead)
	if _, err := io.ReadFull(c.Conn, encPayload); err != nil {
		return nil, err
	}
	payload, err := c.decAEAD.Open(nil, c.decNonce, encPayload, nil)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: decrypt payload: %w", err)
	}
	incrementNonce(c.decNonce)

	return payload, nil
}

func (c *ssConn) initDecryptor() error {
	if c.decAEAD != nil {
		return nil
	}
	salt := make([]byte, c.saltLen)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	subkey := deriveSubkey(c.psk, salt, len(c.psk))
	aead, err := c.t.newAEAD(subkey)
	if err != nil {
		return err
	}
	c.decAEAD = aead
	c.decNonce = make([]byte, aead.NonceSize())
	return nil
}

func (c *ssConn) Read(b []byte) (int, error) {
	if c.decAEAD == nil {
		if err := c.initDecryptor(); err != nil {
			return 0, err
		}
	}

	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}

	data, err := c.readDecrypted()
	if err != nil {
		return 0, err
	}
	atomic.AddUint64(&c.t.bytesIn, uint64(len(data)))

	n := copy(b, data)
	if n < len(data) {
		c.rbuf = data[n:]
	}
	return n, nil
}

func (c *ssConn) Close() error {
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
