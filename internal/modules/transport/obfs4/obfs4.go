package obfs4

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
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

var log = logger.Module("obfs4")

const (
	ModuleName    = "transport.obfs4"
	ModuleVersion = "1.0.0"

	handshakeLen  = 64
	keyLen        = 32
	nonceLen      = 12
	headerLen     = 4
	maxFrameSize  = 65535
)

type Config struct {
	ListenAddr string
	NodeID     string
	PublicKey  string
	PrivateKey string
	IAT        int
}

func DefaultConfig() *Config {
	return &Config{
		IAT: 0,
	}
}

func (c *Config) Validate() error {
	return nil
}

type Transport struct {
	*base.Module
	config   *Config
	mu       sync.RWMutex
	listener net.Listener
	privKey  *ecdh.PrivateKey

	activeConns int64
	totalConns  uint64
	bytesIn     uint64
	bytesOut    uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	var privKey *ecdh.PrivateKey
	// Use provided private key if available (for stable server identity)
	if cfg.PrivateKey != "" {
		privBytes, err := hex.DecodeString(cfg.PrivateKey)
		if err == nil {
			privKey, err = ecdh.X25519().NewPrivateKey(privBytes)
			if err != nil {
				privKey = nil // fall through to generate
			}
		}
	}
	if privKey == nil {
		var err error
		privKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate keypair: %w", err)
		}
	}

	return &Transport{
		Module:  base.NewModule(ModuleName, ModuleVersion, nil),
		config:  cfg,
		privKey: privKey,
	}, nil
}

func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportObfs4
}

func (t *Transport) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("obfs4 listen: %w", err)
	}
	t.mu.Lock()
	t.listener = ln
	t.mu.Unlock()
	log.Info("obfs4 listening on %s", addr)
	return nil
}

func (t *Transport) Accept() (net.Conn, error) {
	t.mu.RLock()
	ln := t.listener
	t.mu.RUnlock()
	if ln == nil {
		return nil, fmt.Errorf("not listening")
	}
	conn, err := ln.Accept()
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

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("obfs4 dial: %w", err)
	}
	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	wrapped, err := t.clientHandshake(conn)
	if err != nil {
		conn.Close()
		atomic.AddInt64(&t.activeConns, -1)
		return nil, err
	}
	return wrapped, nil
}

func (t *Transport) clientHandshake(conn net.Conn) (net.Conn, error) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	ephKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pubBytes := ephKey.PublicKey().Bytes()
	padding := make([]byte, handshakeLen-len(pubBytes))
	rand.Read(padding)

	hello := append(pubBytes, padding...)
	if _, err := conn.Write(hello); err != nil {
		return nil, err
	}

	serverHello := make([]byte, handshakeLen)
	if _, err := io.ReadFull(conn, serverHello); err != nil {
		return nil, err
	}

	serverPub, err := ecdh.X25519().NewPublicKey(serverHello[:32])
	if err != nil {
		return nil, err
	}

	shared, err := ephKey.ECDH(serverPub)
	if err != nil {
		return nil, err
	}

	key := sha256.Sum256(shared)
	return newObfs4Conn(conn, key[:], true), nil
}

func (t *Transport) serverHandshake(conn net.Conn) (net.Conn, error) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	clientHello := make([]byte, handshakeLen)
	if _, err := io.ReadFull(conn, clientHello); err != nil {
		return nil, err
	}

	clientPub, err := ecdh.X25519().NewPublicKey(clientHello[:32])
	if err != nil {
		return nil, err
	}

	shared, err := t.privKey.ECDH(clientPub)
	if err != nil {
		return nil, err
	}

	pubBytes := t.privKey.PublicKey().Bytes()
	padding := make([]byte, handshakeLen-len(pubBytes))
	rand.Read(padding)
	serverHello := append(pubBytes, padding...)

	if _, err := conn.Write(serverHello); err != nil {
		return nil, err
	}

	key := sha256.Sum256(shared)
	return newObfs4Conn(conn, key[:], false), nil
}

func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	s.Details["total_conns"] = atomic.LoadUint64(&t.totalConns)
	return s
}

// obfs4Conn wraps net.Conn with AES-GCM framing
type obfs4Conn struct {
	net.Conn
	enc    cipher.AEAD
	dec    cipher.AEAD
	encSeq uint64
	decSeq uint64
	mu     sync.Mutex
	rbuf   []byte
}

func newObfs4Conn(conn net.Conn, key []byte, isClient bool) *obfs4Conn {
	encKey := sha256.Sum256(append(key, 0x01))
	decKey := sha256.Sum256(append(key, 0x02))
	if !isClient {
		encKey, decKey = decKey, encKey
	}

	encBlock, _ := aes.NewCipher(encKey[:])
	decBlock, _ := aes.NewCipher(decKey[:])
	enc, _ := cipher.NewGCM(encBlock)
	dec, _ := cipher.NewGCM(decBlock)

	return &obfs4Conn{Conn: conn, enc: enc, dec: dec}
}

func (c *obfs4Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nonce := make([]byte, nonceLen)
	binary.BigEndian.PutUint64(nonce[4:], c.encSeq)
	c.encSeq++

	encrypted := c.enc.Seal(nil, nonce, b, nil)

	frame := make([]byte, headerLen+len(encrypted))
	binary.BigEndian.PutUint32(frame, uint32(len(encrypted)))
	copy(frame[headerLen:], encrypted)

	_, err := c.Conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *obfs4Conn) Read(b []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}

	header := make([]byte, headerLen)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}
	frameLen := int(binary.BigEndian.Uint32(header))
	if frameLen > maxFrameSize+c.dec.Overhead() {
		return 0, fmt.Errorf("frame too large: %d", frameLen)
	}

	encrypted := make([]byte, frameLen)
	if _, err := io.ReadFull(c.Conn, encrypted); err != nil {
		return 0, err
	}

	nonce := make([]byte, nonceLen)
	binary.BigEndian.PutUint64(nonce[4:], c.decSeq)
	c.decSeq++

	plain, err := c.dec.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return 0, fmt.Errorf("decrypt failed: %w", err)
	}

	n := copy(b, plain)
	if n < len(plain) {
		c.rbuf = plain[n:]
	}
	return n, nil
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
