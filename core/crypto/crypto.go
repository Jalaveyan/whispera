package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"whispera/common/runtime/base"
	"whispera/common/runtime/events"
	"whispera/common/runtime/interfaces"
	"whispera/common/runtime/registry"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "crypto.provider"
	ModuleVersion = "1.0.0"

	KeySize   = 32
	NonceSize = 12
	SaltSize  = 32
	InfoSend  = "whispera-send"
	InfoRecv  = "whispera-recv"
)

type CipherType string

const (
	CipherChaCha20Poly1305 CipherType = "chacha20-poly1305"
	CipherAESGCM           CipherType = "aes-256-gcm"
)

type Config struct {
	DefaultCipher CipherType
	EnableKeyPool bool
	KeyPoolSize   int
}

func DefaultConfig() *Config {
	return &Config{
		DefaultCipher: CipherChaCha20Poly1305,
		EnableKeyPool: true,
		KeyPoolSize:   100,
	}
}

func (c *Config) Validate() error {
	switch c.DefaultCipher {
	case CipherChaCha20Poly1305, CipherAESGCM:
	default:
		c.DefaultCipher = CipherChaCha20Poly1305
	}
	if c.KeyPoolSize <= 0 {
		c.KeyPoolSize = 100
	}
	return nil
}

type Provider struct {
	*base.Module
	config *Config

	keyPool     chan []byte
	keyPoolOnce sync.Once

	mu              sync.RWMutex
	keysGenerated   uint64
	encryptOps      atomic.Uint64
	decryptOps      atomic.Uint64
	decryptFailures atomic.Uint64
}

func New(cfg *Config) (*Provider, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	p := &Provider{
		Module:  base.NewModule(ModuleName, ModuleVersion, nil),
		config:  cfg,
		keyPool: make(chan []byte, cfg.KeyPoolSize),
	}

	return p, nil
}

func (p *Provider) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := p.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if cryptoCfg, ok := cfg.(*Config); ok {
		p.config = cryptoCfg
	}

	return nil
}

func (p *Provider) Start() error {
	if err := p.Module.Start(); err != nil {
		return err
	}

	if p.config.EnableKeyPool {
		p.keyPoolOnce.Do(func() {
			go p.keyPoolGenerator()
		})
	}

	p.SetHealthy(true, "crypto provider running")
	p.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"cipher": string(p.config.DefaultCipher),
	})

	return nil
}

func (p *Provider) Stop() error {
	p.PublishEvent(events.EventTypeModuleStopped, nil)
	return p.Module.Stop()
}

func (p *Provider) keyPoolGenerator() {
	ctx := p.Context()
	for p.IsRunning() {
		key := make([]byte, KeySize)
		if _, err := rand.Read(key); err != nil {
			continue
		}

		select {
		case p.keyPool <- key:
			p.mu.Lock()
			p.keysGenerated++
			p.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

func (p *Provider) NewAEAD(key []byte) (interfaces.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", KeySize, len(key))
	}

	var aead cipher.AEAD
	var err error

	switch p.config.DefaultCipher {
	case CipherChaCha20Poly1305:
		aead, err = chacha20poly1305.New(key)
	case CipherAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %w", err)
		}
	default:
		aead, err = chacha20poly1305.New(key)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	return &aeadWrapper{
		aead:     aead,
		provider: p,
		nonceBuf: make([]byte, aead.NonceSize()),
	}, nil
}

func (p *Provider) DeriveKeys(seed []byte, isServer bool) (sendKey, recvKey []byte, err error) {
	if len(seed) < SaltSize {
		return nil, nil, fmt.Errorf("seed too short: expected at least %d bytes", SaltSize)
	}

	hash := sha256.New

	sendReader := hkdf.New(hash, seed, nil, []byte(InfoSend))
	sendKey = make([]byte, KeySize)
	if _, err := sendReader.Read(sendKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive send key: %w", err)
	}

	recvReader := hkdf.New(hash, seed, nil, []byte(InfoRecv))
	recvKey = make([]byte, KeySize)
	if _, err := recvReader.Read(recvKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive recv key: %w", err)
	}

	if isServer {
		sendKey, recvKey = recvKey, sendKey
	}

	return sendKey, recvKey, nil
}

func (p *Provider) GenerateSessionID() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("failed to generate session ID: %w", err)
	}

	id := binary.BigEndian.Uint32(buf[:])
	if id == 0 {
		id = 1
	}

	return id, nil
}

func (p *Provider) GenerateKey() ([]byte, error) {
	if p.config.EnableKeyPool {
		select {
		case key := <-p.keyPool:
			return key, nil
		default:
		}
	}

	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	p.mu.Lock()
	p.keysGenerated++
	p.mu.Unlock()

	return key, nil
}

func (p *Provider) GenerateSeed() ([]byte, error) {
	seed := make([]byte, SaltSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}
	return seed, nil
}

func (p *Provider) DeriveKey(input, output []byte, length int) {
	hash := sha256.New
	reader := hkdf.New(hash, input, nil, []byte("whispera-derive"))
	reader.Read(output[:length])
}

func (p *Provider) HealthCheck() interfaces.HealthStatus {
	status := p.Module.HealthCheck()

	p.mu.RLock()
	status.Details["keys_generated"] = p.keysGenerated
	status.Details["key_pool_size"] = len(p.keyPool)
	p.mu.RUnlock()
	status.Details["encrypt_ops"] = p.encryptOps.Load()
	status.Details["decrypt_ops"] = p.decryptOps.Load()
	status.Details["decrypt_failures"] = p.decryptFailures.Load()

	status.Details["cipher"] = string(p.config.DefaultCipher)

	return status
}

type aeadWrapper struct {
	aead     cipher.AEAD
	provider *Provider
	nonceBuf []byte
}

func (a *aeadWrapper) Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error) {
	for i := range a.nonceBuf {
		a.nonceBuf[i] = 0
	}
	binary.BigEndian.PutUint32(a.nonceBuf[len(a.nonceBuf)-4:], seq)

	// Pre-size so Seal appends without allocating.
	dst := make([]byte, 0, len(plaintext)+a.aead.Overhead())
	ciphertext := a.aead.Seal(dst, a.nonceBuf, plaintext, aad)

	a.provider.encryptOps.Add(1)
	return ciphertext, nil
}

func (a *aeadWrapper) Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error) {
	for i := range a.nonceBuf {
		a.nonceBuf[i] = 0
	}
	binary.BigEndian.PutUint32(a.nonceBuf[len(a.nonceBuf)-4:], seq)

	// Pre-size so Open appends without allocating.
	dst := make([]byte, 0, len(ciphertext))
	plaintext, err := a.aead.Open(dst, a.nonceBuf, ciphertext, aad)
	if err != nil {
		a.provider.decryptFailures.Add(1)
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	a.provider.decryptOps.Add(1)
	return plaintext, nil
}

func (a *aeadWrapper) NonceSize() int {
	return a.aead.NonceSize()
}
func (a *aeadWrapper) Overhead() int {
	return a.aead.Overhead()
}

type DirectionalKeys struct {
	SendKey []byte
	RecvKey []byte
}

type AEADState struct {
	SendAEAD interfaces.AEAD
	RecvAEAD interfaces.AEAD
}

func (p *Provider) NewAEADState(sendKey, recvKey []byte) (*AEADState, error) {
	sendAEAD, err := p.NewAEAD(sendKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create send AEAD: %w", err)
	}

	recvAEAD, err := p.NewAEAD(recvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create recv AEAD: %w", err)
	}

	return &AEADState{
		SendAEAD: sendAEAD,
		RecvAEAD: recvAEAD,
	}, nil
}

func (s *AEADState) Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error) {
	return s.SendAEAD.Encrypt(seq, aad, plaintext)
}

func (s *AEADState) Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error) {
	return s.RecvAEAD.Decrypt(seq, aad, ciphertext)
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
