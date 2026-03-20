package handshake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	ModuleName    = "handshake.handler"
	ModuleVersion = "1.0.0"

	HandshakeInitSize = 48
	HandshakeRespSize = 48
	HandshakeMinSize  = 32
	HandshakeMaxSize  = 96

	MagicByte = 0x57
)

var handshakeBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1024)
	},
}

type HandshakeType byte

const (
	HandshakeTypeInit     HandshakeType = 0x01
	HandshakeTypeResponse HandshakeType = 0x02
	HandshakeTypeRekey    HandshakeType = 0x03
)

type Config struct {
	RateLimit        float64
	RateBurst        int
	Timeout          time.Duration
	MaxPending       int
	EnableAntiReplay bool
}

func DefaultConfig() *Config {
	return &Config{
		RateLimit:        100,
		RateBurst:        50,
		Timeout:          2 * time.Second,
		MaxPending:       1000,
		EnableAntiReplay: true,
	}
}

func (c *Config) Validate() error {
	if c.RateLimit <= 0 {
		c.RateLimit = 100
	}
	if c.RateBurst <= 0 {
		c.RateBurst = 50
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxPending <= 0 {
		c.MaxPending = 1000
	}
	return nil
}

type PendingHandshake struct {
	Addr      net.Addr
	Init      []byte
	Timestamp time.Time
	Nonce     []byte
}

type Handler struct {
	*base.Module
	config *Config
	crypto         interfaces.CryptoProvider
	sessionManager interfaces.SessionManager
	rateLimiter *base.RateLimiter

	mu      sync.RWMutex
	pending map[string]*PendingHandshake

	replayMu    sync.RWMutex
	replayCache map[string]time.Time

	staticPubKey  []byte
	staticPrivKey []byte
	deviceID      [16]byte
	handshakesStarted   uint64
	handshakesCompleted uint64
	handshakesFailed    uint64
	handshakesRejected  uint64
}

func New(cfg *Config) (*Handler, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	h := &Handler{
		Module:      base.NewModule(ModuleName, ModuleVersion, []string{"crypto.provider", "session.manager"}),
		config:      cfg,
		rateLimiter: base.NewRateLimiter(cfg.RateLimit, cfg.RateBurst),
		pending:     make(map[string]*PendingHandshake),
		replayCache: make(map[string]time.Time),
	}

	return h, nil
}

func (h *Handler) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := h.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if hsCfg, ok := cfg.(*Config); ok {
		h.config = hsCfg
	}

	return nil
}

func (h *Handler) Start() error {
	if err := h.Module.Start(); err != nil {
		return err
	}

	go h.cleanupLoop()

	h.SetHealthy(true, "handshake handler running")
	h.PublishEvent(events.EventTypeModuleStarted, nil)

	return nil
}

func (h *Handler) Stop() error {
	h.PublishEvent(events.EventTypeModuleStopped, nil)
	return h.Module.Stop()
}

func (h *Handler) SetDependencies(crypto interfaces.CryptoProvider, sessionMgr interfaces.SessionManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.crypto = crypto
	h.sessionManager = sessionMgr
}

func (h *Handler) SetStaticKeys(pubKey, privKey []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.staticPubKey = pubKey
	h.staticPrivKey = privKey
}

func (h *Handler) SetDeviceID(id [16]byte) {
	h.mu.Lock()
	h.deviceID = id
	h.mu.Unlock()
}

func (h *Handler) HandleHandshake(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	h.UpdateActivity()
	atomic.AddUint64(&h.handshakesStarted, 1)

	h.PublishEvent(events.EventTypeHandshakeStarted, map[string]interface{}{
		"address": addr.String(),
		"size":    len(data),
	})

	if !h.rateLimiter.Allow() {
		atomic.AddUint64(&h.handshakesRejected, 1)
		return nil, fmt.Errorf("rate limit exceeded")
	}

	if len(data) < HandshakeMinSize || len(data) > HandshakeMaxSize {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("invalid handshake size: %d", len(data))
	}

	if h.config.EnableAntiReplay {
		if h.isReplay(data) {
			atomic.AddUint64(&h.handshakesRejected, 1)
			return nil, fmt.Errorf("replay detected")
		}
	}

	hsType := HandshakeType(data[0])

	var session interfaces.Session
	var err error

	switch hsType {
	case HandshakeTypeInit:
		session, err = h.handleInit(ctx, data, addr)
	case HandshakeTypeResponse:
		session, err = h.handleResponse(ctx, data, addr)
	case HandshakeTypeRekey:
		session, err = h.handleRekey(ctx, data, addr)
	default:
		session, err = h.handleLegacy(ctx, data, addr)
	}

	if err != nil {
		atomic.AddUint64(&h.handshakesFailed, 1)
		h.PublishEvent(events.EventTypeHandshakeFailed, map[string]interface{}{
			"address": addr.String(),
			"error":   err.Error(),
		})
		return nil, err
	}

	atomic.AddUint64(&h.handshakesCompleted, 1)
	h.PublishEvent(events.EventTypeHandshakeCompleted, map[string]interface{}{
		"address":    addr.String(),
		"session_id": session.ID(),
	})

	return session, nil
}

func (h *Handler) handleInit(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	h.mu.RLock()
	crypto := h.crypto
	sessionMgr := h.sessionManager
	h.mu.RUnlock()

	if crypto == nil || sessionMgr == nil {
		return nil, fmt.Errorf("dependencies not set")
	}

	var clientUUID [16]byte
	if len(data) >= 18 {
		copy(clientUUID[:], data[2:18])
	}

	sessionID, err := crypto.GenerateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}
	session, err := sessionMgr.CreateSession(interfaces.SessionParams{
		ClientAddr: addr,
		Seed:       seed,
		Metadata: map[string]interface{}{
			"handshake_type": "init",
			"generated_id":   sessionID,
			"client_uuid":    fmt.Sprintf("%x", clientUUID),
			"created_at":     time.Now(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	padLenBuf := make([]byte, 1)
	rand.Read(padLenBuf)
	respPadLen := int(padLenBuf[0]) & 0x1F

	response := make([]byte, 48+respPadLen)
	response[0] = byte(HandshakeTypeResponse)
	response[1] = 0x00

	sid := session.ID()
	response[2] = byte(sid >> 24)
	response[3] = byte(sid >> 16)
	response[4] = byte(sid >> 8)
	response[5] = byte(sid)
	copy(response[6:38], seed)
	rand.Read(response[38:47])
	response[47] = byte(respPadLen)
	if respPadLen > 0 {
		rand.Read(response[48:])
	}
	session.SetMetadata("handshake_response", response)

	h.markAsProcessed(data)

	return session, nil
}

func (h *Handler) BuildResponse(session interfaces.Session) []byte {
	if session == nil {
		return nil
	}
	if resp, ok := session.GetMetadata("handshake_response").([]byte); ok {
		return resp
	}
	return nil
}

func (h *Handler) handleResponse(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	h.mu.RLock()
	pending, ok := h.pending[addr.String()]
	h.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no pending handshake for %s", addr)
	}

	if time.Since(pending.Timestamp) > h.config.Timeout {
		h.removePending(addr)
		return nil, fmt.Errorf("handshake timeout")
	}
	session, ok := h.sessionManager.GetSessionByAddr(addr)
	if !ok {
		return nil, fmt.Errorf("session not found for %s", addr)
	}
	h.removePending(addr)

	return session, nil
}

func (h *Handler) handleRekey(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	session, ok := h.sessionManager.GetSessionByAddr(addr)
	if !ok {
		return nil, fmt.Errorf("session not found for rekey")
	}

	h.PublishEvent("session.rekeyed", map[string]interface{}{
		"session_id": session.ID(),
		"address":    addr.String(),
	})

	return session, nil
}

func (h *Handler) handleLegacy(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	if len(data) != HandshakeInitSize {
		return nil, fmt.Errorf("invalid legacy handshake size")
	}

	return h.handleInit(ctx, data, addr)
}

func (h *Handler) InitiateHandshake(ctx context.Context, conn net.Conn, addr net.Addr) (interfaces.Session, error) {
	h.UpdateActivity()
	atomic.AddUint64(&h.handshakesStarted, 1)

	h.mu.RLock()
	crypto := h.crypto
	sessionMgr := h.sessionManager
	h.mu.RUnlock()

	if crypto == nil || sessionMgr == nil {
		return nil, fmt.Errorf("dependencies not set")
	}

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	h.mu.RLock()
	clientUUID := h.deviceID
	h.mu.RUnlock()
	var zeroID [16]byte
	if clientUUID == zeroID {
		if _, err := rand.Read(clientUUID[:]); err != nil {
			return nil, fmt.Errorf("failed to generate client UUID: %w", err)
		}
	}

	padLenBuf := make([]byte, 1)
	rand.Read(padLenBuf)
	padLen := int(padLenBuf[0]) & 0x1F

	initPkt := make([]byte, 64+padLen)
	initPkt[0] = byte(HandshakeTypeInit)
	initPkt[1] = 0x01
	copy(initPkt[2:18], clientUUID[:])
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	copy(initPkt[18:50], seed)

	ts := uint32(time.Now().Unix())
	initPkt[50] = byte(ts >> 24)
	initPkt[51] = byte(ts >> 16)
	initPkt[52] = byte(ts >> 8)
	initPkt[53] = byte(ts)

	rand.Read(initPkt[54:63])
	initPkt[63] = byte(padLen)
	if padLen > 0 {
		rand.Read(initPkt[64:])
	}

	h.PublishEvent(events.EventTypeHandshakeStarted, map[string]interface{}{
		"address": addr.String(),
		"mode":    "client",
	})

	if _, err := conn.Write(initPkt); err != nil {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("failed to send handshake init: %w", err)
	}
	readTimeout := h.config.Timeout
	if readTimeout == 0 || readTimeout > 5*time.Second {
		readTimeout = 2 * time.Second
	}
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	defer conn.SetReadDeadline(time.Time{})

	respBuf := handshakeBufferPool.Get().([]byte)
	defer handshakeBufferPool.Put(respBuf)

	n, err := conn.Read(respBuf)
	if err != nil {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("failed to read handshake response: %w", err)
	}

	data := respBuf[:n]

	if len(data) < HandshakeMinSize {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("invalid handshake response size: %d", len(data))
	}

	if HandshakeType(data[0]) != HandshakeTypeResponse {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("invalid handshake response type: %d", data[0])
	}

	status := data[1]
	if status != 0x00 {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("handshake rejected by server with status: %d", status)
	}

	sessionID := uint32(data[2])<<24 | uint32(data[3])<<16 | uint32(data[4])<<8 | uint32(data[5])

	session, err := sessionMgr.CreateSession(interfaces.SessionParams{
		ClientAddr: addr,
		Seed:       seed, // Our seed
		Metadata: map[string]interface{}{
			"handshake_type": "response",
			"session_id":     sessionID,
			"server_pubkey":  fmt.Sprintf("%x", data[6:38]),
			"created_at":     time.Now(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	atomic.AddUint64(&h.handshakesCompleted, 1)
	h.PublishEvent(events.EventTypeHandshakeCompleted, map[string]interface{}{
		"address":    addr.String(),
		"session_id": session.ID(),
	})

	return session, nil
}
func (h *Handler) SetRateLimiter(rate float64, burst int) {
	h.rateLimiter.SetRate(rate, burst)
}

func (h *Handler) replayKey(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (h *Handler) isReplay(data []byte) bool {
	key := h.replayKey(data)

	h.replayMu.RLock()
	_, exists := h.replayCache[key]
	h.replayMu.RUnlock()

	return exists
}

func (h *Handler) markAsProcessed(data []byte) {
	key := h.replayKey(data)

	h.replayMu.Lock()
	h.replayCache[key] = time.Now()
	h.replayMu.Unlock()
}

func (h *Handler) removePending(addr net.Addr) {
	h.mu.Lock()
	delete(h.pending, addr.String())
	h.mu.Unlock()
}

func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for h.IsRunning() {
		select {
		case <-h.Context().Done():
			return
		case <-ticker.C:
			h.cleanup()
		}
	}
}

func (h *Handler) cleanup() {
	now := time.Now()

	h.mu.Lock()
	for addr, pending := range h.pending {
		if now.Sub(pending.Timestamp) > h.config.Timeout*2 {
			delete(h.pending, addr)
		}
	}
	h.mu.Unlock()

	h.replayMu.Lock()
	for key, timestamp := range h.replayCache {
		if now.Sub(timestamp) > 30*time.Minute {
			delete(h.replayCache, key)
		}
	}
	h.replayMu.Unlock()
}

func (h *Handler) HealthCheck() interfaces.HealthStatus {
	status := h.Module.HealthCheck()

	h.mu.RLock()
	status.Details["pending_count"] = len(h.pending)
	h.mu.RUnlock()

	h.replayMu.RLock()
	status.Details["replay_cache_size"] = len(h.replayCache)
	h.replayMu.RUnlock()

	status.Details["handshakes_started"] = atomic.LoadUint64(&h.handshakesStarted)
	status.Details["handshakes_completed"] = atomic.LoadUint64(&h.handshakesCompleted)
	status.Details["handshakes_failed"] = atomic.LoadUint64(&h.handshakesFailed)
	status.Details["handshakes_rejected"] = atomic.LoadUint64(&h.handshakesRejected)

	return status
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
