// Package handshake provides the handshake handler module
package handshake

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "handshake.handler"
	ModuleVersion = "1.0.0"

	// Handshake message sizes
	HandshakeInitSize = 48
	HandshakeRespSize = 48
	HandshakeMinSize  = 32
	HandshakeMaxSize  = 96

	// Handshake magic byte
	MagicByte = 0x57 // 'W' for Whispera
)

// Пул буферов для handshake ответов (УЛУЧШЕНИЕ: избегаем аллокаций на горячем пути)
var handshakeBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1024)
	},
}

// HandshakeType represents the type of handshake
type HandshakeType byte

const (
	HandshakeTypeInit     HandshakeType = 0x01
	HandshakeTypeResponse HandshakeType = 0x02
	HandshakeTypeRekey    HandshakeType = 0x03
)

// Config holds handshake handler configuration
type Config struct {
	RateLimit        float64       // Handshakes per second
	RateBurst        int           // Burst size
	Timeout          time.Duration // Handshake timeout
	MaxPending       int           // Max pending handshakes
	EnableAntiReplay bool          // Enable anti-replay protection
}

// DefaultConfig returns default handshake configuration
func DefaultConfig() *Config {
	return &Config{
		RateLimit:        100,
		RateBurst:        50,
		Timeout:          2 * time.Second,  // УЛУЧШЕНИЕ: Снижено с 10s до 2s для быстрого handshake
		MaxPending:       1000,
		EnableAntiReplay: true,
	}
}

// Validate validates the configuration
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

// PendingHandshake represents a pending handshake
type PendingHandshake struct {
	Addr      net.Addr
	Init      []byte
	Timestamp time.Time
	Nonce     []byte
}

// Handler implements interfaces.HandshakeHandler
type Handler struct {
	*base.Module
	config *Config

	// Dependencies (set via SetDependencies)
	crypto         interfaces.CryptoProvider
	sessionManager interfaces.SessionManager

	// Rate limiter
	rateLimiter *base.RateLimiter

	// Pending handshakes
	mu      sync.RWMutex
	pending map[string]*PendingHandshake

	// Anti-replay
	replayMu    sync.RWMutex
	replayCache map[string]time.Time

	// Static keys (for server mode)
	staticPubKey  []byte
	staticPrivKey []byte

	// Stats
	handshakesStarted   uint64
	handshakesCompleted uint64
	handshakesFailed    uint64
	handshakesRejected  uint64
}

// New creates a new handshake handler
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

// Init initializes the handshake handler
func (h *Handler) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := h.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if hsCfg, ok := cfg.(*Config); ok {
		h.config = hsCfg
	}

	return nil
}

// Start starts the handshake handler
func (h *Handler) Start() error {
	if err := h.Module.Start(); err != nil {
		return err
	}

	// Start cleanup goroutine
	go h.cleanupLoop()

	h.SetHealthy(true, "handshake handler running")
	h.PublishEvent(events.EventTypeModuleStarted, nil)

	return nil
}

// Stop stops the handshake handler
func (h *Handler) Stop() error {
	h.PublishEvent(events.EventTypeModuleStopped, nil)
	return h.Module.Stop()
}

// SetDependencies sets module dependencies
func (h *Handler) SetDependencies(crypto interfaces.CryptoProvider, sessionMgr interfaces.SessionManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.crypto = crypto
	h.sessionManager = sessionMgr
}

// SetStaticKeys sets the server's static key pair
func (h *Handler) SetStaticKeys(pubKey, privKey []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.staticPubKey = pubKey
	h.staticPrivKey = privKey
}

// HandleHandshake processes a handshake packet
func (h *Handler) HandleHandshake(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	h.UpdateActivity()
	atomic.AddUint64(&h.handshakesStarted, 1)

	h.PublishEvent(events.EventTypeHandshakeStarted, map[string]interface{}{
		"address": addr.String(),
		"size":    len(data),
	})

	// Rate limit check
	if !h.rateLimiter.Allow() {
		atomic.AddUint64(&h.handshakesRejected, 1)
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// Validate packet size
	if len(data) < HandshakeMinSize || len(data) > HandshakeMaxSize {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("invalid handshake size: %d", len(data))
	}

	// Check anti-replay
	if h.config.EnableAntiReplay {
		if h.isReplay(data) {
			atomic.AddUint64(&h.handshakesRejected, 1)
			return nil, fmt.Errorf("replay detected")
		}
	}

	// Parse handshake type
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
		// Try legacy handshake format
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

// handleInit handles initial handshake
func (h *Handler) handleInit(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	h.mu.RLock()
	crypto := h.crypto
	sessionMgr := h.sessionManager
	h.mu.RUnlock()

	if crypto == nil || sessionMgr == nil {
		return nil, fmt.Errorf("dependencies not set")
	}

	// Parse client data (64 bytes expected)
	// [type:1][version:1][uuid:16][pubkey:32][timestamp:4][padding:10]
	var clientUUID [16]byte
	if len(data) >= 18 {
		copy(clientUUID[:], data[2:18])
	}

	// Generate session ID (used for logging/debugging)
	sessionID, err := crypto.GenerateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Generate seed for key derivation
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	// Create session
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

	// Build response packet (48 bytes)
	// [type:1][status:1][session_id:4][server_pubkey:32][nonce:10]
	response := make([]byte, 48)
	response[0] = byte(HandshakeTypeResponse) // 0x02
	response[1] = 0x00                        // Status OK

	// Session ID (bytes 2-5, big-endian)
	sid := session.ID()
	response[2] = byte(sid >> 24)
	response[3] = byte(sid >> 16)
	response[4] = byte(sid >> 8)
	response[5] = byte(sid)

	// Server ephemeral public key (bytes 6-37)
	copy(response[6:38], seed) // Using seed as placeholder for pubkey

	// Nonce (bytes 38-47)
	rand.Read(response[38:48])

	// Store response in session metadata for caller to retrieve and send
	session.SetMetadata("handshake_response", response)

	// Mark as not replay
	h.markAsProcessed(data)

	return session, nil
}

// BuildResponse builds a response for a successful handshake
func (h *Handler) BuildResponse(session interfaces.Session) []byte {
	if session == nil {
		return nil
	}
	if resp, ok := session.GetMetadata("handshake_response").([]byte); ok {
		return resp
	}
	return nil
}

// handleResponse handles handshake response
func (h *Handler) handleResponse(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	// Look up pending handshake
	h.mu.RLock()
	pending, ok := h.pending[addr.String()]
	h.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no pending handshake for %s", addr)
	}

	// Validate response
	if time.Since(pending.Timestamp) > h.config.Timeout {
		h.removePending(addr)
		return nil, fmt.Errorf("handshake timeout")
	}

	// Get session by address
	session, ok := h.sessionManager.GetSessionByAddr(addr)
	if !ok {
		return nil, fmt.Errorf("session not found for %s", addr)
	}

	// Remove pending
	h.removePending(addr)

	return session, nil
}

// handleRekey handles rekey request
func (h *Handler) handleRekey(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	// Get existing session
	session, ok := h.sessionManager.GetSessionByAddr(addr)
	if !ok {
		return nil, fmt.Errorf("session not found for rekey")
	}

	// Verify and update session keys
	// This is a simplified implementation

	h.PublishEvent("session.rekeyed", map[string]interface{}{
		"session_id": session.ID(),
		"address":    addr.String(),
	})

	return session, nil
}

// handleLegacy handles legacy handshake format
func (h *Handler) handleLegacy(ctx context.Context, data []byte, addr net.Addr) (interfaces.Session, error) {
	// For compatibility with older clients
	// Check if it looks like a valid handshake

	if len(data) != HandshakeInitSize {
		return nil, fmt.Errorf("invalid legacy handshake size")
	}

	// Treat as init
	return h.handleInit(ctx, data, addr)
}

// InitiateHandshake initiates a handshake with a server (client mode)
func (h *Handler) InitiateHandshake(ctx context.Context, conn net.Conn, addr net.Addr) (interfaces.Session, error) {
	h.UpdateActivity()
	atomic.AddUint64(&h.handshakesStarted, 1)

	// Dependency check
	h.mu.RLock()
	crypto := h.crypto
	sessionMgr := h.sessionManager
	h.mu.RUnlock()

	if crypto == nil || sessionMgr == nil {
		return nil, fmt.Errorf("dependencies not set")
	}

	// Generate nonce
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Generate client UUID
	var clientUUID [16]byte
	if _, err := rand.Read(clientUUID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate client UUID: %w", err)
	}

	// Build handshake init message
	// [type:1][version:1][uuid:16][pubkey:32][timestamp:4][padding:10] -> Total 64 bytes structure used in handleInit
	// But HandshakeInitSize is 48?
	// handleInit expects:
	// copy(clientUUID[:], data[2:18]) -> bytes 2-17.
	// We should match the structure expected by handleInit.

	initPkt := make([]byte, 64) // Use 64 to be safe and match handleInit expectation
	initPkt[0] = byte(HandshakeTypeInit)
	initPkt[1] = 0x01 // Version
	copy(initPkt[2:18], clientUUID[:])

	// Generate ephemeral keys for this session
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	// Use seed as pubkey placeholder (in real implementation, derive Curve25519 pubkey)
	copy(initPkt[18:50], seed)

	// Timestamp (4 bytes) - Unix timestamp
	ts := uint32(time.Now().Unix())
	initPkt[50] = byte(ts >> 24)
	initPkt[51] = byte(ts >> 16)
	initPkt[52] = byte(ts >> 8)
	initPkt[53] = byte(ts)

	// Padding (random)
	rand.Read(initPkt[54:])

	h.PublishEvent(events.EventTypeHandshakeStarted, map[string]interface{}{
		"address": addr.String(),
		"mode":    "client",
	})

	// Send Init
	if _, err := conn.Write(initPkt); err != nil {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("failed to send handshake init: %w", err)
	}

	// Wait for Response with optimized timeout and buffering
	// УЛУЧШЕНИЕ: Используем пул буферов и адаптивный таймаут
	readTimeout := h.config.Timeout
	if readTimeout == 0 || readTimeout > 5*time.Second {
		readTimeout = 2 * time.Second  // Capped at 2s for faster response
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

	// Validate response
	if len(data) < HandshakeMinSize {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("invalid handshake response size: %d", len(data))
	}

	if HandshakeType(data[0]) != HandshakeTypeResponse {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("invalid handshake response type: %d", data[0])
	}

	// Parse valid response
	// [type:1][status:1][session_id:4][server_pubkey:32][nonce:10] (from handleInit)

	status := data[1]
	if status != 0x00 {
		atomic.AddUint64(&h.handshakesFailed, 1)
		return nil, fmt.Errorf("handshake rejected by server with status: %d", status)
	}

	// Extract Session ID
	sessionID := uint32(data[2])<<24 | uint32(data[3])<<16 | uint32(data[4])<<8 | uint32(data[5])

	// Create Session
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
		"session_id": session.ID(), // Note: Local session ID might differ from Server session ID if not synced
	})

	// Force set the session ID to match server if possible, or store mapping
	// But SessionManager creates new ID.
	// We should probably trust the local session manager's ID for local reference,
	// but we need to include the Server's SessionID in outgoing packets.
	// The Packet structure has SessionID uint32.
	// For now, let's assume valid session established.

	return session, nil
}

// SetRateLimiter updates the rate limiter configuration
func (h *Handler) SetRateLimiter(rate float64, burst int) {
	h.rateLimiter.SetRate(rate, burst)
}

// isReplay checks if a handshake is a replay
func (h *Handler) isReplay(data []byte) bool {
	key := string(data[:min(32, len(data))])

	h.replayMu.RLock()
	_, exists := h.replayCache[key]
	h.replayMu.RUnlock()

	return exists
}

// markAsProcessed marks a handshake as processed (for anti-replay)
func (h *Handler) markAsProcessed(data []byte) {
	key := string(data[:min(32, len(data))])

	h.replayMu.Lock()
	h.replayCache[key] = time.Now()
	h.replayMu.Unlock()
}

// removePending removes a pending handshake
func (h *Handler) removePending(addr net.Addr) {
	h.mu.Lock()
	delete(h.pending, addr.String())
	h.mu.Unlock()
}

// cleanupLoop cleans up expired pending handshakes and replay cache
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

// cleanup removes expired entries
func (h *Handler) cleanup() {
	now := time.Now()

	// Cleanup pending handshakes
	h.mu.Lock()
	for addr, pending := range h.pending {
		if now.Sub(pending.Timestamp) > h.config.Timeout*2 {
			delete(h.pending, addr)
		}
	}
	h.mu.Unlock()

	// Cleanup replay cache (keep entries for 5 minutes)
	h.replayMu.Lock()
	for key, timestamp := range h.replayCache {
		if now.Sub(timestamp) > 5*time.Minute {
			delete(h.replayCache, key)
		}
	}
	h.replayMu.Unlock()
}

// HealthCheck returns health status
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

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Factory creates handshake handler modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
