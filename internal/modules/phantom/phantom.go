// Package phantom implements Whispera's stealth protocol for SNI masquerading
// Phantom proxies TLS handshakes to real servers while authenticating Whispera clients
// This makes VPN traffic indistinguishable from legitimate website visits
package phantom

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"
)

const (
	ModuleName    = "phantom.handler"
	ModuleVersion = "1.0.0"

	// ClientHello extension ID for Phantom authentication
	// Using a reserved extension ID that won't conflict with standard TLS
	phantomExtensionID = 0xFE00

	// TLS record types
	tlsRecordHandshake    = 0x16
	tlsRecordChangeCipher = 0x14
	tlsRecordAlert        = 0x15
	tlsRecordApplication  = 0x17

	// TLS handshake types
	tlsHandshakeClientHello = 0x01
	tlsHandshakeServerHello = 0x02
)

// Reference unused constants for documentation
var _ = []interface{}{
	tlsRecordChangeCipher,
	tlsRecordAlert,
	tlsRecordApplication,
	tlsHandshakeServerHello,
}

var log = logger.Module("phantom")

// Config holds Phantom module configuration
type Config struct {
	// Enabled enables Phantom protocol
	Enabled bool `yaml:"enabled"`

	// ListenAddr is the address to listen on (e.g., ":443")
	ListenAddr string `yaml:"listen_addr"`

	// Dest is the target server to proxy TLS to for non-authenticated clients
	Dest string `yaml:"dest"`

	// ServerNames are the allowed SNI values
	ServerNames []string `yaml:"server_names"`

	// PrivateKey is the x25519 private key (hex string)
	PrivateKey string `yaml:"private_key"`

	// PublicKey is derived from PrivateKey
	PublicKey []byte `yaml:"-"`

	// ShortIds are allowed client identifiers
	ShortIds []string `yaml:"short_ids"`

	// MaxTimeDiff is the max allowed time difference (ms)
	MaxTimeDiff int `yaml:"max_time_diff"`

	// Fingerprint is the browser fingerprint for outbound
	Fingerprint string `yaml:"fingerprint"`

	// OnAuthenticated is called when a client authenticates successfully
	OnAuthenticated func(conn net.Conn, clientID string) `yaml:"-"`
}

// DefaultConfig returns default Phantom configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:     false,
		ListenAddr:  ":8443",
		Dest:        "cloudflare.com:443",
		ServerNames: []string{"cloudflare.com"},
		ShortIds:    []string{""},
		MaxTimeDiff: 60000,
		Fingerprint: "chrome",
	}
}

// Handler implements the Phantom protocol handler
type Handler struct {
	*base.Module
	config   *Config
	listener net.Listener

	// Keys
	privateKey []byte

	// Connection tracking
	mu          sync.RWMutex
	activeConns map[string]net.Conn

	// Metrics
	stats Stats
}

// Stats holds Phantom metrics
type Stats struct {
	TotalConnections      uint64
	AuthenticatedClients  uint64
	ProxiedConnections    uint64
	FailedAuthentications uint64
	ActiveConnections     int32
}

// New creates a new Phantom handler
func New(cfg *Config) (*Handler, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	h := &Handler{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		config:      cfg,
		activeConns: make(map[string]net.Conn),
	}

	// Decode and set private key (Support BOTH Hex and Base64)
	if len(cfg.PrivateKey) > 0 {
		var keyBytes []byte
		var err error

		// Try Base64 first
		keyBytes, err = base64.StdEncoding.DecodeString(cfg.PrivateKey)
		if err != nil {
			// Try Hex
			keyBytes, err = hex.DecodeString(cfg.PrivateKey)
		}

		if err == nil && len(keyBytes) == 32 {
			h.privateKey = keyBytes
			// Derive public key for verification/logging
			pubKey, err := curve25519.X25519(h.privateKey, curve25519.Basepoint)
			if err == nil {
				cfg.PublicKey = pubKey
				log.Printf("Phantom: Loaded Private Key (Format: %s, PubKey: %x)", detectFormat(cfg.PrivateKey), pubKey)
			}
		} else {
			log.Printf("Phantom: Invalid Private Key format (must be 32 bytes Hex or Base64)")
		}
	} else {
		log.Printf("Phantom: No Private Key configured - RUNNING IN OPEN/DEV MODE (Accepting all Whispera Traffic)")
	}

	return h, nil
}

// Init initializes the Phantom handler
func (h *Handler) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := h.Module.Init(ctx, cfg); err != nil {
		return err
	}
	return nil
}

// Start starts the Phantom handler
func (h *Handler) Start() error {
	if err := h.Module.Start(); err != nil {
		return err
	}

	if !h.config.Enabled {
		log.Println("Phantom protocol disabled")
		h.SetHealthy(true, "disabled")
		return nil
	}

	// Start TCP listener
	listener, err := net.Listen("tcp", h.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", h.config.ListenAddr, err)
	}
	h.listener = listener

	log.Printf("Phantom listening on %s (dest: %s)", h.config.ListenAddr, h.config.Dest)

	// Start accept loop
	go h.acceptLoop()

	h.SetHealthy(true, "running")
	return nil
}

// Stop stops the Phantom handler
func (h *Handler) Stop() error {
	if h.listener != nil {
		h.listener.Close()
	}

	// Close all active connections
	h.mu.Lock()
	for _, conn := range h.activeConns {
		conn.Close()
	}
	h.activeConns = make(map[string]net.Conn)
	h.mu.Unlock()

	return h.Module.Stop()
}

// acceptLoop accepts incoming connections
func (h *Handler) acceptLoop() {
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		h.stats.TotalConnections++
		go h.HandleConnection(conn)
	}
}

// HandleConnection processes an incoming connection
func (h *Handler) HandleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	h.mu.Lock()
	h.activeConns[remoteAddr] = conn
	h.stats.ActiveConnections++
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.activeConns, remoteAddr)
		h.stats.ActiveConnections--
		h.mu.Unlock()
	}()

	// Set initial read deadline for ClientHello
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read TLS ClientHello
	clientHello, err := h.readClientHello(conn)
	if err != nil {
		log.Printf("Failed to read ClientHello from %s: %v", remoteAddr, err)
		return
	}

	// Clear deadline
	conn.SetReadDeadline(time.Time{})

	// Parse ClientHello to extract SNI and Phantom auth data
	sni, authData, clientRandom, sessionID, err := h.parseClientHello(clientHello)
	if err != nil {
		log.Printf("Failed to parse ClientHello: %v", err)
		h.proxyToDestination(conn, clientHello)
		return
	}

	// Try to authenticate as Whispera client FIRST (bypass SNI check for valid clients)
	clientID, ok := h.authenticateClient(clientRandom, sessionID)
	// Fallback to legacy extension check if REALITY check fails
	if !ok && len(authData) > 0 && len(h.privateKey) > 0 {
		clientID, ok = h.authenticateClientLegacy(authData)
	}

	if ok {
		// Authenticated Whispera client!
		h.stats.AuthenticatedClients++
		log.Printf("Authenticated client: %s from %s (SNI: %s)", clientID, remoteAddr, sni)

		// REALITY-like: Perform minimal handshake with real destination to satisfy DPI
		if err := h.sendFakeHandshake(conn, clientHello, sni); err != nil {
			log.Printf("Warning: Failed to send fake handshake: %v", err)
		}

		// Call handler for authenticated connection
		if h.config.OnAuthenticated != nil {
			h.config.OnAuthenticated(conn, clientID)
		}
		return
	}

	// Not authenticated - enforce SNI allowlist to avoid being an open proxy
	if !h.isAllowedSNI(sni) {
		log.Printf("Rejected SNI: %s from %s", sni, remoteAddr)
		h.proxyToDestination(conn, clientHello)
		return
	}

	// Allowed SNI but not authenticated - proxy to real destination
	h.stats.ProxiedConnections++
	h.proxyToDestination(conn, clientHello)
}

// sendFakeHandshake is a no-op now - client is already authenticated via HMAC
// No need to proxy real TLS handshake, just return success
func (h *Handler) sendFakeHandshake(clientConn net.Conn, clientHello []byte, sni string) error {
	// 1. Connect to real destination
	destConn, err := h.dialDestination()
	if err != nil {
		return fmt.Errorf("failed to dial dest: %w", err)
	}
	defer destConn.Close()

	// 2. Forward ClientHello
	if _, err := destConn.Write(clientHello); err != nil {
		return fmt.Errorf("failed to write ClientHello: %w", err)
	}

	// 3. Relay ServerHello/Cert/Done back to client
	// We read until the server stops sending (waits for client)
	buf := make([]byte, 4096)

	// Initial read with reasonable timeout
	destConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	first := true
	for {
		n, err := destConn.Read(buf)
		if n > 0 {
			if _, wErr := clientConn.Write(buf[:n]); wErr != nil {
				return wErr
			}
			// If we successfully read data, make subsequent reads faster
			// to detect end of flight
			destConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			first = false
		}

		if err != nil {
			// Timeout is expected after the server finishes its flight
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && !first {
				return nil
			}
			if err == io.EOF {
				return nil
			}
			// Only error if we haven't read anything
			if first {
				return err
			}
			return nil
		}
	}
}

// readClientHello reads the TLS ClientHello from connection
func (h *Handler) readClientHello(conn net.Conn) ([]byte, error) {
	// TLS record header: 5 bytes
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Validate TLS record
	if header[0] != tlsRecordHandshake {
		return nil, fmt.Errorf("not a handshake record: %02x", header[0])
	}

	// Get record length
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen > 16384 {
		return nil, fmt.Errorf("record too large: %d", recordLen)
	}

	// Read record body
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Combine header + body for full ClientHello
	clientHello := make([]byte, 5+recordLen)
	copy(clientHello, header)
	copy(clientHello[5:], body)

	return clientHello, nil
}

// parseClientHello extracts SNI and auth data from ClientHello
func (h *Handler) parseClientHello(data []byte) (sni string, authData []byte, clientRandom []byte, sessionID []byte, err error) {
	if len(data) < 43 {
		return "", nil, nil, nil, fmt.Errorf("ClientHello too short")
	}

	// Skip TLS record header (5 bytes)
	// Handshake header: type (1) + length (3)
	if data[5] != tlsHandshakeClientHello {
		return "", nil, nil, nil, fmt.Errorf("not a ClientHello: %02x", data[5])
	}

	// Parse ClientHello structure
	pos := 5 + 4 // Skip record header + handshake header

	// Version (2 bytes)
	pos += 2

	// Random (32 bytes)
	if pos+32 > len(data) {
		return "", nil, nil, nil, fmt.Errorf("truncated at random")
	}
	clientRandom = make([]byte, 32)
	copy(clientRandom, data[pos:pos+32])
	pos += 32

	// Session ID
	if pos >= len(data) {
		return "", nil, nil, nil, fmt.Errorf("truncated at session ID")
	}
	sessionIDLen := int(data[pos])
	pos++

	if pos+sessionIDLen > len(data) {
		return "", nil, nil, nil, fmt.Errorf("truncated at session ID body")
	}
	if sessionIDLen > 0 {
		sessionID = make([]byte, sessionIDLen)
		copy(sessionID, data[pos:pos+sessionIDLen])
	}
	pos += sessionIDLen

	// Cipher suites
	if pos+2 > len(data) {
		return "", nil, nil, nil, fmt.Errorf("truncated at cipher suites")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// Compression methods
	if pos >= len(data) {
		return "", nil, nil, nil, fmt.Errorf("truncated at compression")
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Extensions
	if pos+2 > len(data) {
		// No extensions
		return "", nil, clientRandom, sessionID, nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	extEnd := pos + extensionsLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	// Parse extensions
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > extEnd {
			break
		}

		extData := data[pos : pos+extLen]
		pos += extLen

		switch extType {
		case 0x0000: // SNI extension
			sni = h.parseSNI(extData)
		case phantomExtensionID: // Phantom auth extension (Optional/Legacy support)
			authData = extData
		}
	}

	return sni, authData, clientRandom, sessionID, nil
}

// parseSNI extracts server name from SNI extension data
func (h *Handler) parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// SNI list length (2 bytes)
	// Name type (1 byte) - should be 0 for hostname
	// Name length (2 bytes)
	// Name data

	nameType := data[2]
	if nameType != 0 {
		return ""
	}

	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}

	return string(data[5 : 5+nameLen])
}

// isAllowedSNI checks if SNI is in allowed list
func (h *Handler) isAllowedSNI(sni string) bool {
	if len(h.config.ServerNames) == 0 {
		return true
	}

	for _, allowed := range h.config.ServerNames {
		if sni == allowed {
			return true
		}
	}
	return false
}

// authenticateClient validates Phantom auth data using REALITY-like SessionID HMAC
func (h *Handler) authenticateClient(clientRandom, sessionID []byte) (string, bool) {
	// DEV MODE: If no private key is configured, ALLOW ALL
	if len(h.privateKey) == 0 {
		return "dev-user", true
	}

	if len(clientRandom) != 32 || len(sessionID) != 32 {
		return "", false
	}

	// auth: Verify if SessionID == HMAC(SharedSecret, "whispera-session-id")
	// We treat ClientRandom as the Client's Ephemeral Public Key (X25519)

	// Derive public key for debugging
	myPubKey, _ := curve25519.X25519(h.privateKey, curve25519.Basepoint)
	log.Printf("[DEBUG] Auth Req: ClientRandom=%x... MyPrivKey=loaded MyPubKey=%x...", clientRandom[:4], myPubKey[:4])

	// Compute shared secret: X25519(ServerPriv, ClientPub)
	// ClientPub is clientRandom
	sharedSecret, err := curve25519.X25519(h.privateKey, clientRandom)
	if err != nil {
		log.Printf("[DEBUG] Shared Secret Derivation Failed: %v", err)
		return "", false
	}

	// Calculate expected SessionID
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte("whispera-session-id"))
	expected := mac.Sum(nil)

	log.Printf("[DEBUG] HMAC Check: SharedSecretPrefix=%x ExpectedID=%x ReceivedID=%x", sharedSecret[:4], expected[:4], sessionID[:4])

	// Use constant time comparison
	if hmac.Equal(sessionID, expected[:32]) {
		log.Printf("[DEBUG] Authentication SUCCESS")
		return "default", true
	}

	log.Printf("[DEBUG] Authentication FAILED: SessionID mismatch")
	return "", false
}

// authenticateClientLegacy validates legacy Phantom auth extension data
func (h *Handler) authenticateClientLegacy(authData []byte) (string, bool) {
	if len(authData) < 16 {
		return "", false
	}

	// Auth data format:
	// [0-7]   timestamp (unix ms)
	// [8-15]  shortId (8 bytes)

	// Check timestamp
	timestamp := binary.BigEndian.Uint64(authData[0:8])
	now := uint64(time.Now().UnixMilli())
	diff := int64(now) - int64(timestamp)
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(h.config.MaxTimeDiff) {
		return "", false
	}

	// Check shortId
	shortId := base64.StdEncoding.EncodeToString(authData[8:16])
	// shortId = trimTrailingZeros(shortId) // No longer applicable for Base64 effectively, but keep structure if needed or remove

	found := false
	for _, allowed := range h.config.ShortIds {
		if shortId == allowed {
			found = true
			break
		}
	}
	if !found {
		return "", false
	}

	return shortId, true
}

// proxyToDestination proxies connection to real destination server
func (h *Handler) proxyToDestination(clientConn net.Conn, clientHello []byte) {
	// Connect to destination
	destConn, err := h.dialDestination()
	if err != nil {
		log.Printf("Failed to connect to dest %s: %v", h.config.Dest, err)
		return
	}
	defer destConn.Close()

	// Forward ClientHello to destination
	if _, err := destConn.Write(clientHello); err != nil {
		log.Printf("Failed to forward ClientHello: %v", err)
		return
	}

	// Bidirectional proxy
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(destConn, clientConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()

	// Wait for either direction to finish
	<-done
}

// dialDestination connects to the destination server (TCP only)
// Correct Logic: detailed "Stealing" works by forwarding the *Client's* Hello packet.
// We must NOT perform a handshake here, otherwise we double-encrypt and fail.
func (h *Handler) dialDestination() (net.Conn, error) {
	// Dial TCP to the target (e.g., cloudflare.com:443)
	tcpConn, err := net.DialTimeout("tcp", h.config.Dest, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Return the raw TCP connection so we can pipe the client's handshake through it
	return tcpConn, nil
}

// GetStats returns current statistics
func (h *Handler) GetStats() Stats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}

// GenerateKeyPair generates a new x25519 key pair
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

// Factory creates Phantom handler modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	if c, ok := cfg.(*Config); ok {
		return New(c)
	}
	return New(DefaultConfig())
}

// trimTrailingZeros removes trailing zeros from hex string
func trimTrailingZeros(s string) string {
	for len(s) > 0 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	return s
}

// detectFormat helper to identify key format for logging
func detectFormat(s string) string {
	if _, err := base64.StdEncoding.DecodeString(s); err == nil {
		return "Base64"
	}
	return "Unknown"
}

// Ensure Handler implements TLS check
var _ = (*tls.Config)(nil)
