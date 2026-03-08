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
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
	"whispera/internal/obfuscation"
	"whispera/internal/obfuscation/russian"
	"whispera/internal/stats"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName         = "phantom.handler"
	ModuleVersion      = "1.0.0"
	phantomExtensionID = 0xFE00

	tlsRecordHandshake      = 0x16
	tlsRecordChangeCipher   = 0x14
	tlsRecordAlert          = 0x15
	tlsRecordApplication    = 0x17
	tlsHandshakeClientHello = 0x01
	tlsHandshakeServerHello = 0x02
)

var _ = []interface{}{
	tlsRecordChangeCipher,
	tlsRecordAlert,
	tlsRecordApplication,
	tlsHandshakeServerHello,
}

var log = logger.Module("phantom")

type Config struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Dest       string `yaml:"dest"`

	ServerNames []string `yaml:"server_names"`

	PrivateKey string `yaml:"private_key"`

	PublicKey []byte   `yaml:"-"`
	ShortIds  []string `yaml:"short_ids"`

	MaxTimeDiff int `yaml:"max_time_diff"`

	Fingerprint string `yaml:"fingerprint"`

	UseRussianService bool `yaml:"use_russian_service"`

	RussianServiceName string `yaml:"russian_service_name"`

	EnableObfuscation bool `yaml:"enable_obfuscation"`

	EnableSNIRotation bool `yaml:"enable_sni_rotation"`

	SNIRotationInterval int `yaml:"sni_rotation_interval"`

	EnableCoverTraffic bool `yaml:"enable_cover_traffic"`

	OnAuthenticated func(conn net.Conn, clientID string) `yaml:"-"`

	GetUsers func() []UserEntry `yaml:"-"`
}

type UserEntry struct {
	UserID    string
	PublicKey [32]byte
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:     false,
		ListenAddr:  ":8443",
		Dest:        "cloudflare.com:443",
		ServerNames: []string{"cloudflare.com"},
		ShortIds:    []string{""},
		MaxTimeDiff: 300000,
		Fingerprint: "chrome",
	}
}

type Handler struct {
	*base.Module
	config   *Config
	listener net.Listener

	privateKey []byte

	mu          sync.RWMutex
	activeConns map[string]net.Conn

	replayMu       sync.Mutex
	replayCache    map[string]time.Time
	maxTimeDiff    time.Duration
	integrationMgr *obfuscation.IntegrationManager

	sniMu         sync.RWMutex
	currentSNI    string
	sniDomains    []string
	sniRotateStop chan struct{}

	watcherStop chan struct{}

	coverTrafficStop chan struct{}

	replayCacheCleanupStop chan struct{}

	probeDetector probeDetectorIface

	stats Stats
}

type probeDetectorIface interface {
	CheckConnection(clientAddr, sni string) (allowed bool, reason string)
	RecordAuthFailure(clientAddr string)
	RecordAuthSuccess(clientAddr string)
}

type Stats struct {
	TotalConnections      uint64
	AuthenticatedClients  uint64
	ProxiedConnections    uint64
	FailedAuthentications uint64
	ActiveConnections     int32
}

func New(cfg *Config) (*Handler, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	maxTimeDiff := 5 * time.Minute
	if cfg.MaxTimeDiff > 0 {
		maxTimeDiff = time.Duration(cfg.MaxTimeDiff) * time.Millisecond
		if maxTimeDiff < 10*time.Second {
			log.Printf("[Phantom] WARNING: max_time_diff=%dms is dangerously small, clamped to 10s (check config units — value must be in milliseconds)", cfg.MaxTimeDiff)
			maxTimeDiff = 10 * time.Second
		}
	}

	h := &Handler{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		config:         cfg,
		activeConns:    make(map[string]net.Conn),
		replayCache:    make(map[string]time.Time),
		maxTimeDiff:    maxTimeDiff,
		integrationMgr: obfuscation.NewIntegrationManager(),
	}

	log.Printf("[Phantom] Handler init: maxTimeDiff=%v, serverNames=%v, shortIds=%v",
		maxTimeDiff, cfg.ServerNames, cfg.ShortIds)

	if len(cfg.PrivateKey) > 0 {
		var keyBytes []byte
		var err error

		keyBytes, err = base64.StdEncoding.DecodeString(cfg.PrivateKey)
		if err != nil {
			keyBytes, err = hex.DecodeString(cfg.PrivateKey)
		}

		if err != nil || len(keyBytes) != 32 {
			log.Printf("Phantom: Invalid Private Key format (must be 32 bytes Base64 or Hex)")
		} else {
			h.privateKey = keyBytes
			pubKey, err := curve25519.X25519(h.privateKey, curve25519.Basepoint)
			if err == nil {
				cfg.PublicKey = pubKey
				log.Printf("Phantom: Loaded Private Key (PubKey: %s)", base64.StdEncoding.EncodeToString(pubKey))
			}
		}
	} else {
		log.Printf("Phantom: No Private Key configured - RUNNING IN OPEN/DEV MODE")
	}

	return h, nil
}

// SetProbeDetector attaches an active-probing detector. Must be called before Start().
func (h *Handler) SetProbeDetector(d probeDetectorIface) {
	h.probeDetector = d
}

// RecordDNSQuery forwards a DNS query log entry to the probe detector (if configured).
// resolvedIPs — список IP-адресов из DNS-ответа, отправленного клиенту. Передайте nil
// если DNS-ответ недоступен (факт запроса всё равно записывается, IP-проверка пропускается).
func (h *Handler) RecordDNSQuery(clientAddr, hostname string, resolvedIPs []string) {
	type dnsRecorder interface {
		RecordDNSQuery(clientAddr, hostname string, resolvedIPs []string)
	}
	if r, ok := h.probeDetector.(dnsRecorder); ok {
		r.RecordDNSQuery(clientAddr, hostname, resolvedIPs)
	}
}

func (h *Handler) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := h.Module.Init(ctx, cfg); err != nil {
		return err
	}
	return nil
}

func (h *Handler) Start() error {
	if err := h.Module.Start(); err != nil {
		return err
	}

	if !h.config.Enabled {
		log.Println("Phantom protocol disabled")
		h.SetHealthy(true, "disabled")
		return nil
	}

	listener, err := net.Listen("tcp", h.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", h.config.ListenAddr, err)
	}
	h.listener = listener

	log.Printf("Phantom listening on %s (dest: %s)", h.config.ListenAddr, h.config.Dest)

	go h.acceptLoop()

	if h.config.EnableSNIRotation {
		h.initSNIRotation()
		go h.sniRotationLoop()
		log.Printf("SNI rotation enabled (interval: %d seconds)", h.config.SNIRotationInterval)
	}

	if h.config.EnableCoverTraffic {
		h.coverTrafficStop = make(chan struct{})
		go h.coverTrafficLoop()
		log.Printf("Cover traffic (network noise) enabled")
	}

	h.replayCacheCleanupStop = make(chan struct{})
	go h.replayCacheCleanupLoop()

	h.SetHealthy(true, "running")
	return nil
}

func (h *Handler) Stop() error {
	if h.listener != nil {
		h.listener.Close()
	}
	if h.sniRotateStop != nil {
		close(h.sniRotateStop)
	}

	if h.coverTrafficStop != nil {
		close(h.coverTrafficStop)
	}

	h.mu.Lock()
	for _, conn := range h.activeConns {
		conn.Close()
	}
	h.activeConns = make(map[string]net.Conn)
	h.mu.Unlock()

	return h.Module.Stop()
}

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

	// Layer 1: check IP blocklist before touching any data.
	if h.probeDetector != nil {
		if allowed, reason := h.probeDetector.CheckConnection(remoteAddr, ""); !allowed {
			log.Debug("[probe] blocked %s (blocklist): %s", remoteAddr, reason)
			h.stats.ProxiedConnections++
			h.handleHTTPFallback(conn)
			return
		}
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	clientHello, err := h.readClientHello(conn)
	if err != nil {
		if strings.Contains(err.Error(), "non-TLS") {
			log.Debug("Detected non-TLS traffic from %s - activating active probing defense", remoteAddr)
			if h.probeDetector != nil {
				h.probeDetector.RecordAuthFailure(remoteAddr)
			}
			h.handleHTTPFallback(conn)
		} else {
			log.Printf("Failed to read ClientHello from %s: %v", remoteAddr, err)
		}
		return
	}

	conn.SetReadDeadline(time.Time{})

	sni, _, clientRandom, sessionID, err := h.parseClientHello(clientHello)
	if err != nil {
		log.Printf("Failed to parse ClientHello from %s: %v - activating fallback", remoteAddr, err)
		h.proxyToDestination(conn, clientHello)
		return
	}

	// Layer 2 & 3: DNS-knock and SNI-ownership check (now that we have the SNI).
	if h.probeDetector != nil {
		if allowed, reason := h.probeDetector.CheckConnection(remoteAddr, sni); !allowed {
			log.Debug("[probe] blocked %s (SNI=%s): %s", remoteAddr, sni, reason)
			h.stats.ProxiedConnections++
			h.proxyToDestination(conn, clientHello)
			return
		}
	}

	clientID, ok := h.authenticateClient(clientRandom, sessionID)

	if ok {
		h.stats.AuthenticatedClients++
		log.Printf("Authenticated client: %s from %s (SNI: %s)", clientID, remoteAddr, sni)
		if h.probeDetector != nil {
			h.probeDetector.RecordAuthSuccess(remoteAddr)
		}

		if h.config.OnAuthenticated != nil {
			obfuscatedConn := h.WrapWithObfuscation(conn)
			trackedConn := stats.WrapConn(obfuscatedConn, clientID)
			h.config.OnAuthenticated(trackedConn, clientID)
		}
		return
	}

	// Auth failed — record it for probe detection.
	if h.probeDetector != nil {
		h.probeDetector.RecordAuthFailure(remoteAddr)
	}

	if !h.isAllowedSNI(sni) {
		log.Printf("Rejected SNI: %s from %s", sni, remoteAddr)
		h.proxyToDestination(conn, clientHello)
		return
	}

	h.stats.ProxiedConnections++
	h.proxyToDestination(conn, clientHello)
}
func (h *Handler) sendFakeHandshake(clientConn net.Conn, clientHello []byte, sni string) error {
	destConn, err := h.dialDestination()
	if err != nil {
		return fmt.Errorf("failed to dial dest: %w", err)
	}
	defer destConn.Close()
	if _, err := destConn.Write(clientHello); err != nil {
		return fmt.Errorf("failed to write ClientHello: %w", err)
	}
	buf := make([]byte, 4096)
	destConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	first := true
	for {
		n, err := destConn.Read(buf)
		if n > 0 {
			if _, wErr := clientConn.Write(buf[:n]); wErr != nil {
				return wErr
			}
			destConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			first = false
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && !first {
				return nil
			}
			if err == io.EOF {
				return nil
			}
			if first {
				return err
			}
			return nil
		}
	}
}

func (h *Handler) readClientHello(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	if header[0] != tlsRecordHandshake {
		if isHTTP(header[0]) {
			return nil, fmt.Errorf("non-TLS (HTTP) traffic detected: %02x", header[0])
		}
		return nil, fmt.Errorf("not a handshake record: %02x", header[0])
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen > 16384 {
		return nil, fmt.Errorf("record too large: %d", recordLen)
	}
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	clientHello := make([]byte, 5+recordLen)
	copy(clientHello, header)
	copy(clientHello[5:], body)
	return clientHello, nil
}

func (h *Handler) parseClientHello(data []byte) (sni string, authData []byte, clientRandom []byte, sessionID []byte, err error) {
	if len(data) < 43 {
		return "", nil, nil, nil, fmt.Errorf("ClientHello too short")
	}
	if data[5] != tlsHandshakeClientHello {
		return "", nil, nil, nil, fmt.Errorf("not a ClientHello: %02x", data[5])
	}
	pos := 5 + 4
	pos += 2
	if pos+32 > len(data) {
		return "", nil, nil, nil, fmt.Errorf("truncated at random")
	}
	clientRandom = make([]byte, 32)
	copy(clientRandom, data[pos:pos+32])
	pos += 32
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
	if pos+2 > len(data) {
		return "", nil, nil, nil, fmt.Errorf("truncated at cipher suites")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos >= len(data) {
		return "", nil, nil, nil, fmt.Errorf("truncated at compression")
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen
	if pos+2 > len(data) {
		return "", nil, clientRandom, sessionID, nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	extEnd := pos + extensionsLen
	if extEnd > len(data) {
		extEnd = len(data)
	}
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
		case 0x0000:
			sni = h.parseSNI(extData)
		case phantomExtensionID:
			authData = extData
		}
	}

	return sni, authData, clientRandom, sessionID, nil
}

func (h *Handler) parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}

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

func (h *Handler) isAllowedSNI(sni string) bool {
	if h.config.UseRussianService && h.config.RussianServiceName != "" {
		tunneler := russian.NewRussianTunneler()
		expectedDomain := tunneler.GetServiceDomain(h.config.RussianServiceName)
		if expectedDomain != "" && sni == expectedDomain {
			return true
		}
	}

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

func (h *Handler) authenticateClient(clientRandom, sessionID []byte) (string, bool) {
	if len(h.privateKey) == 0 {
		log.Println("[Phantom] Auth rejected: no private key configured")
		return "", false
	}

	if len(clientRandom) != 32 || len(sessionID) != 32 {
		return "", false
	}

	clientRandomHex := hex.EncodeToString(clientRandom)
	if h.isReplay(clientRandomHex) {
		log.Printf("[Phantom] Auth rejected: replay attack detected")
		return "", false
	}

	timestamp := binary.BigEndian.Uint64(sessionID[0:8])
	now := time.Now()
	diff := now.Sub(time.UnixMilli(int64(timestamp)))
	if diff < 0 {
		diff = -diff
	}
	if diff > h.maxTimeDiff {
		log.Printf("[Phantom] Auth rejected: timestamp too far off (diff=%v)", diff)
		return "", false
	}

	verifyHMAC := func(sharedSecret []byte) bool {
		hkdfR := hkdf.New(sha256.New, sharedSecret, nil, []byte("whispera-auth-key"))
		authKey := make([]byte, 32)
		if _, err := io.ReadFull(hkdfR, authKey); err != nil {
			return false
		}
		mac := hmac.New(sha256.New, authKey)
		mac.Write([]byte("whispera-session-id"))
		ts := make([]byte, 8)
		binary.BigEndian.PutUint64(ts, timestamp)
		mac.Write(ts)
		return hmac.Equal(sessionID[8:32], mac.Sum(nil)[:24])
	}

	if h.config.GetUsers != nil {
		for _, u := range h.config.GetUsers() {
			if !hmac.Equal(clientRandom, u.PublicKey[:]) {
				continue
			}
			sharedSecret, err := curve25519.X25519(h.privateKey, clientRandom)
			if err != nil {
				continue
			}
			if verifyHMAC(sharedSecret) {
				h.markAsSeen(clientRandomHex)
				log.Printf("[Phantom] Auth SUCCESS: user=%s", u.UserID)
				return u.UserID, true
			}
		}
		log.Printf("[Phantom] Auth FAILED: no matching user for clientRandom")
		return "", false
	}

	sharedSecret, err := curve25519.X25519(h.privateKey, clientRandom)
	if err != nil {
		return "", false
	}
	if !verifyHMAC(sharedSecret) {
		log.Printf("[Phantom] Auth FAILED: SessionID mismatch")
		return "", false
	}
	h.markAsSeen(clientRandomHex)
	log.Printf("[Phantom] Auth SUCCESS (fallback, no user list)")
	return "default", true
}

func (h *Handler) isReplay(clientRandomHex string) bool {
	h.replayMu.Lock()
	defer h.replayMu.Unlock()

	_, exists := h.replayCache[clientRandomHex]
	return exists
}

func (h *Handler) markAsSeen(clientRandomHex string) {
	h.replayMu.Lock()
	defer h.replayMu.Unlock()
	h.replayCache[clientRandomHex] = time.Now()
}

func (h *Handler) replayCacheCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-h.replayCacheCleanupStop:
			return
		case <-ticker.C:
			h.replayMu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for k, t := range h.replayCache {
				if t.Before(cutoff) {
					delete(h.replayCache, k)
				}
			}
			h.replayMu.Unlock()
		}
	}
}


func (h *Handler) proxyToDestination(clientConn net.Conn, clientHello []byte) {
	destConn, err := h.dialDestination()
	if err != nil {
		log.Printf("Failed to connect to dest %s: %v", h.config.Dest, err)
		return
	}
	defer destConn.Close()

	if _, err := destConn.Write(clientHello); err != nil {
		log.Printf("Failed to forward ClientHello: %v", err)
		return
	}

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(destConn, clientConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()

	<-done
}
func (h *Handler) dialDestination() (net.Conn, error) {
	dest := h.config.Dest
	if dest == "" {
		dest = "www.google.com:443"
	}

	tcpConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		return nil, err
	}

	return tcpConn, nil
}

func (h *Handler) GetStats() Stats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}

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

func Factory(cfg interface{}) (interfaces.Module, error) {
	if c, ok := cfg.(*Config); ok {
		return New(c)
	}
	return New(DefaultConfig())
}

func trimTrailingZeros(s string) string {
	for len(s) > 0 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	return s
}

func detectFormat(s string) string {
	if _, err := base64.StdEncoding.DecodeString(s); err == nil {
		return "Base64"
	}
	return "Unknown"
}

func isHTTP(b byte) bool {
	switch b {
	case 'G', 'P', 'C', 'H', 'O', 'D', 'T':
		return true
	}
	return false
}

func (h *Handler) handleHTTPFallback(conn net.Conn) {
	dest := h.config.Dest
	if dest == "" {
		dest = "www.google.com:443"
	}
	host, _, _ := net.SplitHostPort(dest)
	if host == "" {
		host = dest
	}
	resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\n"+
		"Location: https://%s/\r\n"+
		"Content-Type: text/html\r\n"+
		"Content-Length: 0\r\n"+
		"Connection: close\r\n"+
		"\r\n", host)

	conn.Write([]byte(resp))
}

var _ = (*tls.Config)(nil)

type ObfuscatedConn struct {
	net.Conn
	mgr *obfuscation.IntegrationManager
}

func (h *Handler) WrapWithObfuscation(conn net.Conn) net.Conn {
	if !h.config.EnableObfuscation || h.integrationMgr == nil {
		return conn
	}
	log.Printf("Applying Marionette messenger obfuscation to connection")
	return &ObfuscatedConn{
		Conn: conn,
		mgr:  h.integrationMgr,
	}
}

func (c *ObfuscatedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}
	processed, _, procErr := c.mgr.ProcessTraffic(b[:n], "inbound")
	if procErr == nil && len(processed) > 0 {
		copy(b, processed)
		return len(processed), nil
	}
	return n, err
}

func (c *ObfuscatedConn) Write(b []byte) (int, error) {
	processed, _, err := c.mgr.ProcessTraffic(b, "outbound")
	if err != nil {
		return c.Conn.Write(b)
	}
	_, writeErr := c.Conn.Write(processed)
	if writeErr != nil {
		return 0, writeErr
	}
	return len(b), nil
}

func (h *Handler) initSNIRotation() {
	h.sniMu.Lock()
	defer h.sniMu.Unlock()
	h.sniDomains = []string{
		"vk.com",
		"api.vk.com",
		"oauth.vk.com",
		"yandex.ru",
		"api.yandex.ru",
		"mail.ru",
		"ok.ru",
		"sberbank.ru",
		"gosuslugi.ru",
	}

	if len(h.config.ServerNames) > 0 {
		log.Printf("Loading custom SNI rotation list from config (%d domains)", len(h.config.ServerNames))
		customList := make([]string, len(h.config.ServerNames))
		copy(customList, h.config.ServerNames)
		h.sniDomains = customList
	} else {
		log.Printf("No custom SNI list in config, using default Russian services")
	}

	h.sniRotateStop = make(chan struct{})

	if len(h.sniDomains) > 0 {
		h.currentSNI = h.sniDomains[0]
	}
}

func (h *Handler) ReloadSNIFromConfig() {
	h.sniMu.Lock()
	defer h.sniMu.Unlock()

	if len(h.config.ServerNames) > 0 {
		log.Printf("[Phantom] Reloading SNI list. New count: %d", len(h.config.ServerNames))
		customList := make([]string, len(h.config.ServerNames))
		copy(customList, h.config.ServerNames)
		h.sniDomains = customList
	}
}

func (h *Handler) sniRotationLoop() {
	interval := h.config.SNIRotationInterval
	minInterval := 14400
	if interval <= 0 || interval < minInterval {
		interval = minInterval
		log.Printf("[Phantom] SNI rotation interval too low, enforcing minimum: %d seconds (%d hours)", interval, interval/3600)
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.sniRotateStop:
			return
		case <-ticker.C:
			h.sniMu.Lock()
			if len(h.sniDomains) > 1 {
				next := h.sniDomains[0]
				for i, domain := range h.sniDomains {
					if domain == h.currentSNI {
						nextIndex := (i + 1) % len(h.sniDomains)
						next = h.sniDomains[nextIndex]
						break
					}
				}
				h.currentSNI = next
				log.Debug("Rotated SNI to: %s", h.currentSNI)
			}
			h.sniMu.Unlock()
		}
	}
}

func (h *Handler) getCurrentSNI() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.currentSNI != "" {
		return h.currentSNI
	}
	return "vk.com"
}

func (h *Handler) coverTrafficLoop() {
	baseTicker := time.NewTicker(15 * time.Second)
	defer baseTicker.Stop()

	for {
		select {
		case <-h.coverTrafficStop:
			return
		case <-baseTicker.C:
			jitter := time.Duration(randInt(15)) * time.Second
			time.Sleep(jitter)
			h.sendCoverTraffic()
		}
	}
}

func (h *Handler) sendCoverTraffic() {
	h.mu.RLock()
	conns := make([]net.Conn, 0, len(h.activeConns))
	for _, conn := range h.activeConns {
		conns = append(conns, conn)
	}
	h.mu.RUnlock()

	for _, conn := range conns {
		size := 16 + randInt(48)
		noise := make([]byte, size)
		rand.Read(noise)
		conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		conn.Write(noise)
		conn.SetWriteDeadline(time.Time{})
	}
}

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 2)
	rand.Read(b)
	n := int(binary.BigEndian.Uint16(b))
	return n % max
}
