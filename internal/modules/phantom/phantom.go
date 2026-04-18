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
	"math"
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
	"whispera/internal/obfuscation/marionette"
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

	EnableObfuscation    bool   `yaml:"enable_obfuscation"`
	ObfuscationProfile   string `yaml:"obfuscation_profile"`

	EnableSNIRotation bool `yaml:"enable_sni_rotation"`

	SNIRotationInterval int `yaml:"sni_rotation_interval"`

	EnableCoverTraffic bool `yaml:"enable_cover_traffic"`

	EnableChatFSM        bool          `yaml:"enable_chat_fsm"`
	ChatFSMCoverInterval time.Duration `yaml:"chat_fsm_cover_interval"`

	// BlockLocalPeers rejects inbound connections whose remote address is a
	// loopback, link-local, or private RFC1918 range unless it matches
	// AllowedLocalCIDRs. Defends against on-host malware opening the tunnel
	// and bypassing egress firewall rules (so-called "localhost attack").
	BlockLocalPeers   bool     `yaml:"block_local_peers"`
	AllowedLocalCIDRs []string `yaml:"allowed_local_cidrs"`

	OnAuthenticated func(conn net.Conn, clientID string) `yaml:"-"`

	// AdmitSession is consulted right after successful auth. It returns a
	// short reason string when admission is denied (e.g. per-key session or
	// IP cap hit); an empty reason means admitted. The release callback MUST
	// be invoked exactly once when the session ends.
	AdmitSession func(clientID, sessionID, remoteIP string) (release func(), reason string) `yaml:"-"`

	GetUsers func() []UserEntry `yaml:"-"`
}

type UserEntry struct {
	UserID    string
	PublicKey [32]byte
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:            false,
		ListenAddr:         ":8443",
		Dest:               "cloudflare.com:443",
		ServerNames:        []string{"cloudflare.com"},
		ShortIds:           []string{""},
		MaxTimeDiff:        300000,
		Fingerprint:        "chrome",
		EnableObfuscation:  true,
		ObfuscationProfile: "vk",
		BlockLocalPeers:    true,
	}
}

func isLocalOrPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // CGNAT 100.64/10
			return true
		}
	}
	if ip.To4() == nil && len(ip) == net.IPv6len && ip[0] == 0xfc { // fc00::/7 ULA
		return true
	}
	return false
}

func (h *Handler) isAddrAllowed(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return true
		}
		tcp = &net.TCPAddr{IP: net.ParseIP(host)}
	}
	if !isLocalOrPrivateIP(tcp.IP) {
		return true
	}
	for _, cidr := range h.config.AllowedLocalCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipnet.Contains(tcp.IP) {
			return true
		}
	}
	return false
}

type Handler struct {
	*base.Module
	config   *Config
	listener net.Listener

	privateKey []byte

	mu             sync.RWMutex
	activeConns    map[string]net.Conn
	authedConns    map[string]net.Conn

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
	connGuard     connGuardIface

	stats Stats
}

type probeDetectorIface interface {
	CheckConnection(clientAddr, sni string) (allowed bool, reason string)
	RecordAuthFailure(clientAddr string)
	RecordAuthSuccess(clientAddr string)
}

type connGuardIface interface {
	Allow(addr net.Addr) bool
	Done(addr net.Addr)
	CheckFirstBytes(conn net.Conn) (peeked []byte, err error)
}

type Stats struct {
	TotalConnections      uint64
	AuthenticatedClients  uint64
	ProxiedConnections    uint64
	FailedAuthentications uint64
	BlockedLocalPeers     uint64
	AdmissionDenied       uint64
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

	integrationMgr := obfuscation.NewIntegrationManagerWithOptions(false, true)
	integrationMgr.GetMarionetteAdapter().GetCore().MlSystem = nil
	if cfg.EnableObfuscation && cfg.ObfuscationProfile != "" {
		if err := integrationMgr.SetProfile(cfg.ObfuscationProfile); err != nil {
			log.Printf("[Phantom] Warning: failed to set obfuscation profile %q: %v", cfg.ObfuscationProfile, err)
		} else {
			log.Printf("[Phantom] Marionette obfuscation enabled with profile: %s", cfg.ObfuscationProfile)
		}
	}

	h := &Handler{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		config:         cfg,
		activeConns:    make(map[string]net.Conn),
		authedConns:    make(map[string]net.Conn),
		replayCache:    make(map[string]time.Time),
		maxTimeDiff:    maxTimeDiff,
		integrationMgr: integrationMgr,
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

func (h *Handler) SetProbeDetector(d probeDetectorIface) {
	h.probeDetector = d
}

func (h *Handler) SetConnGuard(g connGuardIface) {
	h.connGuard = g
}

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

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", h.config.ListenAddr)
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

	if h.replayCacheCleanupStop != nil {
		close(h.replayCacheCleanupStop)
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

		if h.config.BlockLocalPeers && !h.isAddrAllowed(conn.RemoteAddr()) {
			log.Debug("Rejected local/private peer: %s", conn.RemoteAddr())
			h.stats.BlockedLocalPeers++
			conn.Close()
			continue
		}

		if h.connGuard != nil {
			if !h.connGuard.Allow(conn.RemoteAddr()) {
				conn.Close()
				continue
			}
		}

		h.stats.TotalConnections++
		go h.HandleConnection(conn)
	}
}

func (h *Handler) HandleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()

	connGuardDone := false
	releaseConnGuard := func() {
		if h.connGuard != nil && !connGuardDone {
			connGuardDone = true
			h.connGuard.Done(conn.RemoteAddr())
		}
	}
	defer releaseConnGuard()

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

	if h.probeDetector != nil {
		if allowed, reason := h.probeDetector.CheckConnection(remoteAddr, ""); !allowed {
			log.Debug("[probe] blocked %s (blocklist): %s", remoteAddr, reason)
			h.stats.ProxiedConnections++
			releaseConnGuard()
			h.handleHTTPFallback(conn)
			return
		}

		if h.connGuard != nil {
			if peeked, fbErr := h.connGuard.CheckFirstBytes(conn); fbErr != nil {
				log.Debug("[connguard] fast-reject %s: %v (peeked=%x)", remoteAddr, fbErr, peeked)
				h.probeDetector.RecordAuthFailure(remoteAddr)
				return
			} else if len(peeked) > 0 {
				conn = &prependConn{Conn: conn, buf: peeked}
			}
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
			releaseConnGuard()
			h.handleHTTPFallback(conn)
		} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			log.Debug("Connection closed before ClientHello from %s", remoteAddr)
		} else {
			log.Printf("Failed to read ClientHello from %s: %v", remoteAddr, err)
		}
		return
	}

	conn.SetReadDeadline(time.Time{})

	sni, _, clientRandom, sessionID, err := h.parseClientHello(clientHello)
	if err != nil {
		log.Printf("Failed to parse ClientHello from %s: %v - activating fallback", remoteAddr, err)
		releaseConnGuard()
		h.proxyToDestination(conn, clientHello)
		return
	}

	if h.probeDetector != nil {
		if allowed, reason := h.probeDetector.CheckConnection(remoteAddr, sni); !allowed {
			log.Debug("[probe] blocked %s (SNI=%s): %s", remoteAddr, sni, reason)
			h.stats.ProxiedConnections++
			releaseConnGuard()
			h.proxyToSNI(conn, clientHello, sni)
			return
		}
	}

	clientID, ok := h.authenticateClient(clientRandom, sessionID)

	releaseConnGuard()

	if ok {
		h.stats.AuthenticatedClients++
		log.Printf("Authenticated client: %s from %s (SNI: %s)", clientID, remoteAddr, sni)
		if h.probeDetector != nil {
			h.probeDetector.RecordAuthSuccess(remoteAddr)
		}

		if h.config.OnAuthenticated != nil {
			release := func() {}
			if h.config.AdmitSession != nil {
				host, _, _ := net.SplitHostPort(remoteAddr)
				if host == "" {
					host = remoteAddr
				}
				rel, reason := h.config.AdmitSession(clientID, fmt.Sprintf("%x", sessionID), host)
				if reason != "" {
					log.Printf("Admission denied for %s (%s): %s", clientID, remoteAddr, reason)
					h.stats.AdmissionDenied++
					h.writeAdmissionError(conn, reason)
					return
				}
				if rel != nil {
					release = rel
				}
			}
			defer release()

			obfuscatedConn := h.WrapWithObfuscation(conn)
			trackedConn := stats.WrapConn(obfuscatedConn, clientID)
			h.mu.Lock()
			h.authedConns[remoteAddr] = trackedConn
			h.mu.Unlock()
			defer func() {
				h.mu.Lock()
				delete(h.authedConns, remoteAddr)
				h.mu.Unlock()
			}()
			h.config.OnAuthenticated(trackedConn, clientID)
		}
		return
	}

	if h.probeDetector != nil {
		h.probeDetector.RecordAuthFailure(remoteAddr)
	}

	h.stats.ProxiedConnections++
	h.proxyToSNI(conn, clientHello, sni)
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

	if len(body) >= 4 && body[0] == tlsHandshakeClientHello {
		hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
		totalNeeded := 4 + hsLen

		for len(body) < totalNeeded {
			var nextHeader [5]byte
			if _, err := io.ReadFull(conn, nextHeader[:]); err != nil {
				break
			}
			if nextHeader[0] != tlsRecordHandshake {
				break
			}
			nextLen := int(binary.BigEndian.Uint16(nextHeader[3:5]))
			if nextLen > 16384 {
				break
			}
			nextBody := make([]byte, nextLen)
			if _, err := io.ReadFull(conn, nextBody); err != nil {
				break
			}
			body = append(body, nextBody...)
		}
	}

	clientHello := make([]byte, 5+len(body))
	copy(clientHello, header)
	binary.BigEndian.PutUint16(clientHello[3:5], uint16(len(body)))
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

func (h *Handler) authenticateClient(clientRandom, sessionID []byte) (string, bool) {
	if len(h.privateKey) == 0 {
		log.Println("[Phantom] Auth rejected: no private key configured")
		return "", false
	}

	if len(clientRandom) != 32 || len(sessionID) != 32 {
		return "", false
	}

	replayKey := hex.EncodeToString(clientRandom) + hex.EncodeToString(sessionID)
	if h.isReplay(replayKey) {
		log.Printf("[Phantom] Auth rejected: replay attack detected")
		return "", false
	}

	rawTS := binary.BigEndian.Uint64(sessionID[0:8])
	if rawTS > uint64(math.MaxInt64) {
		log.Printf("[Phantom] Auth rejected: invalid timestamp (overflow)")
		return "", false
	}
	now := time.Now()
	diff := now.Sub(time.UnixMilli(int64(rawTS)))
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
		binary.BigEndian.PutUint64(ts, rawTS)
		mac.Write(ts)
		nonce := sessionID[8:12]
		mac.Write(nonce)
		return hmac.Equal(sessionID[12:32], mac.Sum(nil)[:20])
	}

	if h.config.GetUsers != nil {
		users := h.config.GetUsers()
		log.Debug("[Phantom] Auth: clientRandom=%s, checking %d users", hex.EncodeToString(clientRandom), len(users))
		for _, u := range users {
			log.Debug("[Phantom] Auth: checking user=%s", u.UserID)
			if !hmac.Equal(clientRandom, u.PublicKey[:]) {
				continue
			}
			sharedSecret, err := curve25519.X25519(h.privateKey, clientRandom)
			if err != nil {
				log.Debug("[Phantom] Auth FAILED: ECDH error for user=%s: %v", u.UserID, err)
				return "", false
			}
			if verifyHMAC(sharedSecret) {
				h.markAsSeen(replayKey)
				log.Printf("[Phantom] Auth SUCCESS: user=%s", u.UserID)
				return u.UserID, true
			}
			log.Debug("[Phantom] Auth FAILED: SessionID HMAC mismatch for user=%s", u.UserID)
			return "", false
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
	h.markAsSeen(replayKey)
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


func (h *Handler) proxyToSNI(clientConn net.Conn, clientHello []byte, sni string) {
	target := h.sniProxyTarget(sni)
	if target == "" {
		return
	}

	destConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(
		context.Background(), "tcp", target)
	if err != nil {
		log.Debug("proxyToSNI dial %s: %v", target, err)
		return
	}
	defer destConn.Close()

	if _, err := destConn.Write(clientHello); err != nil {
		return
	}

	deadline := time.Now().Add(5 * time.Minute)
	clientConn.SetDeadline(deadline)
	destConn.SetDeadline(deadline)

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(destConn, clientConn)
		destConn.SetReadDeadline(time.Now())
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, destConn)
		clientConn.SetReadDeadline(time.Now())
		done <- struct{}{}
	}()

	<-done
	<-done
}

func (h *Handler) sniProxyTarget(sni string) string {
	if sni == "" {
		return h.defaultDest()
	}

	h.sniMu.RLock()
	cur := h.currentSNI
	h.sniMu.RUnlock()
	if cur != "" && strings.EqualFold(sni, cur) {
		return net.JoinHostPort(sni, "443")
	}

	for _, allowed := range h.config.ServerNames {
		if strings.EqualFold(sni, allowed) {
			return net.JoinHostPort(sni, "443")
		}
	}

	h.sniMu.RLock()
	pool := h.sniDomains
	h.sniMu.RUnlock()
	for _, d := range pool {
		if strings.EqualFold(sni, d) {
			return net.JoinHostPort(sni, "443")
		}
	}

	destHost := h.destHost()
	if destHost != "" && strings.EqualFold(sni, destHost) {
		return h.defaultDest()
	}

	return ""
}

func (h *Handler) defaultDest() string {
	if h.config.Dest != "" {
		return h.config.Dest
	}
	return "cloudflare.com:443"
}

func (h *Handler) destHost() string {
	d := h.defaultDest()
	host, _, err := net.SplitHostPort(d)
	if err != nil {
		return d
	}
	return host
}

func (h *Handler) proxyToDestination(clientConn net.Conn, clientHello []byte) {
	h.proxyToSNI(clientConn, clientHello, h.destHost())
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

func isHTTP(b byte) bool {
	switch b {
	case 'G', 'P', 'C', 'H', 'O', 'D', 'T':
		return true
	}
	return false
}

func (h *Handler) handleHTTPFallback(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	if h.probeDetector != nil {
		h.probeDetector.RecordAuthFailure(remoteAddr)
	}

	dest := h.config.Dest
	if dest == "" {
		dest = "www.google.com:443"
	}
	destConn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", dest)
	if err != nil {
		time.Sleep(time.Duration(200+randInt(600)) * time.Millisecond)
		return
	}
	defer destConn.Close()

	deadline := time.Now().Add(30 * time.Second)
	conn.SetDeadline(deadline)
	destConn.SetDeadline(deadline)

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(destConn, conn)
		destConn.SetReadDeadline(time.Now())
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, destConn)
		conn.SetReadDeadline(time.Now())
		done <- struct{}{}
	}()
	<-done
	<-done
}

var _ = (*tls.Config)(nil)

type ObfuscatedConn struct {
	net.Conn
	mgr *obfuscation.IntegrationManager
}

// writeAdmissionError sends a short admission-denial marker to the client
// before closing the conn. The format is a single line prefixed with
// "WHISPERA-DENIED:" and terminated by '\n' so clients can distinguish it
// from normal smux garbage and surface the message verbatim.
func (h *Handler) writeAdmissionError(conn net.Conn, reason string) {
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if reason == "" {
		reason = "admission denied"
	}
	_, _ = conn.Write([]byte("WHISPERA-DENIED: " + reason + "\n"))
}

func (h *Handler) WrapWithObfuscation(conn net.Conn) net.Conn {
	wrapped := conn
	if h.config.EnableObfuscation && h.integrationMgr != nil {
		log.Printf("Applying Marionette messenger obfuscation to connection")
		wrapped = &ObfuscatedConn{
			Conn: wrapped,
			mgr:  h.integrationMgr,
		}
	}
	if h.config.EnableChatFSM {
		interval := h.config.ChatFSMCoverInterval
		if interval <= 0 {
			interval = 8 * time.Second
		}
		var chatID [4]byte
		_, _ = rand.Read(chatID[:])
		wrapped = marionette.NewChatFSMConn(wrapped, binary.BigEndian.Uint32(chatID[:]), interval)
		log.Printf("Applying chat-FSM framing (cover interval %s)", interval)
	}
	return wrapped
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
		"kion.ru",
		"rutube.ru",
		"dzen.ru",
		"music.yandex.ru",
		"cloud.mail.ru",
		"premier.one",
		"wink.ru",
		"ivi.ru",
		"start.ru",
		"more.tv",
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

func (h *Handler) coverTrafficLoop() {
	for {
		interval := time.Duration(5+randInt(25)) * time.Second
		select {
		case <-h.coverTrafficStop:
			return
		case <-time.After(interval):
			h.sendCoverTraffic()
		}
	}
}

func (h *Handler) sendCoverTraffic() {
	h.mu.RLock()
	conns := make([]net.Conn, 0, len(h.authedConns))
	for _, conn := range h.authedConns {
		conns = append(conns, conn)
	}
	h.mu.RUnlock()

	for _, conn := range conns {
		payloadSize := 32 + randInt(1400)
		record := make([]byte, 5+payloadSize)
		record[0] = 0x17
		record[1] = 0x03
		record[2] = 0x03
		record[3] = byte(payloadSize >> 8)
		record[4] = byte(payloadSize)
		rand.Read(record[5:])

		conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		conn.Write(record)
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

type prependConn struct {
	net.Conn
	buf []byte
}

func (p *prependConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
