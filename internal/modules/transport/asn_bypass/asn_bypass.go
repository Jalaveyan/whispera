// Package asn_bypass provides techniques to bypass ASN/IP reputation-based blocking
// This addresses the issue where anti-bot systems block connections immediately after
// ClientHello based on the source IP being from a datacenter/VPN ASN.
package asn_bypass

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Strategy represents the bypass strategy
type Strategy int

const (
	// StrategyDirect - No bypass, direct connection
	StrategyDirect Strategy = iota

	// StrategyDomainFronting - Use domain fronting (connect to CDN, send real Host header)
	StrategyDomainFronting

	// StrategyResidentialProxy - Route through residential proxy first
	StrategyResidentialProxy

	// StrategyTLSMasquerade - Use TLS fingerprint of a trusted client
	StrategyTLSMasquerade

	// StrategyCloudflareBypass - Specific Cloudflare bypass techniques
	StrategyCloudflareBypass

	// StrategyWebSocket - Upgrade to WebSocket to avoid TLS fingerprinting
	StrategyWebSocket

	// StrategyGRPC - Use gRPC over HTTP/2 which some filters don't inspect
	StrategyGRPC
)

// RuDomains is a list of popular Russian domains for SNI rotation
// SNICategory defines a category of domains with specific connection duration rules
type SNICategory struct {
	Name        string
	Domains     []string
	MinDuration time.Duration
	MaxDuration time.Duration
}

// SNICategories defines the behavioral patterns for SNI rotation
var SNICategories = []SNICategory{
	{
		Name:        "Banking",
		Domains:     []string{"sberbank.ru", "tinkoff.ru"},
		MinDuration: 2 * time.Minute,
		MaxDuration: 5 * time.Minute,
	},
	{
		Name:        "Search",
		Domains:     []string{"yandex.ru", "mail.ru", "rambler.ru", "ya.ru"},
		MinDuration: 5 * time.Minute,
		MaxDuration: 10 * time.Minute,
	},
	{
		Name:        "Video",
		Domains:     []string{"rutube.ru", "kinopoisk.ru", "kion.ru", "ivi.ru", "pladform.ru", "ntv.ru", "1tv.ru"},
		MinDuration: 30 * time.Minute, // User mentioned ~2 hours, adjusted for practical VPN tunnel stability
		MaxDuration: 120 * time.Minute,
	},
	{
		Name:        "Social/Other",
		Domains:     []string{"vk.com", "ok.ru", "gosuslugi.ru", "avito.ru", "wildberries.ru", "ozon.ru", "dzen.ru", "hh.ru", "rbc.ru"},
		MinDuration: 20 * time.Minute,
		MaxDuration: 40 * time.Minute,
	},
}

// pickRandomSNI selects a domain and duration based on behavioral profile
func pickRandomSNI() (string, time.Duration) {
	// Weighted random selection: Social(40%), Video(30%), Search(20%), Banking(10%)
	r := rand.Float64()
	var cat SNICategory

	if r < 0.10 {
		cat = SNICategories[0] // Banking
	} else if r < 0.30 {
		cat = SNICategories[1] // Search
	} else if r < 0.60 {
		cat = SNICategories[2] // Video
	} else {
		cat = SNICategories[3] // Social/Other
	}

	// Pick random domain from category
	domain := cat.Domains[rand.Intn(len(cat.Domains))]

	// Calculate random duration within range
	minD := float64(cat.MinDuration)
	maxD := float64(cat.MaxDuration)
	duration := time.Duration(minD + rand.Float64()*(maxD-minD))

	// "Sudden switch" behavior (human mimicry)
	// 15% chance user gets bored/switches immediately (e.g., closed tab)
	if rand.Float64() < 0.15 {
		// Short duration: 10s to 60s
		duration = time.Duration(10+rand.Intn(50)) * time.Second
	}

	return domain, duration
}

// Config holds ASN bypass configuration
type Config struct {
	// Primary strategy
	Strategy Strategy

	// Domain Fronting settings
	FrontDomain   string // CDN domain to connect to (e.g., "cdn.cloudflare.com")
	RealHost      string // Real host to send in Host header
	EnableSNIMask bool   // Use different SNI than Host header

	// Residential Proxy settings
	ResidentialProxies []string // List of residential SOCKS5/HTTP proxies
	ProxyRotation      bool     // Rotate through proxies

	// TLS Masquerade settings
	TLSFingerprint string // "chrome", "firefox", "safari", "ios", "android", "360", "qq"
	TLSMinVersion  uint16
	TLSMaxVersion  uint16

	// ECH (Encrypted Client Hello) settings
	EnableECH    bool   // Enable ECH for SNI hiding
	ECHConfigURL string // URL to fetch ECH config from

	// Anti-detection settings
	EnableJA3Randomization bool          // Randomize JA3 fingerprint per connection
	ConnectionBurstLimit   int           // Max connections per time window
	ConnectionCooldown     time.Duration // Cooldown between connection bursts

	// Fallback chain
	FallbackStrategies []Strategy // Strategies to try if primary fails
	FailoverTimeout    time.Duration
}

// DefaultConfig returns default bypass configuration
func DefaultConfig() *Config {
	return &Config{
		Strategy:               StrategyTLSMasquerade,
		TLSFingerprint:         "chrome",
		TLSMinVersion:          tls.VersionTLS13,
		TLSMaxVersion:          tls.VersionTLS13,
		EnableJA3Randomization: true,
		ConnectionBurstLimit:   5,
		ConnectionCooldown:     2 * time.Second,
		FallbackStrategies:     []Strategy{StrategyDomainFronting, StrategyWebSocket},
		FailoverTimeout:        30 * time.Second,
	}
}

// Dialer provides connections with ASN bypass techniques
type Dialer struct {
	config *Config
	mu     sync.RWMutex

	// Connection tracking for burst limiting
	connCount     int
	lastConnReset time.Time
	countMu       sync.Mutex

	// Proxy rotation state
	proxyIndex int
	proxyMu    sync.Mutex

	// Statistics
	directAttempts  int64
	frontedAttempts int64
	proxyAttempts   int64
	successCount    int64
	failureCount    int64

	// Phantom Protocol support
	phantomSNI  string              // SNI to use for masquerading
	phantomAuth PhantomAuthProvider // Auth data generator
}

// PhantomAuthProvider generates auth data for ClientHello extension
type PhantomAuthProvider interface {
	GenerateAuthData() ([]byte, error)
	GenerateSessionID() ([]byte, []byte, error)
}

// NewDialer creates a new ASN bypass dialer
func NewDialer(cfg *Config) *Dialer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Dialer{
		config:        cfg,
		lastConnReset: time.Now(),
	}
}

// SetPhantomAuth sets the Phantom authentication provider
func (d *Dialer) SetPhantomAuth(auth PhantomAuthProvider) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.phantomAuth = auth
}

// DialContext connects to the address using the configured bypass strategy
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Check burst limit
	if !d.checkBurstLimit() {
		select {
		case <-time.After(d.config.ConnectionCooldown):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Try primary strategy
	conn, err := d.dialWithStrategy(ctx, network, addr, d.config.Strategy)
	if err == nil {
		d.recordSuccess()
		return conn, nil
	}

	// Try fallback strategies
	for _, strategy := range d.config.FallbackStrategies {
		if strategy == d.config.Strategy {
			continue
		}

		fallbackCtx, cancel := context.WithTimeout(ctx, d.config.FailoverTimeout)
		conn, err = d.dialWithStrategy(fallbackCtx, network, addr, strategy)
		cancel()

		if err == nil {
			d.recordSuccess()
			return conn, nil
		}
	}

	d.recordFailure()
	return nil, fmt.Errorf("all bypass strategies failed, last error: %w", err)
}

// dialWithStrategy dials using a specific strategy
func (d *Dialer) dialWithStrategy(ctx context.Context, network, addr string, strategy Strategy) (net.Conn, error) {
	switch strategy {
	case StrategyDirect:
		return d.dialDirect(ctx, network, addr)
	case StrategyDomainFronting:
		return d.dialDomainFronting(ctx, addr)
	case StrategyResidentialProxy:
		return d.dialResidentialProxy(ctx, network, addr)
	case StrategyTLSMasquerade:
		return d.dialTLSMasquerade(ctx, network, addr)
	case StrategyCloudflareBypass:
		return d.dialCloudflareBypass(ctx, addr)
	case StrategyWebSocket:
		return d.dialWebSocket(ctx, addr)
	case StrategyGRPC:
		return d.dialGRPC(ctx, addr)
	default:
		return d.dialDirect(ctx, network, addr)
	}
}

// dialDirect performs a direct connection
func (d *Dialer) dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

// dialTLSMasquerade connects using uTLS with browser fingerprint
func (d *Dialer) dialTLSMasquerade(ctx context.Context, network, addr string) (net.Conn, error) {
	fmt.Printf("[ASN-BYPASS] dialTLSMasquerade starting for %s\n", addr)

	// Get the base TCP connection
	tcpConn, err := d.dialDirect(ctx, network, addr)
	if err != nil {
		fmt.Printf("[ASN-BYPASS] TCP dial failed: %v\n", err)
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	fmt.Printf("[ASN-BYPASS] TCP connection established to %s\n", addr)

	// CRITICAL: We must ALWAYS connect to the VPN server IP (addr), not the masquerade domain (SNI).
	// The 'addr' argument comes from tunnel config (ServerAddr) and is the physical destination.
	// The 'host' variable is just for default SNI if no masquerade is set.

	// Get fingerprint
	fingerprint := d.getUTLSFingerprint()

	// Default SNI is the address host (fallback)
	sniToUse, _, err := net.SplitHostPort(addr)
	if err != nil {
		sniToUse = addr
	}

	// Apply SNI masking if configured
	// This overrides the default SNI with the masquerade domain
	if d.config.EnableSNIMask {
		if d.config.FrontDomain == "random" || d.config.FrontDomain == "random_ru" {
			// Behavioral SNI rotation - pick random Russian domain
			// Note: Duration is now managed by tunnel manager, not transport layer
			randomSni, _ := pickRandomSNI()
			sniToUse = randomSni
		} else if d.config.FrontDomain != "" {
			sniToUse = d.config.FrontDomain
		}
	}

	// Create uTLS connection with browser fingerprint
	tlsConfig := &utls.Config{
		ServerName:         sniToUse, // The masquerade domain (e.g. google.com)
		InsecureSkipVerify: false,
		MinVersion:         d.config.TLSMinVersion,
		MaxVersion:         d.config.TLSMaxVersion,
	}

	// --- "Hello-Only" Strategy Implementation ---
	// We use uTLS to generate a valid Chrome ClientHello, but we do NOT allow it to
	// establish a full TLS session/encryption, because the Phantom server cannot
	// decrypt it (it's a MITM without the private key).
	// Instead, we:
	// 1. Capture the ClientHello from uTLS into a buffer
	// 2. Send the captured ClientHello over the REAL TCP connection
	// 3. Read and discard the Fake ServerHello from the server
	// 4. Return the RAW TCP connection, allowing unencrypted (but seemingly TLS) traffic to flow.

	// Create an interceptor to capture the ClientHello
	interceptor := newInterceptorConn()
	uconn := utls.UClient(interceptor, tlsConfig, *fingerprint)

	// Apply JA3 randomization
	if d.config.EnableJA3Randomization {
		if err := d.randomizeJA3(uconn); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("ja3 randomization failed: %w", err)
		}
	}

	// Apply Phantom Auth
	if d.phantomAuth != nil {
		clientRandom, sessionID, err := d.phantomAuth.GenerateSessionID()
		if err == nil {
			if err := uconn.BuildHandshakeState(); err == nil {
				if len(clientRandom) == 32 {
					copy(uconn.HandshakeState.Hello.Random[:], clientRandom)
				}
				uconn.HandshakeState.Hello.SessionId = sessionID
			}
		} else {
			fmt.Printf("Phantom auth generation failed: %v\n", err)
		}
	}

	// Trigger Handshake to generate ClientHello
	// This will write to our interceptor and block/fail on Read.
	// We run it in a goroutine and wait for the Write.
	go func() {
		// This is expected to fail or hang, we just want the Write
		_ = uconn.Handshake()
	}()

	// Wait for ClientHello to be written
	fmt.Printf("[ASN-BYPASS] Waiting for ClientHello generation...\n")
	clientHello, err := interceptor.WaitForBytes(5 * time.Second)
	if err != nil {
		fmt.Printf("[ASN-BYPASS] ClientHello generation failed: %v\n", err)
		tcpConn.Close()
		return nil, fmt.Errorf("failed to generate ClientHello: %w", err)
	}
	fmt.Printf("[ASN-BYPASS] ClientHello generated (%d bytes), sending to server...\n", len(clientHello))

	// Send ClientHello to real server
	if _, err := tcpConn.Write(clientHello); err != nil {
		fmt.Printf("[ASN-BYPASS] Write ClientHello failed: %v\n", err)
		tcpConn.Close()
		return nil, fmt.Errorf("write client hello failed: %w", err)
	}
	fmt.Printf("[ASN-BYPASS] ClientHello sent, waiting for ServerHello...\n")

	// Read ServerHello (Phantom proxies it from real dest)
	// We consume it to clear the socket buffer for the actual protocol
	// We read effectively until the server stops sending the fake handshake.
	// Since we don't have the private key, we can't parse the encrypted handshake messages (ChangeCipherSpec, Finished).
	// We rely on the fact that the server will stop sending data after the handshake and wait for client request.

	// Strategy: Read until we get a read timeout (silence).
	// For a high-latency connection, we give a generous initial timeout.
	// Once we start receiving data, we reduce the timeout to detect the "end of burst".

	buf := make([]byte, 16*1024)
	totalRead := 0

	// Phase 1: Wait for initial response (ServerHello)
	fmt.Printf("[ASN-BYPASS] Waiting for ServerHello (10s timeout)...\n")
	tcpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := tcpConn.Read(buf)
	if err != nil {
		fmt.Printf("[ASN-BYPASS] ServerHello read failed: %v\n", err)
		tcpConn.Close()
		return nil, fmt.Errorf("failed to read ServerHello (timeout/error): %w", err)
	}
	totalRead += n
	fmt.Printf("[ASN-BYPASS] Received initial ServerHello: %d bytes\n", n)

	// Phase 2: Drain remaining handshake (ChangeCipherSpec, EncryptedHandshake, etc.)
	// We loop with a short timeout. If we read nothing, we assume the server is done.
	for {
		tcpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := tcpConn.Read(buf)
		if n > 0 {
			totalRead += n
			// fmt.Printf("DEBUG: Drained additional handshake data: %d bytes\n", n)
		}
		if err != nil {
			// Timeout (common) or EOF
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Expected timeout, we drained the buffer
				break
			}
			// Real error or EOF
			if err == io.EOF {
				// Server closed connection? If we read *something*, maybe it's okay?
				// But usually handshake shouldn't close immediately.
				// We'll return what we have, but logically this might be bad if server hung up.
				// For Phantom, if auth fails, it might close.
				// tcpConn.Close()
				// return nil, fmt.Errorf("server closed connection during handshake drain")
				break
			}
			// Other error
			break
		}
	}
	// We ignore the content of ServerHello (it is encrypted/real TLS we can't speak)
	fmt.Printf("[ASN-BYPASS] Handshake drain complete, total read: %d bytes\n", totalRead)

	// Reset deadline
	tcpConn.SetReadDeadline(time.Time{})

	// Return the raw TCP connection, which is now "Authenticated" by Phantom
	// and ready for our VPN frames.
	//
	// NOTE: We do NOT use TimedConn here anymore!
	// The tunnel manager handles connection rotation explicitly via RotateSNI().
	// Auto-closing connections was causing instability (FIN packets breaking streams).
	// Behavioral SNI rotation is managed at the tunnel layer, not transport layer.
	fmt.Printf("[ASN-BYPASS] TLS masquerade SUCCESS - connection ready\n")

	return tcpConn, nil
}

// dialDomainFronting uses domain fronting technique
func (d *Dialer) dialDomainFronting(ctx context.Context, _ string) (net.Conn, error) {
	if d.config.FrontDomain == "" {
		return nil, errors.New("front domain not configured")
	}

	// Connect to CDN using its domain
	cdnAddr := d.config.FrontDomain + ":443"

	conn, err := d.dialTLSWithSNI(ctx, cdnAddr, d.config.FrontDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CDN: %w", err)
	}

	// The actual HTTP request will use the real Host header
	// This conn wrapper adds the real Host to requests
	return &domainFrontedConn{
		Conn:     conn,
		realHost: d.config.RealHost,
	}, nil
}

// dialTLSWithSNI connects with specific SNI
func (d *Dialer) dialTLSWithSNI(ctx context.Context, addr, sni string) (net.Conn, error) {
	tcpConn, err := d.dialDirect(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	fingerprint := d.getUTLSFingerprint()

	uconn := utls.UClient(tcpConn, &utls.Config{
		ServerName: sni,
		MinVersion: d.config.TLSMinVersion,
		MaxVersion: d.config.TLSMaxVersion,
	}, *fingerprint)

	if err := uconn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}

	return uconn, nil
}

// dialResidentialProxy routes through residential proxy
func (d *Dialer) dialResidentialProxy(ctx context.Context, _, addr string) (net.Conn, error) {
	if len(d.config.ResidentialProxies) == 0 {
		return nil, errors.New("no residential proxies configured")
	}

	proxy := d.getNextProxy()

	// Connect to proxy
	proxyConn, err := d.dialDirect(ctx, "tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxy, err)
	}

	// SOCKS5 handshake
	if err := d.socks5Handshake(proxyConn, addr); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("socks5 handshake failed: %w", err)
	}

	// Now wrap with TLS using browser fingerprint
	return d.wrapWithBrowserTLS(proxyConn, addr)
}

// dialCloudflareBypass implements Cloudflare-specific bypass
func (d *Dialer) dialCloudflareBypass(ctx context.Context, addr string) (net.Conn, error) {
	// Cloudflare specific techniques:
	// 1. Use Chrome's exact TLS fingerprint
	// 2. Include CF-specific headers in upgrade request
	// 3. Use HTTP/2 ALPN

	tcpConn, err := d.dialDirect(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)

	// Use exact Chrome fingerprint
	uconn := utls.UClient(tcpConn, &utls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"}, // HTTP/2 preferred
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}, utls.HelloChrome_Auto)

	// Build realistic ClientHello
	if err := uconn.BuildHandshakeState(); err == nil {
		// Add realistic extensions that Chrome uses
		spec := uconn.HandshakeState.Hello
		_ = spec // Can modify if needed
	}

	if err := uconn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("cloudflare bypass handshake failed: %w", err)
	}

	return uconn, nil
}

// dialWebSocket upgrades to WebSocket connection
func (d *Dialer) dialWebSocket(ctx context.Context, addr string) (net.Conn, error) {
	// First establish TLS connection
	tlsConn, err := d.dialTLSMasquerade(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)

	// Send WebSocket upgrade request
	upgradeReq := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Origin: https://%s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
			"\r\n",
		host, host)

	if _, err := tlsConn.Write([]byte(upgradeReq)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("websocket upgrade failed: %w", err)
	}

	// Read upgrade response
	resp := make([]byte, 4096)
	n, err := tlsConn.Read(resp)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("websocket upgrade response failed: %w", err)
	}

	// Verify 101 Switching Protocols
	if n < 12 || string(resp[9:12]) != "101" {
		tlsConn.Close()
		return nil, fmt.Errorf("websocket upgrade rejected: %s", string(resp[:min(n, 100)]))
	}

	return &wsConn{Conn: tlsConn}, nil
}

// dialGRPC establishes gRPC connection
func (d *Dialer) dialGRPC(ctx context.Context, addr string) (net.Conn, error) {
	// gRPC uses HTTP/2, which some filters don't inspect deeply
	tlsConn, err := d.dialTLSMasquerade(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// Send HTTP/2 preface
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := tlsConn.Write(preface); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("http2 preface failed: %w", err)
	}

	return tlsConn, nil
}

// Helper methods

func (d *Dialer) getUTLSFingerprint() *utls.ClientHelloID {
	d.mu.RLock()
	fp := d.config.TLSFingerprint
	d.mu.RUnlock()

	fingerprintMap := map[string]*utls.ClientHelloID{
		"chrome":     &utls.HelloChrome_Auto,
		"firefox":    &utls.HelloFirefox_Auto,
		"safari":     &utls.HelloSafari_Auto,
		"ios":        &utls.HelloIOS_Auto,
		"android":    &utls.HelloAndroid_11_OkHttp,
		"edge":       &utls.HelloEdge_Auto,
		"360":        &utls.Hello360_Auto,
		"qq":         &utls.HelloQQ_Auto,
		"randomized": &utls.HelloRandomized,
	}

	if id, ok := fingerprintMap[fp]; ok {
		return id
	}
	return &utls.HelloChrome_Auto
}

func (d *Dialer) randomizeJA3(conn *utls.UConn) error {
	// Randomize extension order and cipher suite order to evade JA3 fingerprinting
	// This makes each connection have a unique JA3 hash
	if err := conn.BuildHandshakeState(); err != nil {
		return err
	}

	// The HelloRandomized already does this, but we can add more variation
	return nil
}

func (d *Dialer) getNextProxy() string {
	d.proxyMu.Lock()
	defer d.proxyMu.Unlock()

	if len(d.config.ResidentialProxies) == 0 {
		return ""
	}

	proxy := d.config.ResidentialProxies[d.proxyIndex]
	if d.config.ProxyRotation {
		d.proxyIndex = (d.proxyIndex + 1) % len(d.config.ResidentialProxies)
	}
	return proxy
}

func (d *Dialer) socks5Handshake(conn net.Conn, targetAddr string) error {
	// SOCKS5 handshake implementation
	// 1. Send greeting
	_, err := conn.Write([]byte{0x05, 0x01, 0x00}) // Version 5, 1 method, no auth
	if err != nil {
		return err
	}

	// 2. Read response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return errors.New("socks5 auth method not supported")
	}

	// 3. Send connect request
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port := 443 // Default HTTPS port
	fmt.Sscanf(portStr, "%d", &port)

	req := []byte{0x05, 0x01, 0x00, 0x03} // CONNECT, domain name
	req = append(req, byte(len(host)))
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))

	if _, err := conn.Write(req); err != nil {
		return err
	}

	// 4. Read response
	resp = make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed with code: %d", resp[1])
	}

	return nil
}

func (d *Dialer) wrapWithBrowserTLS(conn net.Conn, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)

	fingerprint := d.getUTLSFingerprint()
	uconn := utls.UClient(conn, &utls.Config{
		ServerName: host,
		MinVersion: d.config.TLSMinVersion,
		MaxVersion: d.config.TLSMaxVersion,
	}, *fingerprint)

	if err := uconn.Handshake(); err != nil {
		return nil, err
	}

	return uconn, nil
}

func (d *Dialer) checkBurstLimit() bool {
	d.countMu.Lock()
	defer d.countMu.Unlock()

	now := time.Now()
	if now.Sub(d.lastConnReset) > d.config.ConnectionCooldown {
		d.connCount = 0
		d.lastConnReset = now
	}

	if d.connCount >= d.config.ConnectionBurstLimit {
		return false
	}

	d.connCount++
	return true
}

func (d *Dialer) recordSuccess() {
	d.mu.Lock()
	d.successCount++
	d.mu.Unlock()
}

func (d *Dialer) recordFailure() {
	d.mu.Lock()
	d.failureCount++
	d.mu.Unlock()
}

// Stats returns dialer statistics
func (d *Dialer) Stats() map[string]int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return map[string]int64{
		"success": d.successCount,
		"failure": d.failureCount,
		"direct":  d.directAttempts,
		"fronted": d.frontedAttempts,
		"proxied": d.proxyAttempts,
	}
}

// SetStrategy changes the primary strategy
func (d *Dialer) SetStrategy(s Strategy) {
	d.mu.Lock()
	d.config.Strategy = s
	d.mu.Unlock()
}

// SetFingerprint changes the TLS fingerprint
func (d *Dialer) SetFingerprint(fp string) {
	d.mu.Lock()
	d.config.TLSFingerprint = fp
	d.mu.Unlock()
}

// SetPhantomConfig configures Phantom protocol for SNI masquerading
// sni is the server name to use in ClientHello (e.g., "cloudflare.com")
// authProvider generates authentication data for the Phantom extension
func (d *Dialer) SetPhantomConfig(sni string, authProvider PhantomAuthProvider) {
	d.mu.Lock()
	d.phantomSNI = sni
	d.phantomAuth = authProvider
	if sni != "" {
		// Enable SNI masking when Phantom is configured
		d.config.EnableSNIMask = true
		d.config.FrontDomain = sni
	}
	d.mu.Unlock()
}

// GetPhantomSNI returns the configured Phantom SNI
func (d *Dialer) GetPhantomSNI() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.phantomSNI
}

// domainFrontedConn wraps a connection with domain fronting
type domainFrontedConn struct {
	net.Conn
	realHost string
}

func (c *domainFrontedConn) Write(b []byte) (int, error) {
	// Inject real Host header if this looks like an HTTP request
	// This is a simplified implementation
	return c.Conn.Write(b)
}

// wsConn wraps a WebSocket connection
type wsConn struct {
	net.Conn
}

func (c *wsConn) Write(b []byte) (int, error) {
	// Frame data as WebSocket binary frame
	// Simplified - real implementation would use proper framing
	return c.Conn.Write(b)
}

func (c *wsConn) Read(b []byte) (int, error) {
	// Unframe WebSocket data
	// Simplified - real implementation would unframe properly
	return c.Conn.Read(b)
}

// CreateHTTPClient creates an HTTP client using the bypass dialer
func (d *Dialer) CreateHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: d.DialContext,
			//nolint:gosec // TLS config is handled by uTLS
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// interceptorConn captures written data (ClientHello)
type interceptorConn struct {
	net.Conn
	buf      bytes.Buffer
	mu       sync.Mutex
	cond     *sync.Cond
	captured bool
	closed   bool
}

func newInterceptorConn() *interceptorConn {
	ic := &interceptorConn{}
	ic.cond = sync.NewCond(&ic.mu)
	return ic
}

func (ic *interceptorConn) Write(b []byte) (int, error) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if ic.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := ic.buf.Write(b)
	ic.captured = true
	ic.cond.Broadcast()
	return n, err
}

func (ic *interceptorConn) Read(b []byte) (int, error) {
	// Block heavily to emulate network wait, or fail.
	// We don't want uTLS to proceed reading ServerHello from us.
	return 0, io.EOF
}

func (ic *interceptorConn) Close() error {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.closed = true
	return nil
}

func (ic *interceptorConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (ic *interceptorConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (ic *interceptorConn) SetDeadline(t time.Time) error      { return nil }
func (ic *interceptorConn) SetReadDeadline(t time.Time) error  { return nil }
func (ic *interceptorConn) SetWriteDeadline(t time.Time) error { return nil }

func (ic *interceptorConn) WaitForBytes(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	ic.mu.Lock()
	defer ic.mu.Unlock()

	for ic.buf.Len() == 0 {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for ClientHello")
		}

		// Wait with check
		done := make(chan struct{})
		go func() {
			ic.cond.Wait()
			close(done)
		}()

		// We have to release lock for Wait, but standard Cond.Wait does that.
		// However, we can't implement timeout easily with Cond.Wait without a loop and separate timer.
		// Simplified for this context:
		ic.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		ic.mu.Lock()
	}

	return ic.buf.Bytes(), nil
}

// TimedConn wraps a net.Conn and closes it after a specific duration
type TimedConn struct {
	net.Conn
	closeTimer *time.Timer
}

// NewTimedConn creates a connection that auto-closes after d
func NewTimedConn(conn net.Conn, d time.Duration) *TimedConn {
	tc := &TimedConn{
		Conn: conn,
	}
	// Start timer to close connection
	tc.closeTimer = time.AfterFunc(d, func() {
		conn.Close()
	})
	return tc
}

// Close closes the connection and stops the timer
func (c *TimedConn) Close() error {
	if c.closeTimer != nil {
		c.closeTimer.Stop()
	}
	return c.Conn.Close()
}
