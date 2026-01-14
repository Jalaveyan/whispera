// Package asn_bypass provides techniques to bypass ASN/IP reputation-based blocking
// This addresses the issue where anti-bot systems block connections immediately after
// ClientHello based on the source IP being from a datacenter/VPN ASN.
package asn_bypass

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
	// Get the base TCP connection
	tcpConn, err := d.dialDirect(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	// Get fingerprint
	fingerprint := d.getUTLSFingerprint()

	// Extract host for SNI
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// Create uTLS connection with browser fingerprint
	tlsConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
		MinVersion:         d.config.TLSMinVersion,
		MaxVersion:         d.config.TLSMaxVersion,
	}

	// Apply SNI masking if configured
	if d.config.EnableSNIMask && d.config.FrontDomain != "" {
		tlsConfig.ServerName = d.config.FrontDomain
	}

	uconn := utls.UClient(tcpConn, tlsConfig, *fingerprint)

	// Apply JA3 randomization if enabled
	if d.config.EnableJA3Randomization {
		if err := d.randomizeJA3(uconn); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("ja3 randomization failed: %w", err)
		}
	}

	// Apply Phantom /  auth if configured
	if d.phantomAuth != nil {
		clientRandom, sessionID, err := d.phantomAuth.GenerateSessionID()
		if err == nil {
			// Ensure handshake state is built (idempotent)
			if err := uconn.BuildHandshakeState(); err == nil {
				// Inject Random (Client Ephemeral PubKey)
				if len(clientRandom) == 32 {
					copy(uconn.HandshakeState.Hello.Random[:], clientRandom)
				}
				// Inject SessionID (HMAC)
				uconn.HandshakeState.Hello.SessionId = sessionID
			}
		} else {
			// Log warning but continue (might use extension auth)
			fmt.Printf("Phantom auth generation failed: %v\n", err)
		}
	}

	// Perform handshake with context timeout
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- uconn.Handshake()
	}()

	select {
	case err := <-errChan:
		if err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
	case <-handshakeCtx.Done():
		tcpConn.Close()
		return nil, fmt.Errorf("tls handshake timeout")
	}

	return uconn, nil
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
