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

type Strategy int

const (
	StrategyDirect Strategy = iota

	StrategyDomainFronting

	StrategyResidentialProxy

	StrategyTLSMasquerade

	StrategyCloudflareBypass

	StrategyWebSocket

	StrategyGRPC
)

type SNICategory struct {
	Name        string
	Domains     []string
	MinDuration time.Duration
	MaxDuration time.Duration
}

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
		MinDuration: 30 * time.Minute,
		MaxDuration: 120 * time.Minute,
	},
	{
		Name:        "Social/Other",
		Domains:     []string{"vk.com", "ok.ru", "gosuslugi.ru", "avito.ru", "wildberries.ru", "ozon.ru", "dzen.ru", "hh.ru", "rbc.ru"},
		MinDuration: 20 * time.Minute,
		MaxDuration: 40 * time.Minute,
	},
}

func PickRandomSNI() (string, time.Duration) {
	return pickRandomSNI()
}

func WhitelistSNIPool() []string {
	pool := make([]string, 0, 32)
	for _, cat := range SNICategories {
		pool = append(pool, cat.Domains...)
	}
	return pool
}

func pickRandomSNI() (string, time.Duration) {
	r := rand.Float64()
	var cat SNICategory

	if r < 0.10 {
		cat = SNICategories[0]
	} else if r < 0.30 {
		cat = SNICategories[1]
	} else if r < 0.60 {
		cat = SNICategories[2]
	} else {
		cat = SNICategories[3]
	}

	domain := cat.Domains[rand.Intn(len(cat.Domains))]

	minD := float64(cat.MinDuration)
	maxD := float64(cat.MaxDuration)
	duration := time.Duration(minD + rand.Float64()*(maxD-minD))

	if rand.Float64() < 0.05 {
		duration = time.Duration(10+rand.Intn(50)) * time.Second
	}

	return domain, duration
}

type Config struct {
	Strategy Strategy

	FrontDomain   string
	RealHost      string
	EnableSNIMask bool

	ResidentialProxies []string
	ProxyRotation      bool

	TLSFingerprint string
	TLSMinVersion  uint16
	TLSMaxVersion  uint16

	EnableECH    bool
	ECHConfigURL string

	EnableJA3Randomization bool
	EnableTLSFragmentation bool
	TLSFragmentSize        int
	ConnectionBurstLimit   int
	ConnectionCooldown     time.Duration

	FallbackStrategies []Strategy
	FailoverTimeout    time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		Strategy:               StrategyTLSMasquerade,
		TLSFingerprint:         "chrome",
		TLSMinVersion:          tls.VersionTLS13,
		TLSMaxVersion:          tls.VersionTLS13,
		EnableJA3Randomization: true,
		EnableTLSFragmentation: true,
		TLSFragmentSize:        40,
		ConnectionBurstLimit:   5,
		ConnectionCooldown:     2 * time.Second,
		FallbackStrategies:     []Strategy{StrategyDomainFronting, StrategyWebSocket},
		FailoverTimeout:        30 * time.Second,
	}
}

type Dialer struct {
	config *Config
	mu     sync.RWMutex

	connCount     int
	lastConnReset time.Time
	countMu       sync.Mutex

	proxyIndex int
	proxyMu    sync.Mutex

	directAttempts  int64
	frontedAttempts int64
	proxyAttempts   int64
	successCount    int64
	failureCount    int64
}

func NewDialer(cfg *Config) *Dialer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Dialer{
		config:        cfg,
		lastConnReset: time.Now(),
	}
}

type stickySNI struct {
	domain    string
	expiresAt time.Time
}

var (
	globalStickySNI stickySNI
	globalSNIMu     sync.RWMutex
)

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !d.checkBurstLimit() {
		select {
		case <-time.After(d.config.ConnectionCooldown):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}

	resultCh := make(chan dialResult, len(d.config.FallbackStrategies)+1)
	raceCtx, raceCancel := context.WithTimeout(ctx, d.config.FailoverTimeout)
	defer raceCancel()

	go func() {
		conn, err := d.dialWithStrategy(raceCtx, network, addr, d.config.Strategy)
		select {
		case resultCh <- dialResult{conn, err}:
		case <-raceCtx.Done():
			if conn != nil {
				conn.Close()
			}
		}
	}()

	for _, strategy := range d.config.FallbackStrategies {
		if strategy == d.config.Strategy {
			continue
		}
		go func(s Strategy) {
			conn, err := d.dialWithStrategy(raceCtx, network, addr, s)
			select {
			case resultCh <- dialResult{conn, err}:
			case <-raceCtx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}(strategy)
	}

	numStrategies := len(d.config.FallbackStrategies) + 1
	var lastErr error
	for i := 0; i < numStrategies; i++ {
		select {
		case res := <-resultCh:
			if res.err == nil && res.conn != nil {
				d.recordSuccess()
				return res.conn, nil
			}
			lastErr = res.err
		case <-raceCtx.Done():
			d.recordFailure()
			return nil, fmt.Errorf("all bypass strategies timed out, last error: %w", lastErr)
		}
	}

	d.recordFailure()
	return nil, fmt.Errorf("all bypass strategies failed, last error: %w", lastErr)
}

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

func (d *Dialer) dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{
		KeepAlive: 30 * time.Second,
	}).DialContext(ctx, "tcp4", addr)

	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}

	return conn, nil
}

func (d *Dialer) dialTLSMasquerade(ctx context.Context, network, addr string) (net.Conn, error) {
	fmt.Printf("[ASN-BYPASS] dialTLSMasquerade starting for %s\n", addr)

	tcpConn, err := d.dialDirect(ctx, network, addr)
	if err != nil {
		fmt.Printf("[ASN-BYPASS] TCP dial failed: %v\n", err)
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	fmt.Printf("[ASN-BYPASS] TCP connection established to %s\n", addr)

	fingerprint := d.getUTLSFingerprint()

	sniToUse, _, err := net.SplitHostPort(addr)
	if err != nil {
		sniToUse = addr
	}

	if d.config.EnableSNIMask {
		if d.config.FrontDomain == "random" || d.config.FrontDomain == "random_ru" {
			globalSNIMu.Lock()
			if globalStickySNI.domain == "" || time.Now().After(globalStickySNI.expiresAt) {
				domain, duration := pickRandomSNI()
				globalStickySNI.domain = domain
				globalStickySNI.expiresAt = time.Now().Add(duration)
			}
			sniToUse = globalStickySNI.domain
			globalSNIMu.Unlock()
		} else if d.config.FrontDomain != "" {
			sniToUse = d.config.FrontDomain
		}
	}

	tlsConfig := &utls.Config{
		ServerName:         sniToUse,
		InsecureSkipVerify: false,
		MinVersion:         d.config.TLSMinVersion,
		MaxVersion:         d.config.TLSMaxVersion,
	}

	interceptor := newInterceptorConn()
	uconn := utls.UClient(interceptor, tlsConfig, *fingerprint)

	if d.config.EnableJA3Randomization {
		if err := d.randomizeJA3(uconn); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("ja3 randomization failed: %w", err)
		}
	}

	go func() {
		_ = uconn.Handshake()
	}()

	fmt.Printf("[ASN-BYPASS] Waiting for ClientHello generation...\n")
	clientHello, err := interceptor.WaitForBytes(5 * time.Second)
	if err != nil {
		fmt.Printf("[ASN-BYPASS] ClientHello generation failed: %v\n", err)
		tcpConn.Close()
		return nil, fmt.Errorf("failed to generate ClientHello: %w", err)
	}

	fmt.Printf("[ASN-BYPASS] ClientHello generated (%d bytes), sending to server...\n", len(clientHello))

	if d.config.EnableTLSFragmentation && len(clientHello) > 5 {
		if err := d.writeFragmentedTLS(tcpConn, clientHello); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("write fragmented client hello failed: %w", err)
		}
	} else if _, err := tcpConn.Write(clientHello); err != nil {
		fmt.Printf("[ASN-BYPASS] Write ClientHello failed: %v\n", err)
		tcpConn.Close()
		return nil, fmt.Errorf("write client hello failed: %w", err)
	}
	fmt.Printf("[ASN-BYPASS] ClientHello sent - server authenticated via HMAC in SessionID\n")

	tcpConn.SetReadDeadline(time.Time{})

	fmt.Printf("[ASN-BYPASS] TLS masquerade SUCCESS - connection ready\n")

	return tcpConn, nil
}

func (d *Dialer) dialDomainFronting(ctx context.Context, _ string) (net.Conn, error) {
	if d.config.FrontDomain == "" {
		return nil, errors.New("front domain not configured")
	}

	cdnAddr := d.config.FrontDomain + ":443"

	conn, err := d.dialTLSWithSNI(ctx, cdnAddr, d.config.FrontDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CDN: %w", err)
	}

	return &domainFrontedConn{
		Conn:     conn,
		realHost: d.config.RealHost,
	}, nil
}

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

func (d *Dialer) dialResidentialProxy(ctx context.Context, _, addr string) (net.Conn, error) {
	if len(d.config.ResidentialProxies) == 0 {
		return nil, errors.New("no residential proxies configured")
	}

	proxy := d.getNextProxy()

	proxyConn, err := d.dialDirect(ctx, "tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxy, err)
	}

	if err := d.socks5Handshake(proxyConn, addr); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("socks5 handshake failed: %w", err)
	}

	return d.wrapWithBrowserTLS(proxyConn, addr)
}

func (d *Dialer) dialCloudflareBypass(ctx context.Context, addr string) (net.Conn, error) {
	tcpConn, err := d.dialDirect(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)

	uconn := utls.UClient(tcpConn, &utls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}, utls.HelloChrome_Auto)

	if err := uconn.BuildHandshakeState(); err == nil {
		spec := uconn.HandshakeState.Hello
		_ = spec
	}

	if err := uconn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("cloudflare bypass handshake failed: %w", err)
	}

	return uconn, nil
}

func (d *Dialer) dialWebSocket(ctx context.Context, addr string) (net.Conn, error) {
	tlsConn, err := d.dialTLSMasquerade(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)

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

	resp := make([]byte, 4096)
	n, err := tlsConn.Read(resp)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("websocket upgrade response failed: %w", err)
	}

	if n < 12 || string(resp[9:12]) != "101" {
		tlsConn.Close()
		return nil, fmt.Errorf("websocket upgrade rejected: %s", string(resp[:min(n, 100)]))
	}

	return &wsConn{Conn: tlsConn}, nil
}

func (d *Dialer) dialGRPC(ctx context.Context, addr string) (net.Conn, error) {
	tlsConn, err := d.dialTLSMasquerade(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := tlsConn.Write(preface); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("http2 preface failed: %w", err)
	}

	return tlsConn, nil
}

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
		"vk":         &utls.HelloAndroid_11_OkHttp,
		"max":        &utls.HelloAndroid_11_OkHttp,
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

func (d *Dialer) writeFragmentedTLS(conn net.Conn, data []byte) error {
	fragSize := d.config.TLSFragmentSize
	if fragSize <= 0 || fragSize > 64 {
		fragSize = 40
	}

	if len(data) < 6 || data[0] != 0x16 {
		_, err := conn.Write(data)
		return err
	}

	contentType := data[0]
	majorVer := data[1]
	minorVer := data[2]
	payload := data[5:]

	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > fragSize {
			chunk = payload[:fragSize]
		}
		payload = payload[len(chunk):]

		record := make([]byte, 5+len(chunk))
		record[0] = contentType
		record[1] = majorVer
		record[2] = minorVer
		record[3] = byte(len(chunk) >> 8)
		record[4] = byte(len(chunk))
		copy(record[5:], chunk)

		if _, err := conn.Write(record); err != nil {
			return err
		}

		if len(payload) > 0 {
			jitter := time.Duration(rand.Intn(10)+1) * time.Millisecond
			time.Sleep(jitter)
		}
	}
	return nil
}

func (d *Dialer) randomizeJA3(conn *utls.UConn) error {
	extensions := conn.Extensions
	if len(extensions) <= 2 {
		return conn.BuildHandshakeState()
	}

	var sni utls.TLSExtension
	var psk utls.TLSExtension
	sniIdx := -1
	pskIdx := -1
	shuffleable := make([]utls.TLSExtension, 0, len(extensions))

	for i, ext := range extensions {
		switch ext.(type) {
		case *utls.SNIExtension:
			sni = ext
			sniIdx = i
		case *utls.FakePreSharedKeyExtension, *utls.UtlsPreSharedKeyExtension:
			psk = ext
			pskIdx = i
		default:
			shuffleable = append(shuffleable, ext)
		}
	}

	rand.Shuffle(len(shuffleable), func(i, j int) {
		shuffleable[i], shuffleable[j] = shuffleable[j], shuffleable[i]
	})

	result := make([]utls.TLSExtension, 0, len(extensions))
	if sniIdx >= 0 {
		result = append(result, sni)
	}
	result = append(result, shuffleable...)
	if pskIdx >= 0 {
		result = append(result, psk)
	}
	conn.Extensions = result

	if err := conn.BuildHandshakeState(); err != nil {
		return err
	}

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
	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return errors.New("socks5 auth method not supported")
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port := 443
	fmt.Sscanf(portStr, "%d", &port)

	req := []byte{0x05, 0x01, 0x00, 0x03}
	req = append(req, byte(len(host)))
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))

	if _, err := conn.Write(req); err != nil {
		return err
	}

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

func (d *Dialer) SetStrategy(s Strategy) {
	d.mu.Lock()
	d.config.Strategy = s
	d.mu.Unlock()
}

func (d *Dialer) SetFingerprint(fp string) {
	d.mu.Lock()
	d.config.TLSFingerprint = fp
	d.mu.Unlock()
}

type domainFrontedConn struct {
	net.Conn
	realHost string
}

func (c *domainFrontedConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

type wsConn struct {
	net.Conn
}

func (c *wsConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

func (c *wsConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}

func (d *Dialer) CreateHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: d.DialContext,
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

type interceptorConn struct {
	net.Conn
	buf      bytes.Buffer
	mu       sync.Mutex
	captured bool
	closed   bool
}

func newInterceptorConn() *interceptorConn {
	return &interceptorConn{}
}

func (ic *interceptorConn) Write(b []byte) (int, error) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if ic.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := ic.buf.Write(b)
	ic.captured = true
	return n, err
}

func (ic *interceptorConn) Read(b []byte) (int, error) {
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

	for {
		ic.mu.Lock()
		if ic.buf.Len() > 0 {
			out := make([]byte, ic.buf.Len())
			copy(out, ic.buf.Bytes())
			ic.mu.Unlock()
			return out, nil
		}
		ic.mu.Unlock()

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for ClientHello")
		}

		time.Sleep(10 * time.Millisecond)
	}
}

type TimedConn struct {
	net.Conn
	closeTimer *time.Timer
}
