package mtproto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
)

const (
	TSPUModuleName    = "transport.mtproto.tspu"
	TSPUModuleVersion = "1.0.0"
)

var _ = registerTSPUFactory()

func registerTSPUFactory() bool {
	registry.GlobalFactoryRegistry.RegisterFactory(TSPUModuleName, TSPUFactory)
	return true
}

type TSPUConfig struct {
	Secret         string
	ListenAddr     string
	TargetAddr     string
	DCAddresses    map[int]string
	EnableFakeTLS  bool
	Domains        []string
	PollutionRate  int
	DecoyWorkers   int
	RotateInterval time.Duration
	JitterMin      time.Duration
	JitterMax      time.Duration
	BurstSize      int
	BurstInterval  time.Duration
}

func DefaultTSPUConfig() *TSPUConfig {
	return &TSPUConfig{
		DCAddresses: map[int]string{
			1: "149.154.175.50:443",
			2: "149.154.167.51:443",
			3: "149.154.175.100:443",
			4: "149.154.167.91:443",
			5: "91.108.56.100:443",
		},
		EnableFakeTLS: true,
		Domains: []string{
			"google.com", "youtube.com", "facebook.com", "cloudflare.com",
			"amazon.com", "microsoft.com", "apple.com", "netflix.com",
			"instagram.com", "twitter.com", "linkedin.com", "github.com",
			"stackoverflow.com", "reddit.com", "wikipedia.org",
		},
		PollutionRate:  50,
		DecoyWorkers:   4,
		RotateInterval: 90 * time.Second,
		JitterMin:      5 * time.Millisecond,
		JitterMax:      150 * time.Millisecond,
		BurstSize:      8,
		BurstInterval:  500 * time.Millisecond,
	}
}

func (c *TSPUConfig) Validate() error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required")
	}
	if len(c.Secret) < 32 {
		return fmt.Errorf("secret must be at least 32 characters")
	}
	if c.PollutionRate < 1 {
		c.PollutionRate = 50
	}
	if c.DecoyWorkers < 1 {
		c.DecoyWorkers = 4
	}
	if len(c.Domains) == 0 {
		c.Domains = DefaultTSPUConfig().Domains
	}
	return nil
}

type TSPUPressure struct {
	*base.Module
	config *TSPUConfig
	secret *ParsedSecret

	mu       sync.RWMutex
	listener net.Listener
	acceptCh chan net.Conn
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	domainIdx    uint32
	currentEpoch uint64

	pollutionSent uint64
	decoysServed  uint64
	realConns     uint64
	activeConns   int32
	bytesIn       uint64
	bytesOut      uint64
	stateEntries  uint64
}

func NewTSPUPressure(cfg *TSPUConfig) (*TSPUPressure, error) {
	if cfg == nil {
		cfg = DefaultTSPUConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	secret, err := ParseSecret(cfg.Secret)
	if err != nil {
		return nil, fmt.Errorf("invalid secret: %w", err)
	}

	return &TSPUPressure{
		Module:   base.NewModule(TSPUModuleName, TSPUModuleVersion, nil),
		config:   cfg,
		secret:   secret,
		acceptCh: make(chan net.Conn, 256),
		stopCh:   make(chan struct{}),
	}, nil
}

func (t *TSPUPressure) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	return t.Module.Init(ctx, cfg)
}

func (t *TSPUPressure) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	if t.config.ListenAddr != "" {
		listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", t.config.ListenAddr)
		if err != nil {
			t.SetHealthy(false, fmt.Sprintf("listen failed: %v", err))
			return fmt.Errorf("listen failed: %w", err)
		}
		t.mu.Lock()
		t.listener = listener
		t.mu.Unlock()

		t.wg.Add(1)
		go t.acceptLoop()
	}

	t.wg.Add(1)
	go t.domainRotator()

	for i := 0; i < t.config.DecoyWorkers; i++ {
		t.wg.Add(1)
		go t.decoyWorker()
	}

	if t.config.TargetAddr != "" {
		t.wg.Add(1)
		go t.stateTablePolluter()
	}

	t.SetHealthy(true, "tspu pressure active")
	log.Info("TSPU pressure started (workers=%d, pollution_rate=%d/s, domains=%d)",
		t.config.DecoyWorkers, t.config.PollutionRate, len(t.config.Domains))
	return nil
}

func (t *TSPUPressure) Stop() error {
	t.stopOnce.Do(func() { close(t.stopCh) })
	t.mu.Lock()
	if t.listener != nil {
		t.listener.Close()
		t.listener = nil
	}
	t.mu.Unlock()
	t.wg.Wait()
	return t.Module.Stop()
}

func (t *TSPUPressure) Type() interfaces.TransportType {
	return interfaces.TransportMTProto
}

func (t *TSPUPressure) Listen(addr string) error { return nil }

func (t *TSPUPressure) Dial(ctx context.Context, addr string) (net.Conn, error) {
	jitter := t.randomJitter()
	select {
	case <-time.After(jitter):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	domain := t.currentDomain()
	session := t.newPressureSession(domain)
	if err := session.HandshakeWithServer(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tspu handshake failed: %w", err)
	}

	atomic.AddUint64(&t.realConns, 1)
	atomic.AddInt32(&t.activeConns, 1)

	return &tspuConn{
		Conn:    conn,
		session: session,
		onClose: func() { atomic.AddInt32(&t.activeConns, -1) },
	}, nil
}

func (t *TSPUPressure) Accept() (net.Conn, error) {
	conn, ok := <-t.acceptCh
	if !ok {
		return nil, fmt.Errorf("transport closed")
	}
	return conn, nil
}

func (t *TSPUPressure) Close() error {
	return t.Stop()
}

func (t *TSPUPressure) acceptLoop() {
	defer t.wg.Done()
	for {
		t.mu.RLock()
		listener := t.listener
		t.mu.RUnlock()
		if listener == nil {
			return
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-t.stopCh:
				return
			default:
				log.Warn("TSPU accept error: %v", err)
				continue
			}
		}

		atomic.AddInt32(&t.activeConns, 1)
		go t.handleInbound(conn)
	}
}

func (t *TSPUPressure) handleInbound(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		atomic.AddInt32(&t.activeConns, -1)
	}()

	clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	header := make([]byte, nonceLen)
	if _, err := readFull(clientConn, header); err != nil {
		t.serveDecoy(clientConn)
		return
	}

	if t.secret.Type == "faketls" && header[0] == fakeTLSClientHello {
		session, err := t.handleFakeTLSPressure(clientConn, header)
		if err != nil {
			t.serveDecoy(clientConn)
			return
		}

		clientConn.SetDeadline(time.Time{})
		atomic.AddUint64(&t.realConns, 1)

		wrapped := &tspuConn{
			Conn:    clientConn,
			session: session,
			onClose: func() {},
		}

		select {
		case t.acceptCh <- wrapped:
		default:
			log.Warn("TSPU accept channel full")
		}
		return
	}

	session := NewMTProtoSession(t.secret.Secret)
	if err := session.DecryptHeader(header); err != nil {
		t.serveDecoy(clientConn)
		return
	}

	clientConn.SetDeadline(time.Time{})
	atomic.AddUint64(&t.realConns, 1)

	wrapped := &tspuConn{
		Conn:    clientConn,
		session: session,
		onClose: func() {},
	}

	select {
	case t.acceptCh <- wrapped:
	default:
		log.Warn("TSPU accept channel full")
	}
}

func (t *TSPUPressure) handleFakeTLSPressure(conn net.Conn, header []byte) (*MTProtoSession, error) {
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen > 16384 {
		return nil, fmt.Errorf("record too large")
	}
	tlsData := make([]byte, recordLen)
	if _, err := readFull(conn, tlsData); err != nil {
		return nil, err
	}
	if len(tlsData) < 34 {
		return nil, fmt.Errorf("invalid ClientHello")
	}

	random := tlsData[6:38]
	session := NewMTProtoSession(t.secret.Secret)
	if err := session.VerifyFakeTLS(random, t.secret.Domain); err != nil {
		return nil, err
	}

	serverHello := t.buildServerHello()
	if _, err := conn.Write(serverHello); err != nil {
		return nil, err
	}

	return session, nil
}

func (t *TSPUPressure) buildServerHello() []byte {
	hello := []byte{0x16, 0x03, 0x03, 0x00, 0x3B, 0x02, 0x00, 0x00, 0x37, 0x03, 0x03}
	random := make([]byte, 32)
	rand.Read(random)
	hello = append(hello, random...)
	hello = append(hello, 0x00, 0x13, 0x01, 0x00, 0x00, 0x05, 0x00, 0x17, 0x00, 0x00, 0x00)
	return hello
}

func (t *TSPUPressure) serveDecoy(conn net.Conn) {
	atomic.AddUint64(&t.decoysServed, 1)

	domain := t.currentDomain()
	response := t.generateDecoyResponse(domain)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(response)
}

func (t *TSPUPressure) generateDecoyResponse(domain string) []byte {
	serverHello := make([]byte, 0, 256)
	serverHello = append(serverHello, 0x16, 0x03, 0x03)

	random := make([]byte, 32)
	rand.Read(random)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	body := []byte{0x02, 0x00, 0x00, 0x00, 0x03, 0x03}
	body = append(body, random...)
	body = append(body, 0x20)
	body = append(body, sessionID...)

	ciphers := [][]byte{{0x13, 0x01}, {0x13, 0x02}, {0x13, 0x03}, {0xc0, 0x2f}, {0xc0, 0x30}}
	idx := cryptoRandIntn(len(ciphers))
	body = append(body, ciphers[idx]...)
	body = append(body, 0x00)

	sni := []byte(domain)
	extPayload := []byte{0x00, 0x00}
	sniLen := len(sni)
	listLen := 3 + sniLen
	extLen := 2 + listLen
	extPayload = append(extPayload, byte(extLen>>8), byte(extLen))
	extPayload = append(extPayload, byte(listLen>>8), byte(listLen))
	extPayload = append(extPayload, 0x00)
	extPayload = append(extPayload, byte(sniLen>>8), byte(sniLen))
	extPayload = append(extPayload, sni...)

	body = append(body, byte(len(extPayload)>>8), byte(len(extPayload)))
	body = append(body, extPayload...)

	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)-4))
	serverHello = append(serverHello, byte(len(body)>>8), byte(len(body)))
	serverHello = append(serverHello, body...)

	return serverHello
}

func (t *TSPUPressure) stateTablePolluter() {
	defer t.wg.Done()

	interval := time.Second / time.Duration(t.config.PollutionRate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.sendPollutionBurst()
		}
	}
}

func (t *TSPUPressure) sendPollutionBurst() {
	burstSize := t.config.BurstSize + cryptoRandIntn(t.config.BurstSize/2+1)
	for i := 0; i < burstSize; i++ {
		go t.sendPollutionPacket()
	}
}

func (t *TSPUPressure) sendPollutionPacket() {
	domain := t.currentDomain()
	addr := t.config.TargetAddr

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return
	}

	jitter := t.randomJitter()
	time.Sleep(jitter)

	hello := t.buildPollutionClientHello(domain)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write(hello)

	atomic.AddUint64(&t.pollutionSent, 1)
	atomic.AddUint64(&t.stateEntries, 1)

	drainTime := 200 + cryptoRandIntn(800)
	time.Sleep(time.Duration(drainTime) * time.Millisecond)

	buf := make([]byte, 4096)
	_, _ = conn.Read(buf)

	closeDelay := 100 + cryptoRandIntn(2000)
	time.Sleep(time.Duration(closeDelay) * time.Millisecond)
	conn.Close()
}

func (t *TSPUPressure) buildPollutionClientHello(domain string) []byte {
	hello := make([]byte, 0, 512)
	hello = append(hello, 0x16, 0x03, 0x01)

	random := make([]byte, 32)
	rand.Read(random)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	body := []byte{0x01, 0x00, 0x00, 0x00, 0x03, 0x03}
	body = append(body, random...)
	body = append(body, 0x20)
	body = append(body, sessionID...)

	allCiphers := []uint16{
		0x1301, 0x1302, 0x1303,
		0xc02b, 0xc02f, 0xc02c, 0xc030,
		0xcca9, 0xcca8,
		0xc013, 0xc014,
		0x009c, 0x009d,
		0x002f, 0x0035,
	}
	numCiphers := 4 + cryptoRandIntn(len(allCiphers)-4)
	used := make(map[int]bool)
	var selected []uint16
	for len(selected) < numCiphers {
		idx := cryptoRandIntn(len(allCiphers))
		if !used[idx] {
			used[idx] = true
			selected = append(selected, allCiphers[idx])
		}
	}

	cipherBytes := make([]byte, len(selected)*2)
	for i, s := range selected {
		binary.BigEndian.PutUint16(cipherBytes[i*2:], s)
	}
	body = append(body, byte(len(cipherBytes)>>8), byte(len(cipherBytes)))
	body = append(body, cipherBytes...)
	body = append(body, 0x01, 0x00)

	extensions := t.buildPollutionExtensions(domain)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)-4))

	hello = append(hello, byte(len(body)>>8), byte(len(body)))
	hello = append(hello, body...)

	return hello
}

func (t *TSPUPressure) buildPollutionExtensions(domain string) []byte {
	ext := make([]byte, 0, 256)

	sni := []byte(domain)
	sniNameLen := len(sni)
	sniListLen := 3 + sniNameLen
	sniExtLen := 2 + sniListLen
	ext = append(ext, 0x00, 0x00)
	ext = append(ext, byte(sniExtLen>>8), byte(sniExtLen))
	ext = append(ext, byte(sniListLen>>8), byte(sniListLen))
	ext = append(ext, 0x00)
	ext = append(ext, byte(sniNameLen>>8), byte(sniNameLen))
	ext = append(ext, sni...)

	ext = append(ext, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18)

	ext = append(ext, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)

	ext = append(ext, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
		0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
		0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
		0x02, 0x01)

	alpnProtos := [][]byte{
		{0x02, 'h', '2'},
		{0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'},
	}
	alpnListLen := 0
	for _, p := range alpnProtos {
		alpnListLen += len(p)
	}
	alpnExtLen := 2 + alpnListLen
	ext = append(ext, 0x00, 0x10)
	ext = append(ext, byte(alpnExtLen>>8), byte(alpnExtLen))
	ext = append(ext, byte(alpnListLen>>8), byte(alpnListLen))
	for _, p := range alpnProtos {
		ext = append(ext, p...)
	}

	grease := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a}
	greaseVal := grease[cryptoRandIntn(len(grease))]
	ext = append(ext, byte(greaseVal>>8), byte(greaseVal), 0x00, 0x01, 0x00)

	padding := make([]byte, 16+cryptoRandIntn(64))
	rand.Read(padding)
	ext = append(ext, 0x00, 0x15)
	ext = append(ext, byte(len(padding)>>8), byte(len(padding)))
	ext = append(ext, padding...)

	return ext
}

func (t *TSPUPressure) decoyWorker() {
	defer t.wg.Done()

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		jitter := time.Duration(500+cryptoRandIntn(2000)) * time.Millisecond
		select {
		case <-t.stopCh:
			return
		case <-time.After(jitter):
		}

		if t.config.TargetAddr == "" {
			continue
		}

		t.sendDecoyHandshake()
	}
}

func (t *TSPUPressure) sendDecoyHandshake() {
	domain := t.currentDomain()
	addr := t.config.TargetAddr

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	hello := t.buildPollutionClientHello(domain)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(hello)

	buf := make([]byte, 8192)
	_, _ = conn.Read(buf)

	atomic.AddUint64(&t.decoysServed, 1)

	extraData := make([]byte, 64+cryptoRandIntn(256))
	rand.Read(extraData)

	record := []byte{0x17, 0x03, 0x03}
	record = append(record, byte(len(extraData)>>8), byte(len(extraData)))
	record = append(record, extraData...)

	conn.Write(record)
	time.Sleep(time.Duration(100+cryptoRandIntn(500)) * time.Millisecond)
}

func (t *TSPUPressure) domainRotator() {
	defer t.wg.Done()

	rotateInterval := t.config.RotateInterval
	if rotateInterval < 10*time.Second {
		rotateInterval = 10 * time.Second
	}

	ticker := time.NewTicker(rotateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			idx := atomic.AddUint32(&t.domainIdx, 1)
			atomic.AddUint64(&t.currentEpoch, 1)
			domain := t.config.Domains[int(idx)%len(t.config.Domains)]
			log.Debug("TSPU domain rotated to %s (epoch %d)", domain, atomic.LoadUint64(&t.currentEpoch))
		}
	}
}

func (t *TSPUPressure) currentDomain() string {
	idx := atomic.LoadUint32(&t.domainIdx)
	return t.config.Domains[int(idx)%len(t.config.Domains)]
}

func (t *TSPUPressure) newPressureSession(domain string) *MTProtoSession {
	secret := t.deriveEpochSecret(domain)
	return NewMTProtoSession(secret)
}

func (t *TSPUPressure) deriveEpochSecret(domain string) []byte {
	epoch := atomic.LoadUint64(&t.currentEpoch)
	h := sha256.New()
	h.Write(t.secret.Secret)
	h.Write([]byte(domain))
	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, epoch)
	h.Write(epochBytes)
	return h.Sum(nil)[:16]
}

func (t *TSPUPressure) randomJitter() time.Duration {
	minMs := t.config.JitterMin.Milliseconds()
	maxMs := t.config.JitterMax.Milliseconds()
	if maxMs <= minMs {
		return t.config.JitterMin
	}
	delta := cryptoRandIntn(int(maxMs - minMs))
	return time.Duration(minMs+int64(delta)) * time.Millisecond
}

func (t *TSPUPressure) Stats() map[string]interface{} {
	return map[string]interface{}{
		"pollution_sent": atomic.LoadUint64(&t.pollutionSent),
		"decoys_served":  atomic.LoadUint64(&t.decoysServed),
		"real_conns":     atomic.LoadUint64(&t.realConns),
		"active_conns":   atomic.LoadInt32(&t.activeConns),
		"bytes_in":       atomic.LoadUint64(&t.bytesIn),
		"bytes_out":      atomic.LoadUint64(&t.bytesOut),
		"state_entries":  atomic.LoadUint64(&t.stateEntries),
		"current_domain": t.currentDomain(),
		"epoch":          atomic.LoadUint64(&t.currentEpoch),
	}
}

func TSPUFactory(cfg interface{}) (interfaces.Module, error) {
	var config *TSPUConfig
	if c, ok := cfg.(*TSPUConfig); ok {
		config = c
	} else {
		config = DefaultTSPUConfig()
		config.Secret = "dd" + hex.EncodeToString(make([]byte, 16))
	}
	return NewTSPUPressure(config)
}

type tspuConn struct {
	net.Conn
	session   *MTProtoSession
	onClose   func()
	closeOnce sync.Once
}

func (c *tspuConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}
	decrypted := c.session.DecryptFromClient(b[:n])
	copy(b, decrypted)
	return len(decrypted), nil
}

func (c *tspuConn) Write(b []byte) (int, error) {
	encrypted := c.session.EncryptToClient(b)
	_, err := c.Conn.Write(encrypted)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *tspuConn) Close() error {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.Conn.Close()
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func cryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(int64(n))
	val, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0
	}
	return int(val.Int64())
}

type ProbeReflector struct {
	mu          sync.RWMutex
	fingerprints map[string][]byte
	certCache    map[string][]byte
}

func NewProbeReflector() *ProbeReflector {
	return &ProbeReflector{
		fingerprints: make(map[string][]byte),
		certCache:    make(map[string][]byte),
	}
}

func (r *ProbeReflector) HandleProbe(conn net.Conn, header []byte, domain string) {
	defer conn.Close()

	if len(header) > 0 && header[0] == 0x16 {
		r.reflectTLS(conn, domain)
		return
	}

	if isHTTPProbe(header) {
		r.reflectHTTP(conn, domain)
		return
	}

	noise := make([]byte, 64+cryptoRandIntn(192))
	rand.Read(noise)
	conn.Write(noise)
}

func (r *ProbeReflector) reflectTLS(conn net.Conn, domain string) {
	r.mu.RLock()
	cached, hasCert := r.certCache[domain]
	r.mu.RUnlock()

	if hasCert {
		conn.Write(cached)
		return
	}

	realConn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(context.Background(), "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return
	}
	defer realConn.Close()

	hello := buildMinimalClientHello(domain)
	realConn.SetDeadline(time.Now().Add(3 * time.Second))
	realConn.Write(hello)

	response := make([]byte, 8192)
	n, err := realConn.Read(response)
	if err != nil || n == 0 {
		return
	}

	cert := make([]byte, n)
	copy(cert, response[:n])

	r.mu.Lock()
	r.certCache[domain] = cert
	r.mu.Unlock()

	conn.Write(cert)
}

func (r *ProbeReflector) reflectHTTP(conn net.Conn, domain string) {
	response := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s/\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", domain)
	conn.Write([]byte(response))
}

func isHTTPProbe(header []byte) bool {
	if len(header) < 4 {
		return false
	}
	methods := []string{"GET ", "POST", "HEAD", "PUT ", "OPTI"}
	s := string(header[:4])
	for _, m := range methods {
		if s == m {
			return true
		}
	}
	return false
}

func buildMinimalClientHello(domain string) []byte {
	hello := make([]byte, 0, 256)
	hello = append(hello, 0x16, 0x03, 0x01)

	body := []byte{0x01, 0x00, 0x00, 0x00, 0x03, 0x03}
	random := make([]byte, 32)
	rand.Read(random)
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02)
	body = append(body, 0x01, 0x00)

	sni := []byte(domain)
	sniLen := len(sni)
	listLen := 3 + sniLen
	extLen := 2 + listLen
	ext := []byte{0x00, 0x00}
	ext = append(ext, byte(extLen>>8), byte(extLen))
	ext = append(ext, byte(listLen>>8), byte(listLen))
	ext = append(ext, 0x00)
	ext = append(ext, byte(sniLen>>8), byte(sniLen))
	ext = append(ext, sni...)

	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)-4))

	hello = append(hello, byte(len(body)>>8), byte(len(body)))
	hello = append(hello, body...)

	return hello
}

type TimingEngine struct {
	baseDelay time.Duration
	variance  float64
}

func NewTimingEngine(baseDelay time.Duration, variance float64) *TimingEngine {
	return &TimingEngine{
		baseDelay: baseDelay,
		variance:  variance,
	}
}

func (te *TimingEngine) Delay() time.Duration {
	base := te.baseDelay.Milliseconds()
	jitter := cryptoRandIntn(int(float64(base) * te.variance))
	if cryptoRandIntn(2) == 0 {
		return time.Duration(base+int64(jitter)) * time.Millisecond
	}
	result := base - int64(jitter)
	if result < 1 {
		result = 1
	}
	return time.Duration(result) * time.Millisecond
}

func (te *TimingEngine) BurstPattern(count int) []time.Duration {
	delays := make([]time.Duration, count)
	for i := range delays {
		delays[i] = te.Delay()
	}
	for i := len(delays) - 1; i > 0; i-- {
		j := cryptoRandIntn(i + 1)
		delays[i], delays[j] = delays[j], delays[i]
	}
	return delays
}

type KeyRotator struct {
	mu       sync.RWMutex
	baseSeed []byte
	epoch    uint64
	current  []byte
}

func NewKeyRotator(seed []byte) *KeyRotator {
	kr := &KeyRotator{
		baseSeed: seed,
	}
	kr.rotate()
	return kr
}

func (kr *KeyRotator) rotate() {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	kr.epoch++
	h := sha256.New()
	h.Write(kr.baseSeed)
	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, kr.epoch)
	h.Write(epochBytes)
	kr.current = h.Sum(nil)
}

func (kr *KeyRotator) Current() []byte {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	key := make([]byte, len(kr.current))
	copy(key, kr.current)
	return key
}

func (kr *KeyRotator) Epoch() uint64 {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.epoch
}

func (kr *KeyRotator) NewStream() (cipher.Stream, error) {
	key := kr.Current()
	if len(key) < 32 {
		return nil, fmt.Errorf("key too short")
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	return cipher.NewCTR(block, iv), nil
}
