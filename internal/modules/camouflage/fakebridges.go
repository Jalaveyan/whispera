package camouflage

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type FakeBridgeConfig struct {
	ListenAddrs     []string
	Domains         []string
	ResponseDelay   time.Duration
	MaxSessionTime  time.Duration
	DrainRate       int
	CertFile        string
	KeyFile         string
}

func DefaultFakeBridgeConfig() *FakeBridgeConfig {
	return &FakeBridgeConfig{
		Domains: []string{
			"example.com", "cloudflare.com", "google.com",
			"amazon.com", "microsoft.com", "apple.com",
		},
		ResponseDelay:  200 * time.Millisecond,
		MaxSessionTime: 30 * time.Second,
		DrainRate:      1024,
	}
}

type FakeBridgeManager struct {
	mu        sync.RWMutex
	config    *FakeBridgeConfig
	listeners []net.Listener
	tlsConfig *tls.Config

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	totalConns     uint64
	activeConns    int32
	bytesWasted    uint64
	probesReceived uint64
}

func NewFakeBridgeManager(cfg *FakeBridgeConfig) *FakeBridgeManager {
	if cfg == nil {
		cfg = DefaultFakeBridgeConfig()
	}
	return &FakeBridgeManager{
		config: cfg,
		stopCh: make(chan struct{}),
	}
}

func (fb *FakeBridgeManager) Start() error {
	if fb.config.CertFile != "" && fb.config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(fb.config.CertFile, fb.config.KeyFile)
		if err != nil {
			log.Warn("FakeBridge TLS cert load failed: %v, using plain TCP", err)
		} else {
			fb.tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		}
	}

	for _, addr := range fb.config.ListenAddrs {
		var listener net.Listener
		var err error

		if fb.tlsConfig != nil {
			listener, err = tls.Listen("tcp", addr, fb.tlsConfig)
		} else {
			listener, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
		}

		if err != nil {
			log.Warn("FakeBridge failed to listen on %s: %v", addr, err)
			continue
		}

		fb.mu.Lock()
		fb.listeners = append(fb.listeners, listener)
		fb.mu.Unlock()

		fb.wg.Add(1)
		go fb.acceptLoop(listener, addr)

		log.Info("FakeBridge listening on %s", addr)
	}

	return nil
}

func (fb *FakeBridgeManager) Stop() {
	fb.stopOnce.Do(func() { close(fb.stopCh) })

	fb.mu.Lock()
	for _, l := range fb.listeners {
		l.Close()
	}
	fb.listeners = nil
	fb.mu.Unlock()

	fb.wg.Wait()
}

func (fb *FakeBridgeManager) acceptLoop(listener net.Listener, addr string) {
	defer fb.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-fb.stopCh:
				return
			default:
				continue
			}
		}

		atomic.AddUint64(&fb.totalConns, 1)
		atomic.AddInt32(&fb.activeConns, 1)

		fb.wg.Add(1)
		go fb.handleFakeConn(conn)
	}
}

func (fb *FakeBridgeManager) handleFakeConn(conn net.Conn) {
	defer func() {
		conn.Close()
		atomic.AddInt32(&fb.activeConns, -1)
		fb.wg.Done()
	}()

	conn.SetDeadline(time.Now().Add(fb.config.MaxSessionTime))

	header := make([]byte, 5)
	n, err := conn.Read(header)
	if err != nil || n == 0 {
		return
	}

	atomic.AddUint64(&fb.probesReceived, 1)

	if header[0] == 0x16 {
		fb.handleFakeTLS(conn, header[:n])
	} else if isHTTP(header[:n]) {
		fb.handleFakeHTTP(conn)
	} else {
		fb.handleFakeProtocol(conn, header[:n])
	}
}

func (fb *FakeBridgeManager) handleFakeTLS(conn net.Conn, header []byte) {
	domain := fb.randomDomain()

	serverHello := buildFakeServerHello(domain)
	time.Sleep(fb.jitteredDelay())
	conn.Write(serverHello)

	changeCipherSpec := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	time.Sleep(fb.jitteredDelay())
	conn.Write(changeCipherSpec)

	fb.drainAndWaste(conn)
}

func (fb *FakeBridgeManager) handleFakeHTTP(conn net.Conn) {
	domain := fb.randomDomain()

	headers := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.24.0\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Connection: keep-alive\r\n" +
		"X-Frame-Options: SAMEORIGIN\r\n" +
		"Strict-Transport-Security: max-age=31536000\r\n" +
		"Content-Length: 4096\r\n\r\n"

	time.Sleep(fb.jitteredDelay())
	conn.Write([]byte(headers))

	body := make([]byte, 4096)
	generateFakeHTML(body, domain)
	conn.Write(body)

	atomic.AddUint64(&fb.bytesWasted, uint64(len(headers)+4096))

	fb.drainAndWaste(conn)
}

func (fb *FakeBridgeManager) handleFakeProtocol(conn net.Conn, header []byte) {
	response := make([]byte, 64+cryptoRandSmall(192))
	rand.Read(response)

	time.Sleep(fb.jitteredDelay())
	conn.Write(response)
	atomic.AddUint64(&fb.bytesWasted, uint64(len(response)))

	fb.drainAndWaste(conn)
}

func (fb *FakeBridgeManager) drainAndWaste(conn net.Conn) {
	buf := make([]byte, 4096)
	deadline := time.Now().Add(fb.config.MaxSessionTime)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		atomic.AddUint64(&fb.probesReceived, uint64(n))

		wasteSize := 128 + cryptoRandSmall(512)
		waste := make([]byte, wasteSize)
		rand.Read(waste)

		record := []byte{0x17, 0x03, 0x03}
		record = append(record, byte(wasteSize>>8), byte(wasteSize))
		record = append(record, waste...)

		time.Sleep(fb.jitteredDelay())
		conn.Write(record)
		atomic.AddUint64(&fb.bytesWasted, uint64(len(record)))
	}
}

func (fb *FakeBridgeManager) randomDomain() string {
	domains := fb.config.Domains
	if len(domains) == 0 {
		return "example.com"
	}
	return domains[cryptoRandSmall(len(domains))]
}

func (fb *FakeBridgeManager) jitteredDelay() time.Duration {
	base := fb.config.ResponseDelay.Milliseconds()
	jitter := cryptoRandSmall(int(base/2) + 1)
	return time.Duration(base/2+int64(jitter)) * time.Millisecond
}

func (fb *FakeBridgeManager) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_conns":     atomic.LoadUint64(&fb.totalConns),
		"active_conns":    atomic.LoadInt32(&fb.activeConns),
		"bytes_wasted":    atomic.LoadUint64(&fb.bytesWasted),
		"probes_received": atomic.LoadUint64(&fb.probesReceived),
	}
}

func buildFakeServerHello(domain string) []byte {
	hello := []byte{0x16, 0x03, 0x03}

	random := make([]byte, 32)
	rand.Read(random)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	body := []byte{0x02, 0x00, 0x00, 0x00, 0x03, 0x03}
	body = append(body, random...)
	body = append(body, 0x20)
	body = append(body, sessionID...)

	ciphers := [][]byte{{0x13, 0x01}, {0x13, 0x02}, {0x13, 0x03}, {0xc0, 0x2f}, {0xc0, 0x30}}
	body = append(body, ciphers[cryptoRandSmall(len(ciphers))]...)
	body = append(body, 0x00)

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

	certData := make([]byte, 512+cryptoRandSmall(1024))
	rand.Read(certData)

	certRecord := []byte{0x16, 0x03, 0x03}
	certBody := []byte{0x0b, 0x00, 0x00, 0x00}
	certBody = append(certBody, certData...)
	binary.BigEndian.PutUint16(certBody[2:4], uint16(len(certBody)-4))
	certRecord = append(certRecord, byte(len(certBody)>>8), byte(len(certBody)))
	certRecord = append(certRecord, certBody...)

	hello = append(hello, certRecord...)

	return hello
}

func generateFakeHTML(buf []byte, domain string) {
	page := []byte(`<!DOCTYPE html><html><head><title>` + domain + `</title>` +
		`<meta charset="utf-8"><style>body{margin:40px;font-family:sans-serif}` +
		`h1{color:#333}p{color:#666;line-height:1.6}</style></head><body>` +
		`<h1>Welcome to ` + domain + `</h1>` +
		`<p>This page is currently unavailable. Please try again later.</p>` +
		`<p>If you continue to experience issues, contact support.</p>` +
		`</body></html>`)

	copy(buf, page)
	if len(page) < len(buf) {
		noise := make([]byte, len(buf)-len(page))
		rand.Read(noise)
		for i := range noise {
			noise[i] = ' '
		}
		copy(buf[len(page):], noise)
	}
}

func isHTTP(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	s := string(data[:4])
	return s == "GET " || s == "POST" || s == "HEAD" || s == "PUT " || s == "DELE" || s == "OPTI"
}

func cryptoRandSmall(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(binary.LittleEndian.Uint32(b)) % n
}
