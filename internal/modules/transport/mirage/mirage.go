package mirage

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("mirage")

const (
	ModuleName    = "transport.mirage"
	ModuleVersion = "1.0.0"

	authTagLen   = 8
	maxHandshake = 16384
)

type Config struct {
	Secret       string
	TargetServer string
	TargetPort   int
	SNI          string
	Fingerprint  string
	ServerMode   bool
	ListenAddr   string
	BackendAddr  string
	ShortIDs     []string
}

func DefaultConfig() *Config {
	return &Config{
		TargetPort:  443,
		SNI:         "www.google.com",
		Fingerprint: "chrome",
	}
}

func (c *Config) Validate() error {
	if c.Secret == "" {
		return fmt.Errorf("mirage: secret key required")
	}
	if !c.ServerMode && c.TargetServer == "" {
		return fmt.Errorf("mirage: target server required for client mode")
	}
	if c.ServerMode && c.BackendAddr == "" {
		return fmt.Errorf("mirage: backend address required for server mode")
	}
	return nil
}

type Transport struct {
	*base.Module
	config   *Config
	listener net.Listener

	connCount   int64
	bytesIn     uint64
	bytesOut    uint64
	authFails   uint64
	proxyFalls  uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
	}, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportMirage }

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	target := addr
	if t.config.TargetServer != "" {
		target = fmt.Sprintf("%s:%d", t.config.TargetServer, t.config.TargetPort)
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("mirage: dial %s: %w", target, err)
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	sni := t.config.SNI
	if sni == "" {
		sni = t.config.TargetServer
	}

	helloID := t.getClientHelloID()

	conn := utls.UClient(raw, &utls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, helloID)

	if err := conn.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("mirage: build handshake: %w", err)
	}

	authTag := t.generateAuthTag()
	t.injectAuthMsg(conn.HandshakeState.Hello, authTag)

	if err := conn.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("mirage: rebuild handshake: %w", err)
	}

	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("mirage: handshake: %w", err)
	}

	mc := &mirageConn{
		Conn:      conn,
		transport: t,
	}

	atomic.AddInt64(&t.connCount, 1)
	return mc, nil
}

func (t *Transport) DialConn(ctx context.Context, existing net.Conn, addr string) (net.Conn, error) {
	sni := t.config.SNI
	if sni == "" {
		sni = t.config.TargetServer
	}

	helloID := t.getClientHelloID()

	uconn := utls.UClient(existing, &utls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, helloID)

	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("mirage: build handshake: %w", err)
	}

	authTag := t.generateAuthTag()
	t.injectAuthMsg(uconn.HandshakeState.Hello, authTag)

	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("mirage: rebuild handshake: %w", err)
	}

	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("mirage: handshake: %w", err)
	}

	mc := &mirageConn{
		Conn:      uconn,
		transport: t,
	}

	atomic.AddInt64(&t.connCount, 1)
	return mc, nil
}

func (t *Transport) generateAuthTag() []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	nonce := make([]byte, 8)
	rand.Read(nonce)

	mac := hmac.New(sha256.New, []byte(t.config.Secret))
	mac.Write(ts)
	mac.Write(nonce)
	sum := mac.Sum(nil)

	tag := make([]byte, 0, authTagLen+16)
	tag = append(tag, ts...)
	tag = append(tag, nonce...)
	tag = append(tag, sum[:authTagLen]...)
	return tag
}

func (t *Transport) verifyAuthTag(tag []byte) bool {
	if len(tag) < authTagLen+16 {
		return false
	}
	ts := tag[:8]
	nonce := tag[8:16]
	sig := tag[16 : 16+authTagLen]

	tsVal := binary.BigEndian.Uint64(ts)
	now := uint64(time.Now().Unix())
	if now > tsVal+120 || tsVal > now+30 {
		return false
	}

	mac := hmac.New(sha256.New, []byte(t.config.Secret))
	mac.Write(ts)
	mac.Write(nonce)
	expected := mac.Sum(nil)

	return hmac.Equal(sig, expected[:authTagLen])
}

func (t *Transport) injectAuthMsg(hello *utls.PubClientHelloMsg, authTag []byte) {
	if hello == nil {
		return
	}
	copy(hello.SessionId[:8], authTag[:8])
	copy(hello.SessionId[8:16], authTag[8:16])
	if len(hello.SessionId) >= 24+authTagLen {
		copy(hello.SessionId[16:16+authTagLen], authTag[16:16+authTagLen])
	}
}

func (t *Transport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	if !t.config.ServerMode {
		return nil, fmt.Errorf("mirage: not in server mode")
	}

	listenAddr := addr
	if t.config.ListenAddr != "" {
		listenAddr = t.config.ListenAddr
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("mirage: listen %s: %w", listenAddr, err)
	}

	t.listener = ln

	ml := &mirageListener{
		Listener:  ln,
		transport: t,
		ctx:       ctx,
	}

	log.Info("Mirage server listening on %s (target: %s:%d)", listenAddr, t.config.SNI, t.config.TargetPort)
	return ml, nil
}

type mirageListener struct {
	net.Listener
	transport *Transport
	ctx       context.Context
}

func (ml *mirageListener) Accept() (net.Conn, error) {
	for {
		conn, err := ml.Listener.Accept()
		if err != nil {
			return nil, err
		}

		mc, err := ml.transport.handleServerConn(ml.ctx, conn)
		if err != nil {
			continue
		}
		return mc, nil
	}
}

func (t *Transport) handleServerConn(ctx context.Context, raw net.Conn) (net.Conn, error) {
	raw.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, maxHandshake)
	n, err := raw.Read(buf)
	if err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetReadDeadline(time.Time{})

	clientHello := buf[:n]

	authTag := t.extractAuth(clientHello)
	if authTag != nil && t.verifyAuthTag(authTag) {
		log.Info("Mirage: authenticated client from %s", raw.RemoteAddr())
		atomic.AddInt64(&t.connCount, 1)

		targetAddr := net.JoinHostPort(t.config.SNI, strconv.Itoa(t.config.TargetPort))
		targetConn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			log.Warn("Mirage: cannot reach target %s: %v", targetAddr, err)
			raw.Close()
			return nil, err
		}

		if _, err := targetConn.Write(clientHello); err != nil {
			targetConn.Close()
			raw.Close()
			return nil, err
		}

		serverHello := make([]byte, maxHandshake)
		sn, err := targetConn.Read(serverHello)
		if err != nil {
			targetConn.Close()
			raw.Close()
			return nil, err
		}

		if _, err := raw.Write(serverHello[:sn]); err != nil {
			targetConn.Close()
			raw.Close()
			return nil, err
		}

		go t.proxyTLSHandshake(raw, targetConn)

		return &mirageServerConn{
			clientConn:   raw,
			targetConn:   targetConn,
			transport:    t,
			authenticated: true,
			handshakeDone: make(chan struct{}),
		}, nil
	}

	atomic.AddUint64(&t.proxyFalls, 1)
	log.Debug("Mirage: unauthenticated connection from %s, proxying to real server", raw.RemoteAddr())

	targetAddr := net.JoinHostPort(t.config.SNI, strconv.Itoa(t.config.TargetPort))
	targetConn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("mirage: proxy to %s: %w", targetAddr, err)
	}

	if _, err := targetConn.Write(clientHello); err != nil {
		targetConn.Close()
		raw.Close()
		return nil, err
	}

	go func() {
		defer raw.Close()
		defer targetConn.Close()
		go func() {
			io.Copy(raw, targetConn)
			raw.Close()
		}()
		io.Copy(targetConn, raw)
	}()

	return nil, fmt.Errorf("mirage: proxied to real server")
}

func (t *Transport) proxyTLSHandshake(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	done := make(chan struct{})

	go func() {
		defer wg.Done()
		buf := make([]byte, 8192)
		for {
			select {
			case <-done:
				return
			default:
			}
			target.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := target.Read(buf)
			if err != nil {
				return
			}
			if isHandshakeFinished(buf[:n]) {
				client.Write(buf[:n])
				close(done)
				return
			}
			client.Write(buf[:n])
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 8192)
		for {
			select {
			case <-done:
				return
			default:
			}
			client.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := client.Read(buf)
			if err != nil {
				return
			}
			target.Write(buf[:n])
		}
	}()

	wg.Wait()
	target.Close()
}

func isHandshakeFinished(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	return data[0] == 0x14
}

func (t *Transport) extractAuth(clientHello []byte) []byte {
	if len(clientHello) < 44 {
		return nil
	}
	if clientHello[0] != 0x16 {
		return nil
	}

	offset := 5
	if offset >= len(clientHello) || clientHello[offset] != 0x01 {
		return nil
	}
	offset += 4
	offset += 2
	offset += 32

	if offset >= len(clientHello) {
		return nil
	}
	sessionIDLen := int(clientHello[offset])
	offset++

	if sessionIDLen < 24+authTagLen || offset+sessionIDLen > len(clientHello) {
		return nil
	}

	tag := make([]byte, 16+authTagLen)
	copy(tag[:8], clientHello[offset:offset+8])
	copy(tag[8:16], clientHello[offset+8:offset+16])
	copy(tag[16:16+authTagLen], clientHello[offset+16:offset+16+authTagLen])

	return tag
}

type mirageConn struct {
	net.Conn
	transport *Transport
}

func (c *mirageConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesIn, uint64(n))
	}
	return n, err
}

func (c *mirageConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesOut, uint64(n))
	}
	return n, err
}

func (c *mirageConn) Close() error {
	atomic.AddInt64(&c.transport.connCount, -1)
	return c.Conn.Close()
}

type mirageServerConn struct {
	clientConn    net.Conn
	targetConn    net.Conn
	transport     *Transport
	authenticated bool
	handshakeDone chan struct{}
	switched      int32
}

func (c *mirageServerConn) Read(b []byte) (int, error) {
	n, err := c.clientConn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesIn, uint64(n))
	}
	return n, err
}

func (c *mirageServerConn) Write(b []byte) (int, error) {
	n, err := c.clientConn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesOut, uint64(n))
	}
	return n, err
}

func (c *mirageServerConn) Close() error {
	atomic.AddInt64(&c.transport.connCount, -1)
	c.targetConn.Close()
	return c.clientConn.Close()
}

func (c *mirageServerConn) LocalAddr() net.Addr  { return c.clientConn.LocalAddr() }
func (c *mirageServerConn) RemoteAddr() net.Addr { return c.clientConn.RemoteAddr() }
func (c *mirageServerConn) SetDeadline(t time.Time) error {
	c.clientConn.SetDeadline(t)
	return nil
}
func (c *mirageServerConn) SetReadDeadline(t time.Time) error {
	return c.clientConn.SetReadDeadline(t)
}
func (c *mirageServerConn) SetWriteDeadline(t time.Time) error {
	return c.clientConn.SetWriteDeadline(t)
}

func (t *Transport) getClientHelloID() utls.ClientHelloID {
	switch t.config.Fingerprint {
	case "chrome", "":
		return utls.HelloChrome_Auto
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "random":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}
	t.SetHealthy(true, "mirage transport running")
	return nil
}

func (t *Transport) Stop() error {
	if t.listener != nil {
		t.listener.Close()
	}
	return t.Module.Stop()
}

func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"connections": atomic.LoadInt64(&t.connCount),
		"bytes_in":    atomic.LoadUint64(&t.bytesIn),
		"bytes_out":   atomic.LoadUint64(&t.bytesOut),
		"auth_fails":  atomic.LoadUint64(&t.authFails),
		"proxy_falls": atomic.LoadUint64(&t.proxyFalls),
	}
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
