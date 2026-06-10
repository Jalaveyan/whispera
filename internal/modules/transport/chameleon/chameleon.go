package chameleon

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	stdlog "log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

var log = logger.Module("chameleon")

func NewSessionCache(capacity int) any {
	return utls.NewLRUClientSessionCache(capacity)
}

var decoyGraph = [4][]string{
	{"/api/v1/config", "/cdn/app/index.js", "/assets/main.css"},
	{"/static/vendor.js", "/static/app.js", "/assets/theme.css", "/cdn/fonts/roboto.woff2"},
	{"/static/icons/192.png", "/favicon.ico", "/manifest.json", "/robots.txt"},
	{"/api/v1/health", "/api/v1/status"},
}

const (
	sessionCookie       = "_s"
	headerToken         = "Authorization"
	contentType         = "application/octet-stream"
	contentTypeDownload = "video/mp4"

	h2StreamWindow = 64 << 20
	h2ConnWindow   = 256 << 20
)

func newH2Transport(dial func(context.Context, string, string, *tls.Config) (net.Conn, error)) *http2.Transport {
	stub := &http.Transport{
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerStream:     h2StreamWindow,
			MaxReceiveBufferPerConnection: h2ConnWindow,
		},
	}
	h2t, err := http2.ConfigureTransports(stub)
	if err != nil || h2t == nil {
		h2t = &http2.Transport{}
	}
	h2t.ConnPool = nil
	h2t.MaxReadFrameSize = 1 << 20
	h2t.ReadIdleTimeout = 30 * time.Second
	h2t.PingTimeout = 15 * time.Second
	h2t.MaxDecoderHeaderTableSize = 65536
	h2t.MaxHeaderListSize = 262144
	h2t.DisableCompression = true
	h2t.DialTLSContext = dial
	return h2t
}

type UserEntry struct {
	UserID string
	PSK    []byte
}


func encodeSession(sessionID []byte, anchor time.Time) string {
	buf := make([]byte, 24)
	copy(buf, sessionID)
	binary.BigEndian.PutUint64(buf[16:], uint64(anchor.Unix()))
	return base64.RawURLEncoding.EncodeToString(buf)
}

func decodeSession(s string) (sessionID []byte, anchor time.Time, err error) {
	buf, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(buf) != 24 {
		return nil, time.Time{}, fmt.Errorf("chameleon: bad session header")
	}
	sessionID = buf[:16]
	anchor = time.Unix(int64(binary.BigEndian.Uint64(buf[16:])), 0)
	return
}

func pickSNI(cfg *ClientConfig) string {
	if len(cfg.ServerNames) > 0 {
		return cfg.ServerNames[mrand.Intn(len(cfg.ServerNames))]
	}
	return cfg.ServerName
}

func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func pinVerifier(pin string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("chameleon: no server certificate to pin")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("chameleon: parse server cert: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(SPKIPin(cert)), []byte(pin)) != 1 {
			return fmt.Errorf("chameleon: server cert pin mismatch")
		}
		return nil
	}
}

func Client(ctx context.Context, cfg *ClientConfig) (net.Conn, error) {
	sessionID := make([]byte, 16)
	if _, err := crand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("chameleon: session id: %w", err)
	}
	anchor := time.Now().UTC().Truncate(time.Second)

	keys := DeriveKeys(cfg.SharedSecret)
	sched := NewWindowScheduler(keys.Behavior, sessionID, anchor)

	windowIdx := sched.CurrentIndex()
	bp := DeriveBehaviorParams(keys.Behavior, windowIdx, sessionID)
	path := GeneratePath(bp.PathSeed, windowIdx)
	token := AuthToken(keys.Auth, anchor.Unix()/30, sessionID)

	sni := pickSNI(cfg)
	origin := "https://" + sni

	helloID, helloSpec := pickFingerprint()

	dialFn := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		d := &net.Dialer{Timeout: 10 * time.Second}
		rawConn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if tcpConn, ok := rawConn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(time.Duration(30+mrand.Intn(61)) * time.Second)
			tcpConn.SetNoDelay(true)
			tcpFastKeepalive(tcpConn)
		}
		uCfg := &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		}
		if cfg.ServerCertPin != "" {
			uCfg.VerifyPeerCertificate = pinVerifier(cfg.ServerCertPin)
		}
		if sc, ok := cfg.SessionCache.(utls.ClientSessionCache); ok {
			uCfg.ClientSessionCache = sc
		}
		var uConn *utls.UConn
		if helloSpec != nil {
			uConn = utls.UClient(rawConn, uCfg, utls.HelloCustom)
			if err := uConn.ApplyPreset(helloSpec); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("chameleon: apply fingerprint: %w", err)
			}
		} else {
			uConn = utls.UClient(rawConn, uCfg, helloID)
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("chameleon: utls handshake: %w", err)
		}
		return uConn, nil
	}

	h2Transport := newH2Transport(dialFn)
	decoyTransport := newH2Transport(dialFn)

	pr, pw := io.Pipe()
	bpw := newBufferedPipeWriter(pw)
	url := fmt.Sprintf("https://%s%s", cfg.ServerAddr, path)

	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())

	req, err := http.NewRequestWithContext(tunnelCtx, http.MethodPost, url, pr)
	if err != nil {
		tunnelCancel()
		pr.Close()
		bpw.Close()
		return nil, fmt.Errorf("chameleon: build request: %w", err)
	}
	req.Host = sni
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(headerToken, "Bearer "+token)
	applyBrowserHeaders(req, origin)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: encodeSession(sessionID, anchor)})

	local := staticAddr{"tcp", cfg.ServerAddr}
	remote := staticAddr{"tcp", cfg.ServerAddr}

	pc := newPipelinedConn(pr, bpw, tunnelCancel, local, remote)

	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client := &http.Client{Transport: h2Transport, CheckRedirect: noRedirect}
	decoyClient := &http.Client{Transport: decoyTransport, CheckRedirect: noRedirect}

	fc := NewFrameConn(pc)

	go runDecoy(tunnelCtx, decoyClient, cfg.ServerAddr, sni, origin, bp, fc)

	go func() {
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			pc.deliver(nil)
			return
		}
		if !pc.deliver(resp.Body) {
			resp.Body.Close()
		}
	}()

	return fc, nil
}

func ListenAndServe(ctx context.Context, cfg *ServerConfig) error {
	cfg.initCond()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, cfg)
	})

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":443"
	}

	cdnCipherSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	cdnCurves := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

	var tlsCfg *tls.Config

	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("chameleon: load cert: %w", err)
		}
		tlsCfg = &tls.Config{
			Certificates:     []tls.Certificate{cert},
			NextProtos:       []string{"h2", "http/1.1"},
			MinVersion:       tls.VersionTLS12,
			CipherSuites:     cdnCipherSuites,
			CurvePreferences: cdnCurves,
		}
		if len(cert.Certificate) > 0 {
			if leaf, e := x509.ParseCertificate(cert.Certificate[0]); e == nil {
				log.Printf("Chameleon server SPKI pin: %s", SPKIPin(leaf))
			}
		}
	} else if cfg.Domain != "" {
		cacheDir := cfg.ACMEDir
		if cacheDir == "" {
			cacheDir = "/var/lib/whispera/acme"
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Cache:      autocert.DirCache(cacheDir),
		}
		go func() {
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				log.Printf("chameleon: acme http-01 listener: %v", err)
			}
		}()
		tlsCfg = m.TLSConfig()
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		tlsCfg.MinVersion = tls.VersionTLS12
		tlsCfg.CipherSuites = cdnCipherSuites
		tlsCfg.CurvePreferences = cdnCurves
		domain := cfg.Domain
		origGet := tlsCfg.GetCertificate
		tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" || hello.ServerName != domain {
				patched := *hello
				patched.ServerName = domain
				return origGet(&patched)
			}
			return origGet(hello)
		}
		log.Printf("Chameleon: autocert for %s (cache: %s)", cfg.Domain, cacheDir)
	} else {
		return fmt.Errorf("chameleon: neither TLSCert nor Domain configured")
	}

	srv := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: tlsCfg,
		ErrorLog:  stdlog.New(io.Discard, "", 0),
	}

	if err := http2.ConfigureServer(srv, &http2.Server{
		MaxUploadBufferPerConnection: 1 << 28,
		MaxUploadBufferPerStream:     1 << 26,
	}); err != nil {
		return fmt.Errorf("chameleon: h2 server config: %w", err)
	}

	if cfg.DecoyOrigin != "" {
		cfg.proxy = newDecoyProxy(cfg.DecoyOrigin)
	}

	go func() { <-ctx.Done(); srv.Close() }()

	rawLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("chameleon: listen: %w", err)
	}
	tlsLn := tls.NewListener(&noDelayListener{TCPListener: rawLn.(*net.TCPListener)}, tlsCfg)
	log.Printf("Chameleon listening on %s", listenAddr)
	return srv.Serve(tlsLn)
}

type noDelayListener struct {
	*net.TCPListener
}

func (l *noDelayListener) Accept() (net.Conn, error) {
	tc, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(time.Duration(30+mrand.Intn(61)) * time.Second)
	tc.SetNoDelay(true)
	tcpFastKeepalive(tc)
	return tc, nil
}

func handleRequest(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
	_, cookieErr := r.Cookie(sessionCookie)
	hasSess := func() bool { return cookieErr == nil }

	switch r.Method {
	case http.MethodOptions:
		handleRESTOptions(w, r)
		return
	case http.MethodDelete:
		handleRESTDelete(w, r)
		return
	case http.MethodGet:
		path := r.URL.Path
		if strings.HasPrefix(path, "/video/") {
			if strings.HasSuffix(path, ".m3u8") {
				handleHLSPlaylist(w, r, cfg)
			} else {
				handleHLSSegment(w, r, cfg)
			}
			return
		}
		if hasSess() {
			handleRESTDownload(w, r, cfg)
			return
		}
		serveDecoy(w, r, cfg)
		return
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		if hasSess() {
			if r.ContentLength < 0 {
				handleClientStream(w, r, cfg)
			} else {
				handleRESTUpload(w, r, cfg)
			}
			return
		}
		serveDecoy(w, r, cfg)
		return
	default:
		serveDecoy(w, r, cfg)
		return
	}
}

func handleClientStream(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
	tokenHdr := r.Header.Get(headerToken)
	if len(tokenHdr) < 8 || tokenHdr[:7] != "Bearer " {
		serveDecoy(w, r, cfg)
		return
	}
	token := tokenHdr[7:]

	sessCookie, err := r.Cookie(sessionCookie)
	if err != nil {
		serveDecoy(w, r, cfg)
		return
	}
	sessionID, _, err := decodeSession(sessCookie.Value)
	if err != nil {
		serveDecoy(w, r, cfg)
		return
	}

	secret, userID := resolveSecret(cfg, token, sessionID)
	if secret == nil {
		serveDecoy(w, r, cfg)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentTypeDownload)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	local := staticAddr{"tcp", r.Host}
	remote := staticAddr{"tcp", r.RemoteAddr}
	conn := newHTTPStreamConn(r.Body, w, flusher.Flush, local, remote, cfg.GANDecide)
	fc := NewFrameConn(conn)

	if cfg.OnConn != nil {
		cfg.OnConn(fc, userID)
	}

	select {
	case <-conn.done:
	case <-r.Context().Done():
	}
}

func resolveSecret(cfg *ServerConfig, token string, sessionID []byte) ([]byte, string) {
	if cfg.GetUsers == nil {
		k := DeriveKeys(cfg.SharedSecret)
		if VerifyAuthToken(k.Auth, token, sessionID) {
			return cfg.SharedSecret, "default"
		}
		return nil, ""
	}
	for _, u := range cfg.GetUsers() {
		if len(u.PSK) != 32 {
			continue
		}
		k := DeriveKeys(u.PSK)
		if VerifyAuthToken(k.Auth, token, sessionID) {
			return u.PSK, u.UserID
		}
	}
	return nil, ""
}

func serveDecoy(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
	if cfg != nil && cfg.proxy != nil {
		cfg.proxy.serve(w, r)
		return
	}
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	path := r.URL.Path
	var ct, body string
	switch {
	case strings.HasSuffix(path, ".js"):
		ct, body = "application/javascript; charset=utf-8", "(function(){'use strict';})();\n"
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	case strings.HasSuffix(path, ".css"):
		ct, body = "text/css; charset=utf-8", "*{box-sizing:border-box}body{margin:0}\n"
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	case strings.HasSuffix(path, ".json") ||
		strings.HasSuffix(path, "health") ||
		strings.HasSuffix(path, "config"):
		ct, body = "application/json; charset=utf-8", `{"status":"ok","version":"1.0.0"}`+"\n"
		w.Header().Set("Cache-Control", "no-cache")
	case strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".ico") ||
		strings.HasSuffix(path, ".woff2"):
		switch {
		case strings.HasSuffix(path, ".ico"):
			ct = "image/x-icon"
		case strings.HasSuffix(path, ".png"):
			ct = "image/png"
		case strings.HasSuffix(path, ".woff2"):
			ct = "font/woff2"
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
	case path == "/robots.txt":
		ct, body = "text/plain; charset=utf-8", "User-agent: *\nDisallow: /api/\n"
		w.Header().Set("Cache-Control", "public, max-age=86400")
	case path == "/manifest.json":
		ct = "application/json; charset=utf-8"
		body = `{"name":"","short_name":"","start_url":"/","display":"standalone","icons":[]}` + "\n"
		w.Header().Set("Cache-Control", "public, max-age=3600")
	default:
		ct, body = "text/html; charset=utf-8", "<!DOCTYPE html><html><head><title></title></head><body></body></html>\n"
		w.Header().Set("Cache-Control", "max-age=3600")
	}

	w.Header().Set("Content-Type", ct)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	if body != "" {
		io.WriteString(w, body)
	}
}

func runDecoy(ctx context.Context, client *http.Client, serverAddr, sni, origin string, bp BehaviorParams, fc *FrameConn) {
	get := func(path string) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("https://%s%s", serverAddr, path), nil)
		if err != nil {
			return
		}
		req.Host = sni
		applyBrowserHeaders(req, origin)
		if resp, err := client.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	loadFactor := func() int {
		if fc == nil {
			return 1
		}
		bytes := fc.SampleAndResetBytes()
		switch {
		case bytes > 4<<20:
			return 8
		case bytes > 1<<20:
			return 4
		case bytes > 256<<10:
			return 2
		default:
			return 1
		}
	}

	burstFor := func(base int) int {
		if fc == nil {
			return base
		}
		recent := atomic.LoadUint64(&fc.bytesRecent)
		switch {
		case recent > 4<<20:
			return 1
		case recent > 1<<20:
			if base > 2 {
				return 2
			}
		}
		return base
	}

	heavyLoad := func() bool {
		if fc == nil {
			return false
		}
		return atomic.LoadUint64(&fc.bytesRecent) > 4<<20
	}

	sleep := func(ms int) bool {
		ms *= loadFactor()
		jitter := time.Duration(mrand.Intn(ms/4+1)) * time.Millisecond
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Duration(ms)*time.Millisecond + jitter):
			return true
		}
	}

	parallel := func(paths []string, n int) {
		if n > len(paths) {
			n = len(paths)
		}
		chosen := mrand.Perm(len(paths))[:n]
		var wg sync.WaitGroup
		for _, i := range chosen {
			wg.Add(1)
			p := paths[i]
			go func() { defer wg.Done(); get(p) }()
			time.Sleep(time.Duration(mrand.Intn(20)) * time.Millisecond)
		}
		wg.Wait()
	}

	go func() {
		api := decoyGraph[3]
		for {
			ms := 3000 + mrand.Intn(5001)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(ms) * time.Millisecond):
			}
			if heavyLoad() {
				continue
			}
			get(api[mrand.Intn(len(api))])
		}
	}()

	shouldSkip := func() bool {
		if fc == nil {
			return false
		}
		return atomic.LoadUint64(&fc.bytesRecent) > 8<<20
	}

	for {
		if shouldSkip() {
			if !sleep(bp.ParseDelayMs * 4) {
				return
			}
			continue
		}
		nav := decoyGraph[0]
		get(nav[mrand.Intn(len(nav))])
		if !sleep(bp.ParseDelayMs) {
			return
		}

		parallel(decoyGraph[1], burstFor(bp.BurstSize))
		if !sleep(20) {
			return
		}

		parallel(decoyGraph[2], burstFor(1+mrand.Intn(2)))
		if !sleep(bp.ParseDelayMs / 2) {
			return
		}

		api := decoyGraph[3]
		get(api[mrand.Intn(len(api))])

		if !sleep(bp.IdleSec * 1000) {
			return
		}
	}
}

type decoyProxy struct {
	origin string
	rp     *httputil.ReverseProxy
}

func newDecoyProxy(origin string) *decoyProxy {
	origin = strings.TrimRight(origin, "/")
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return &decoyProxy{origin: origin}
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		serveDecoy(w, r, nil)
	}
	return &decoyProxy{origin: origin, rp: rp}
}

func (p *decoyProxy) serve(w http.ResponseWriter, r *http.Request) {
	if p.rp == nil {
		serveDecoy(w, r, nil)
		return
	}
	p.rp.ServeHTTP(w, r)
}
