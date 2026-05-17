package chameleon

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"whispera/internal/logger"
)

var log = logger.Module("chameleon")

// NewSessionCache returns a session cache suitable for Config.SessionCache.
// Capacity is the maximum number of TLS sessions stored.
func NewSessionCache(capacity int) any {
	return utls.NewLRUClientSessionCache(capacity)
}

// chromeHelloPool — набор современных Chrome TLS-fingerprint-ов.
// Выбирается случайно per-connection, чтобы JA3 hash варьировался.
// Версии 120+ с post-quantum соответствуют реальным Chrome 120-133 на Android.
// decoyGraph mirrors a realistic browser page-load dependency graph.
// Phase 0 — navigation (1 request): main document / entry API.
// Phase 1 — critical subresources (parallel): JS bundles + CSS.
// Phase 2 — deferred resources (parallel): images, fonts, icons.
// Phase 3 — post-load API calls (sequential): telemetry, config refresh.
var decoyGraph = [4][]string{
	{"/api/v1/config", "/cdn/app/index.js", "/assets/main.css"},
	{"/static/vendor.js", "/static/app.js", "/assets/theme.css", "/cdn/fonts/roboto.woff2"},
	{"/static/icons/192.png", "/favicon.ico", "/manifest.json", "/robots.txt"},
	{"/api/v1/health", "/api/v1/status"},
}

var chromeHelloPool = []utls.ClientHelloID{
	utls.HelloChrome_120_PQ,
	utls.HelloChrome_131,
	utls.HelloChrome_133,
	utls.HelloChrome_Auto,
}

const (
	headerSession = "X-Session-Id"
	headerToken   = "Authorization"
	contentType   = "application/octet-stream"
)

// UserEntry is one registered user on the server side.
type UserEntry struct {
	UserID string
	PSK    []byte // 32-byte pre-shared key (same value client has in ConnectionKey.PSK)
}

// Config for the Chameleon transport.
type Config struct {
	// Server-side
	ListenAddr string
	// Manual TLS — takes priority over autocert.
	TLSCert string
	TLSKey  string
	// Autocert (Let's Encrypt) — used when TLSCert is empty.
	// Domain is the public hostname the server is reachable at.
	// ACMEDir is the directory for certificate cache (default: /var/lib/whispera/acme).
	Domain  string
	ACMEDir string

	// GetUsers returns the list of registered users for per-user auth verification.
	// If nil, SharedSecret is used (single-secret mode).
	GetUsers func() []UserEntry

	// Client-side
	ServerAddr string // host:port
	ServerName string // SNI / Host header (primary)

	// ServerNames — optional pool of SNI aliases for the same server.
	// Each new connection picks one at random to vary the TLS fingerprint.
	// All names must resolve to ServerAddr and share the same TLS certificate.
	// If empty, ServerName is used for every connection.
	ServerNames []string

	// SharedSecret — single 32-byte secret (client mode, or single-user server).
	// Derived by caller as HKDF(psk, "chameleon-v1").
	SharedSecret []byte

	// SessionCache enables TLS session resumption across reconnects.
	// Create with NewSessionCache(); shared across all connections to the same server.
	SessionCache any // holds *utls.LRUClientSessionCache

	// DecoyOrigin — if set, probe requests are reverse-proxied from this URL
	// (e.g. "https://en.wikipedia.org") so active probers see real content.
	DecoyOrigin string

	// OnConn is called server-side for each authenticated tunnel connection.
	OnConn func(conn net.Conn, userID string)

	// internal — initialized by ListenAndServe when DecoyOrigin is set.
	proxy *decoyProxy
}

// sessionHeader encodes sessionID (16B) + anchor unix-seconds (8B) as base64.
// The anchor is the connection start time — both sides use it to synchronize
// the random window schedule without any additional round-trips.
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

// pickSNI returns a random SNI name from the pool, falling back to ServerName.
func pickSNI(cfg *Config) string {
	if len(cfg.ServerNames) > 0 {
		return cfg.ServerNames[mrand.Intn(len(cfg.ServerNames))]
	}
	return cfg.ServerName
}

// Client dials the Chameleon server and returns a net.Conn tunnel.
func Client(ctx context.Context, cfg *Config) (net.Conn, error) {
	sessionID := make([]byte, 16)
	if _, err := crand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("chameleon: session id: %w", err)
	}
	anchor := time.Now().UTC().Truncate(time.Second)

	keys := DeriveKeys(cfg.SharedSecret, true)
	sched := NewWindowScheduler(keys.Behavior, sessionID, anchor)

	windowIdx := sched.CurrentIndex()
	bp := DeriveBehaviorParams(keys.Behavior, windowIdx, sessionID)
	path := GeneratePath(bp.PathSeed, windowIdx)
	token := AuthToken(keys.Auth, anchor.Unix()/30, sessionID)

	sni := pickSNI(cfg)
	origin := "https://" + sni

	// Random Chrome fingerprint per connection — JA3 hash varies across sessions.
	helloID := chromeHelloPool[mrand.Intn(len(chromeHelloPool))]

	// Use http2.Transport directly so DialTLSContext can return *utls.UConn.
	// http.Transport's TLSNextProto mechanism casts to *tls.Conn which would panic;
	// http2.Transport accepts any net.Conn that exposes ConnectionState().
	h2Transport := &http2.Transport{
		// H2-level PING disabled — tunnel keepalive + net.Pipe EOF handle detection.
		ReadIdleTimeout: 0,
		// Chrome's SETTINGS frame values (from Wireshark captures of Chrome 120-133):
		//   SETTINGS_HEADER_TABLE_SIZE      = 65536  (Go default: 4096)
		//   SETTINGS_MAX_HEADER_LIST_SIZE   = 262144 (Go default: 10MB)
		// SETTINGS_INITIAL_WINDOW_SIZE (6291456) is not settable via public API.
		MaxDecoderHeaderTableSize: 65536,
		MaxHeaderListSize:         262144,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			rawConn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if tcpConn, ok := rawConn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				// 30-90s keepalive — matches Chrome's OS-default range on Android.
				tcpConn.SetKeepAlivePeriod(time.Duration(30+mrand.Intn(61)) * time.Second)
				// Disable Nagle: yamux WINDOW_UPDATE and control frames are tiny;
				// Nagle would hold them up to 200ms, stalling flow control.
				tcpConn.SetNoDelay(true)
			}
			uCfg := &utls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true,
			}
			if sc, ok := cfg.SessionCache.(utls.ClientSessionCache); ok {
				uCfg.ClientSessionCache = sc
			}
			uConn := utls.UClient(rawConn, uCfg, helloID)
			if err := uConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("chameleon: utls handshake: %w", err)
			}
			return uConn, nil
		},
	}

	pr, pw := io.Pipe()
	bpw := newBufferedPipeWriter(pw)
	url := fmt.Sprintf("https://%s%s", cfg.ServerAddr, path)

	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())

	req, err := http.NewRequestWithContext(tunnelCtx, http.MethodPost, url, pr)
	if err != nil {
		tunnelCancel()
		pr.Close(); bpw.Close()
		return nil, fmt.Errorf("chameleon: build request: %w", err)
	}
	req.Host = sni
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(headerToken, "Bearer "+token)
	req.Header.Set(headerSession, encodeSession(sessionID, anchor))
	applyBrowserHeaders(req, origin)

	local := staticAddr{"tcp", cfg.ServerAddr}
	remote := staticAddr{"tcp", cfg.ServerAddr}

	pc := newPipelinedConn(pr, bpw, tunnelCancel, local, remote)

	client := &http.Client{Transport: h2Transport}

	// Fire the POST in the background so yamux SETTINGS can be written to the
	// request body before the server's 200 OK arrives, saving one RTT on start.
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

	fc, err := NewFrameConn(pc, keys.DataSend, keys.DataRecv)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("chameleon: frame conn: %w", err)
	}

	go runDecoy(tunnelCtx, client, cfg.ServerAddr, sni, origin, bp)

	return newShapedConn(fc, sched), nil
}

// ListenAndServe runs the Chameleon HTTPS server.
// If TLSCert/TLSKey are set, uses manual certificates.
// Otherwise, if Domain is set, obtains a certificate from Let's Encrypt automatically.
func ListenAndServe(ctx context.Context, cfg *Config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, cfg)
	})

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":443"
	}

	var tlsCfg *tls.Config

	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("chameleon: load cert: %w", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS12,
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
		// http-01 challenge listener on :80 (best-effort — may fail if port is taken).
		go func() {
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				log.Printf("chameleon: acme http-01 listener: %v", err)
			}
		}()
		tlsCfg = m.TLSConfig()
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		tlsCfg.MinVersion = tls.VersionTLS12
		log.Printf("Chameleon: autocert for %s (cache: %s)", cfg.Domain, cacheDir)
	} else {
		return fmt.Errorf("chameleon: neither TLSCert nor Domain configured")
	}

	srv := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	// Without explicit H2 configuration Go uses the spec-default upload window of
	// 65535 bytes per stream.  At 20 ms RTT that caps the POST-body throughput at
	// ~3 MB/s (~26 Mbps) regardless of link capacity.  Set large windows so the
	// upload path is not the bottleneck for any realistic RTT.
	if err := http2.ConfigureServer(srv, &http2.Server{
		MaxUploadBufferPerConnection: 1 << 26, // 64 MB — connection-level receive window
		MaxUploadBufferPerStream:     1 << 24, // 16 MB — per-stream receive window
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
	tlsLn := tls.NewListener(&noDelayListener{rawLn.(*net.TCPListener)}, tlsCfg)
	log.Printf("Chameleon listening on %s", listenAddr)
	return srv.Serve(tlsLn)
}

// noDelayListener sets TCP_NODELAY (and keepalive) on every accepted connection.
// This ensures yamux WINDOW_UPDATE frames are sent immediately without Nagle batching.
type noDelayListener struct{ *net.TCPListener }

func (l *noDelayListener) Accept() (net.Conn, error) {
	tc, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(time.Duration(30+mrand.Intn(61)) * time.Second)
	tc.SetNoDelay(true)
	return tc, nil
}

func handleRequest(w http.ResponseWriter, r *http.Request, cfg *Config) {
	if r.Method != http.MethodPost {
		serveDecoy(w, r, cfg)
		return
	}

	log.Printf("chameleon: POST %s from %s", r.URL.Path, r.RemoteAddr)

	tokenHdr := r.Header.Get(headerToken)
	sessionHdr := r.Header.Get(headerSession)

	if len(tokenHdr) < 8 || tokenHdr[:7] != "Bearer " {
		serveDecoy(w, r, cfg)
		return
	}
	token := tokenHdr[7:]

	sessionID, anchor, err := decodeSession(sessionHdr)
	if err != nil {
		serveDecoy(w, r, cfg)
		return
	}

	// Resolve the shared secret and user ID by trying all registered users.
	secret, userID := resolveSecret(cfg, token, sessionID)
	if secret == nil {
		log.Printf("chameleon: auth failed from %s (token len=%d, session len=%d)", r.RemoteAddr, len(token), len(sessionHdr))
		serveDecoy(w, r, cfg)
		return
	}

	keys := DeriveKeys(secret, false)
	log.Printf("chameleon: authenticated user=%s from %s", userID, r.RemoteAddr)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("chameleon: ResponseWriter not a Flusher")
		return
	}

	sched := NewWindowScheduler(keys.Behavior, sessionID, anchor)

	local := staticAddr{"tcp", r.Host}
	remote := staticAddr{"tcp", r.RemoteAddr}

	done := make(chan struct{})
	h2s := newH2ServerConn(r.Body, w, flusher.Flush, local, remote, func() { close(done) })

	fc, err := NewFrameConn(h2s, keys.DataSend, keys.DataRecv)
	if err != nil {
		log.Printf("chameleon: frame conn: %v", err)
		return
	}

	shaped := newShapedConn(fc, sched)

	if cfg.OnConn != nil {
		cfg.OnConn(shaped, userID)
	}

	<-done
}

// DeriveSecret produces a 32-byte chameleon shared secret from a raw PSK.
func DeriveSecret(psk []byte) []byte {
	return DeriveKeys(psk, true).Auth[:32]
}

// resolveSecret tries cfg.SharedSecret first, then iterates GetUsers until HMAC matches.
// Returns (secret, userID) on success, or (nil, "") on failure.
func resolveSecret(cfg *Config, token string, sessionID []byte) ([]byte, string) {
	if cfg.GetUsers == nil {
		// Single-secret mode.
		k := DeriveKeys(cfg.SharedSecret, false)
		if VerifyAuthToken(k.Auth, token, sessionID) {
			return cfg.SharedSecret, "default"
		}
		return nil, ""
	}
	for _, u := range cfg.GetUsers() {
		if len(u.PSK) != 32 {
			continue
		}
		k := DeriveKeys(u.PSK, false)
		if VerifyAuthToken(k.Auth, token, sessionID) {
			return u.PSK, u.UserID
		}
	}
	return nil, ""
}

func serveDecoy(w http.ResponseWriter, r *http.Request, cfg *Config) {
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
		// Binary formats — return correct Content-Type with empty body.
		// Client discards the body; DPI sees the correct content-type fingerprint.
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

// runDecoy simulates a browser page-load cycle on the H2 connection:
//
//	Phase 0 — navigation (1 random entry point)
//	Phase 1 — critical subresources in parallel (JS + CSS)
//	Phase 2 — deferred resources in parallel (images, fonts)
//	Phase 3 — post-load API calls (sequential)
//	Idle     — randomized think-time before next cycle
//
// Timing is driven by BehaviorParams so each session has a distinct fingerprint.
func runDecoy(ctx context.Context, client *http.Client, serverAddr, sni, origin string, bp BehaviorParams) {
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

	sleep := func(ms int) bool {
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
			// stagger requests by 0–20 ms to mimic browser connection scheduler
			time.Sleep(time.Duration(mrand.Intn(20)) * time.Millisecond)
		}
		wg.Wait()
	}

	// Cover ticker: small API probe every 3–8 s to prevent POST-body silence
	// during the page-load idle phase.
	go func() {
		api := decoyGraph[3]
		for {
			ms := 3000 + mrand.Intn(5001)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(ms) * time.Millisecond):
			}
			get(api[mrand.Intn(len(api))])
		}
	}()

	for {
		// Phase 0 — navigation
		nav := decoyGraph[0]
		get(nav[mrand.Intn(len(nav))])
		if !sleep(bp.ParseDelayMs) {
			return
		}

		// Phase 1 — critical subresources
		parallel(decoyGraph[1], bp.BurstSize)
		if !sleep(20) {
			return
		}

		// Phase 2 — deferred resources
		parallel(decoyGraph[2], 1+mrand.Intn(2))
		if !sleep(bp.ParseDelayMs/2) {
			return
		}

		// Phase 3 — post-load API call
		api := decoyGraph[3]
		get(api[mrand.Intn(len(api))])

		// Idle: think-time before next page load
		if !sleep(bp.IdleSec * 1000) {
			return
		}
	}
}

// decoyProxy reverse-proxies GET requests to a real upstream so active probers
// receive genuine content. Responses are cached for 1 hour.
type decoyProxy struct {
	origin string
	client *http.Client
	mu     sync.RWMutex
	cache  map[string]*proxyCacheEntry
}

type proxyCacheEntry struct {
	status  int
	ct      string
	body    []byte
	expires time.Time
}

func newDecoyProxy(origin string) *decoyProxy {
	return &decoyProxy{
		origin: strings.TrimRight(origin, "/"),
		client: &http.Client{Timeout: 8 * time.Second},
		cache:  make(map[string]*proxyCacheEntry),
	}
}

func (p *decoyProxy) serve(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Path

	p.mu.RLock()
	entry, ok := p.cache[key]
	p.mu.RUnlock()
	if ok && time.Now().Before(entry.expires) {
		p.writeEntry(w, entry)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, p.origin+key, nil)
	if err != nil {
		p.writeStatic(w, r)
		return
	}
	if ua := r.Header.Get("User-Agent"); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := p.client.Do(req)
	if err != nil {
		p.writeStatic(w, r)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		p.writeStatic(w, r)
		return
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/html; charset=utf-8"
	}
	entry = &proxyCacheEntry{
		status:  resp.StatusCode,
		ct:      ct,
		body:    body,
		expires: time.Now().Add(time.Hour),
	}
	p.mu.Lock()
	p.cache[key] = entry
	p.mu.Unlock()

	p.writeEntry(w, entry)
}

func (p *decoyProxy) writeEntry(w http.ResponseWriter, e *proxyCacheEntry) {
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("Content-Type", e.ct)
	w.WriteHeader(e.status)
	w.Write(e.body)
}

func (p *decoyProxy) writeStatic(w http.ResponseWriter, r *http.Request) {
	serveDecoy(w, r, nil)
}
