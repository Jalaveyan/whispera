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

func NewSessionCache(capacity int) any {
	return utls.NewLRUClientSessionCache(capacity)
}

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

const maxConnsPerUser = 4

type userConnEntry struct {
	close func()
}

type connRegistry struct {
	mu    sync.Mutex
	conns map[string][]*userConnEntry
}

func (r *connRegistry) tryAdd(userID string) (*userConnEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.conns[userID]) >= maxConnsPerUser {
		return nil, false
	}
	e := &userConnEntry{}
	r.conns[userID] = append(r.conns[userID], e)
	return e, true
}

func (r *connRegistry) remove(userID string, e *userConnEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.conns[userID]
	for i, v := range list {
		if v == e {
			r.conns[userID] = append(list[:i], list[i+1:]...)
			return
		}
	}
}

type UserEntry struct {
	UserID string
	PSK    []byte
}

type Config struct {
	ListenAddr string
	TLSCert string
	TLSKey  string
	Domain  string
	ACMEDir string

	GetUsers func() []UserEntry

	ServerAddr string
	ServerName string

	ServerNames []string

	SharedSecret []byte

	SessionCache any

	DecoyOrigin string

	OnConn func(conn net.Conn, userID string)

	proxy    *decoyProxy
	registry *connRegistry
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

func pickSNI(cfg *Config) string {
	if len(cfg.ServerNames) > 0 {
		return cfg.ServerNames[mrand.Intn(len(cfg.ServerNames))]
	}
	return cfg.ServerName
}

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

	helloID := chromeHelloPool[mrand.Intn(len(chromeHelloPool))]

	h2Transport := &http2.Transport{
		ReadIdleTimeout: 0,
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
				tcpConn.SetKeepAlivePeriod(time.Duration(30+mrand.Intn(61)) * time.Second)
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

	if err := http2.ConfigureServer(srv, &http2.Server{
		MaxUploadBufferPerConnection: 1 << 26,
		MaxUploadBufferPerStream:     1 << 24,
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

	secret, userID := resolveSecret(cfg, token, sessionID)
	if secret == nil {
		log.Printf("chameleon: auth failed from %s (token len=%d, session len=%d)", r.RemoteAddr, len(token), len(sessionHdr))
		serveDecoy(w, r, cfg)
		return
	}

	keys := DeriveKeys(secret, false)
	log.Printf("chameleon: authenticated user=%s from %s", userID, r.RemoteAddr)

	w.Header().Set("Content-Type", contentTypeForPath(r.URL.Path))
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

	if cfg.registry != nil {
		entry, ok := cfg.registry.tryAdd(userID)
		if !ok {
			h2s.Close()
			return
		}
		defer cfg.registry.remove(userID, entry)
	}

	if cfg.OnConn != nil {
		cfg.OnConn(shaped, userID)
	}

	<-done
}

func DeriveSecret(psk []byte) []byte {
	return DeriveKeys(psk, true).Auth[:32]
}

func resolveSecret(cfg *Config, token string, sessionID []byte) ([]byte, string) {
	if cfg.GetUsers == nil {
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

func contentTypeForPath(path string) string {
	switch {
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(path, ".json"):
		return "application/json; charset=utf-8"
	case strings.HasSuffix(path, ".bin"):
		return "application/octet-stream"
	default:
		return "text/html; charset=utf-8"
	}
}

func runDecoy(ctx context.Context, client *http.Client, serverAddr, sni, origin string, bp BehaviorParams) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(200+mrand.Intn(300)) * time.Millisecond):
	}

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
			get(api[mrand.Intn(len(api))])
		}
	}()

	for {
		nav := decoyGraph[0]
		get(nav[mrand.Intn(len(nav))])
		if !sleep(bp.ParseDelayMs) {
			return
		}

		parallel(decoyGraph[1], bp.BurstSize)
		if !sleep(20) {
			return
		}

		parallel(decoyGraph[2], 1+mrand.Intn(2))
		if !sleep(bp.ParseDelayMs/2) {
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
