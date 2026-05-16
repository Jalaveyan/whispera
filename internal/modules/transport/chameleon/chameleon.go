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
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"whispera/internal/logger"
)

var log = logger.Module("chameleon")

// chromeHelloPool — набор современных Chrome TLS-fingerprint-ов.
// Выбирается случайно per-connection, чтобы JA3 hash варьировался.
// Версии 120+ с post-quantum соответствуют реальным Chrome 120-133 на Android.
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

	// OnConn is called server-side for each authenticated tunnel connection.
	OnConn func(conn net.Conn, userID string)
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
		// 30-90s idle before PING — closer to real browser behaviour.
		ReadIdleTimeout: time.Duration(30+mrand.Intn(61)) * time.Second,
		PingTimeout:     time.Duration(10+mrand.Intn(11)) * time.Second,
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
			}
			uConn := utls.UClient(rawConn, &utls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true,
			}, helloID)
			if err := uConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("chameleon: utls handshake: %w", err)
			}
			return uConn, nil
		},
	}

	pr, pw := io.Pipe()
	url := fmt.Sprintf("https://%s%s", cfg.ServerAddr, path)

	// tunnelCtx controls the HTTP/2 POST lifetime (= tunnel lifetime).
	// Must NOT be tied to ctx: ctx carries a short ConnectionTimeout deadline
	// that only covers the dial phase. The TCP dial is already capped by
	// Dialer.Timeout=10s; once client.Do returns we have the connection and
	// tunnelCtx is canceled only when the caller closes the returned conn.
	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())

	req, err := http.NewRequestWithContext(tunnelCtx, http.MethodPost, url, pr)
	if err != nil {
		tunnelCancel()
		pr.Close(); pw.Close()
		return nil, fmt.Errorf("chameleon: build request: %w", err)
	}
	// req.Host sets HTTP/2 :authority pseudo-header; req.Header["Host"] is ignored by Go's h2 stack.
	req.Host = sni
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(headerToken, "Bearer "+token)
	req.Header.Set(headerSession, encodeSession(sessionID, anchor))
	applyBrowserHeaders(req, origin)

	client := &http.Client{Transport: h2Transport}
	resp, err := client.Do(req)
	if err != nil {
		tunnelCancel()
		pr.Close(); pw.Close()
		return nil, fmt.Errorf("chameleon: connect: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		tunnelCancel()
		pr.Close(); pw.Close(); resp.Body.Close()
		return nil, fmt.Errorf("chameleon: server rejected: %s", resp.Status)
	}

	local := staticAddr{"tcp", cfg.ServerAddr}
	remote := staticAddr{"tcp", cfg.ServerAddr}

	h2c := newH2ClientConn(pr, pw, resp.Body, tunnelCancel, local, remote)

	fc, err := NewFrameConn(h2c, keys.DataSend, keys.DataRecv)
	if err != nil {
		h2c.Close()
		return nil, fmt.Errorf("chameleon: frame conn: %w", err)
	}

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

	go func() { <-ctx.Done(); srv.Close() }()

	log.Printf("Chameleon listening on %s", listenAddr)
	return srv.ListenAndServeTLS("", "")
}

func handleRequest(w http.ResponseWriter, r *http.Request, cfg *Config) {
	if r.Method != http.MethodPost {
		serveDecoy(w, r)
		return
	}

	log.Printf("chameleon: POST %s from %s", r.URL.Path, r.RemoteAddr)

	tokenHdr := r.Header.Get(headerToken)
	sessionHdr := r.Header.Get(headerSession)

	if len(tokenHdr) < 8 || tokenHdr[:7] != "Bearer " {
		serveDecoy(w, r)
		return
	}
	token := tokenHdr[7:]

	sessionID, anchor, err := decodeSession(sessionHdr)
	if err != nil {
		serveDecoy(w, r)
		return
	}

	// Resolve the shared secret and user ID by trying all registered users.
	secret, userID := resolveSecret(cfg, token, sessionID)
	if secret == nil {
		log.Printf("chameleon: auth failed from %s (token len=%d, session len=%d)", r.RemoteAddr, len(token), len(sessionHdr))
		serveDecoy(w, r)
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

	// Download-padding goroutine: sends encrypted frameTypePad frames that the client
	// discards silently. Inflates server→client bytes so the upload/download ratio
	// shifts from ~50/50 toward browser-like ~20/80, defeating NetFlow ML classifiers.
	go func() {
		for {
			delay := time.Duration(100+mrand.Intn(300)) * time.Millisecond
			select {
			case <-done:
				return
			case <-time.After(delay):
			}
			if err := fc.WritePadding(1024 + mrand.Intn(7168)); err != nil {
				return
			}
		}
	}()

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

func serveDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("Cache-Control", "max-age=3600")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "<!DOCTYPE html><html><head><title></title></head><body></body></html>\n")
}
