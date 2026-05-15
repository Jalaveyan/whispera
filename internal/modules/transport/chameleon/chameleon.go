package chameleon

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"whispera/internal/logger"
)

var log = logger.Module("chameleon")

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
	ServerName string // SNI / Host header

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

// Client dials the Chameleon server and returns a net.Conn tunnel.
func Client(ctx context.Context, cfg *Config) (net.Conn, error) {
	sessionID := make([]byte, 16)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("chameleon: session id: %w", err)
	}
	anchor := time.Now().UTC().Truncate(time.Second)

	keys := DeriveKeys(cfg.SharedSecret, true)
	sched := NewWindowScheduler(keys.Behavior, sessionID, anchor)

	windowIdx := sched.CurrentIndex()
	bp := DeriveBehaviorParams(keys.Behavior, windowIdx, sessionID)
	path := GeneratePath(bp.PathSeed, windowIdx)
	token := AuthToken(keys.Auth, anchor.Unix()/30, sessionID)

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: cfg.ServerName, NextProtos: []string{"h2"}, InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			tc, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if tcpConn, ok := tc.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(4 * time.Second)
			}
			return tc, nil
		},
	}
	// HTTP/2 application-level PINGs keep NAT mappings alive on mobile networks.
	// ReadIdleTimeout triggers a PING after this much silence; if no PONG arrives
	// within PingTimeout the transport considers the connection dead and closes it.
	if h2t, err := http2.ConfigureTransports(transport); err == nil {
		h2t.ReadIdleTimeout = 5 * time.Second
		h2t.PingTimeout = 4 * time.Second
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
	req.Header.Set("Host", cfg.ServerName)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(headerToken, "Bearer "+token)
	req.Header.Set(headerSession, encodeSession(sessionID, anchor))

	client := &http.Client{Transport: transport}
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
