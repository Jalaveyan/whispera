package protocol

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	stdlog "log"
	mrand "math/rand"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	quicgo "github.com/quic-go/quic-go"
	http3 "github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

func quicConnContext(ctx context.Context, c *quicgo.Conn) context.Context {
	return context.WithValue(ctx, rtConnContextKey, c)
}

type noDelayListener struct {
	*net.TCPListener
}

type serverErrLogWriter struct{}

func (serverErrLogWriter) Write(p []byte) (int, error) {
	traceLog.Warnw("whispera_server_error", "msg", strings.TrimSpace(string(p)))
	return len(p), nil
}

func ListenAndServe(ctx context.Context, cfg *ServerConfig) error {
	cfg.initCond()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, cfg)
	})

	go func() {
		ticker := time.NewTicker(replayWindowSeconds * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cfg.seenTokens.sweep(time.Now().Unix())
			}
		}
	}()

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
			return fmt.Errorf("whispera: load cert: %w", err)
		}
		decoyCertDir := cfg.DecoyCertDir
		tlsCfg = &tls.Config{
			Certificates:     []tls.Certificate{cert},
			NextProtos:       []string{"h2", "http/1.1"},
			MinVersion:       tls.VersionTLS12,
			CipherSuites:     cdnCipherSuites,
			CurvePreferences: cdnCurves,
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				return nil, nil
			},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hello.ServerName != "" {
					if c, ok := loadSNICert(decoyCertDir, hello.ServerName); ok {
						return c, nil
					}
				}
				return &cert, nil
			},
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
	} else {
		return fmt.Errorf("whispera: neither TLSCert nor Domain configured")
	}

	srv := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: tlsCfg,
		ErrorLog:  stdlog.New(serverErrLogWriter{}, "", 0),
		ConnState: func(c net.Conn, state http.ConnState) {
			traceLog.Infow("whispera_conn_state", "remote", c.RemoteAddr().String(), "state", state.String())
		},
	}

	if err := http2.ConfigureServer(srv, &http2.Server{
		MaxUploadBufferPerConnection: 1 << 28,
		MaxUploadBufferPerStream:     1 << 26,
	}); err != nil {
		return fmt.Errorf("whispera: h2 server config: %w", err)
	}

	if cfg.DecoyOrigin != "" {
		cfg.proxy = newDecoyProxy(cfg.DecoyOrigin)
	}

	camoKeys := camoKeysFunc(cfg)
	camoAddr := camoDecoyAddr(cfg.DecoyOrigin)

	var h3srv *http3.Server
	var extraH3srvs []*http3.Server
	if cfg.QUICListenAddr != "" && cfg.TLSCert != "" {
		_, port, _ := net.SplitHostPort(cfg.QUICListenAddr)
		if port == "" {
			port = "443"
		}
		cfg.altSvcHeader = fmt.Sprintf(`h3=":%s"; ma=2592000`, port)
		h3srv = &http3.Server{
			Handler:     mux,
			TLSConfig:   http3.ConfigureTLSConfig(tlsCfg.Clone()),
			QUICConfig:  chromeLikeQUICConfig(),
			ConnContext: quicConnContext,
		}
		if pconn, err := net.ListenPacket("udp", cfg.QUICListenAddr); err == nil {
			camoConn := newQUICCamoConn(pconn, camoKeys, camoAddr)
			go func() {
				if err := h3srv.Serve(camoConn); err != nil {
				}
			}()
		}

		for _, extraQUICAddr := range cfg.ExtraQUICListenAddrs {
			extraQUICAddr := extraQUICAddr
			extraH3srv := &http3.Server{
				Handler:     mux,
				TLSConfig:   http3.ConfigureTLSConfig(tlsCfg.Clone()),
				QUICConfig:  chromeLikeQUICConfig(),
				ConnContext: quicConnContext,
			}
			extraH3srvs = append(extraH3srvs, extraH3srv)
			if pconn, err := net.ListenPacket("udp", extraQUICAddr); err == nil {
				camoConn := newQUICCamoConn(pconn, camoKeys, camoAddr)
				go func() {
					if err := extraH3srv.Serve(camoConn); err != nil {
					}
				}()
			}
		}
	}

	go func() {
		<-ctx.Done()
		if h3srv != nil {
			h3srv.Close()
		}
		for _, extraH3srv := range extraH3srvs {
			extraH3srv.Close()
		}
		srv.Close()
	}()

	for _, extraAddr := range cfg.ExtraListenAddrs {
		extraAddr := extraAddr
		extraLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", extraAddr)
		if err != nil {
			continue
		}
		extraBase := &noDelayListener{TCPListener: extraLn.(*net.TCPListener)}
		extraTLSLn := tls.NewListener(newCamouflageListener(extraBase, camoKeys, camoAddr), tlsCfg)
		go srv.Serve(extraTLSLn)
	}

	rawLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("whispera: listen: %w", err)
	}
	baseLn := &noDelayListener{TCPListener: rawLn.(*net.TCPListener)}
	tlsLn := tls.NewListener(newCamouflageListener(baseLn, camoKeys, camoAddr), tlsCfg)
	return srv.Serve(tlsLn)
}

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

func handleRequest(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
	_, cookieErr := r.Cookie(sessionCookie)
	hasSess := func() bool { return cookieErr == nil }

	switch r.Method {
	case http.MethodOptions:
		handleRESTOptions(w)
		return
	case http.MethodDelete:
		handleRESTDelete(w)
		return
	case http.MethodGet:
		path := r.URL.Path
		if path == "/video/sync" {
			handleFingerprintSync(w, r, cfg)
			return
		}
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
		traceLog.Infow("handle_request_decoy_fallback", "reason", "no_session_cookie", "method", r.Method, "remote", r.RemoteAddr)
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
		traceLog.Infow("handle_request_decoy_fallback", "reason", "no_session_cookie", "method", r.Method, "remote", r.RemoteAddr)
		serveDecoy(w, r, cfg)
		return
	default:
		serveDecoy(w, r, cfg)
		return
	}
}

func handleFingerprintSync(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
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

	secret, _ := resolveSecret(cfg, token, sessionID)
	if secret == nil {
		serveDecoy(w, r, cfg)
		return
	}
	if !cfg.consumeToken(token) {
		serveDecoy(w, r, cfg)
		return
	}

	records := HarvestedRawRecords()
	encoded := make([]string, 0, len(records))
	for _, rec := range records {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(rec))
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"fingerprints": encoded})
}

func handleClientStream(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
	tokenHdr := r.Header.Get(headerToken)
	if len(tokenHdr) < 8 || tokenHdr[:7] != "Bearer " {
		traceLog.Infow("client_stream_decoy_fallback", "reason", "missing_or_malformed_token_header", "remote", r.RemoteAddr)
		serveDecoy(w, r, cfg)
		return
	}
	token := tokenHdr[7:]

	sessCookie, err := r.Cookie(sessionCookie)
	if err != nil {
		traceLog.Infow("client_stream_decoy_fallback", "reason", "missing_session_cookie", "remote", r.RemoteAddr)
		serveDecoy(w, r, cfg)
		return
	}
	sessionID, _, err := decodeSession(sessCookie.Value)
	if err != nil {
		traceLog.Infow("client_stream_decoy_fallback", "reason", "session_decode_failed", "remote", r.RemoteAddr)
		serveDecoy(w, r, cfg)
		return
	}

	secret, userID := resolveSecret(cfg, token, sessionID)
	if secret == nil {
		traceLog.Infow("client_stream_decoy_fallback", "reason", "secret_not_resolved", "remote", r.RemoteAddr)
		serveDecoy(w, r, cfg)
		return
	}
	if !cfg.consumeToken(token) {
		traceLog.Infow("client_stream_decoy_fallback", "reason", "token_replay_or_expired", "remote", r.RemoteAddr, "user", userID)
		serveDecoy(w, r, cfg)
		return
	}

	startedAt := time.Now()
	traceLog.Infow("client_stream_authenticated",
		"user", userID,
		"remote", r.RemoteAddr,
		"proto", r.Proto,
		"content_length", r.ContentLength,
	)

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
	conn := newHTTPStreamConn(r.Body, w, flusher.Flush, local, remote, effectiveGANDecide(cfg, userID))
	fc := NewFrameConn(conn)

	if quicConn, ok := r.Context().Value(rtConnContextKey).(*quicgo.Conn); ok {
		RegisterRTQUICConn(sessionID, quicConn)
	}

	if cfg.OnConn != nil {
		cfg.OnConn(fc, userID)
	}

	select {
	case <-conn.done:
		traceLog.Infow("client_stream_closed",
			"reason", "conn_done",
			"remote", r.RemoteAddr,
			"dur_ms", time.Since(startedAt).Milliseconds(),
			"up_bytes", atomic.LoadInt64(&conn.upBytes),
			"down_bytes", atomic.LoadInt64(&conn.downBytes),
		)
	case <-r.Context().Done():
		traceLog.Warnw("client_stream_closed",
			"reason", "request_context_done",
			"remote", r.RemoteAddr,
			"dur_ms", time.Since(startedAt).Milliseconds(),
			"up_bytes", atomic.LoadInt64(&conn.upBytes),
			"down_bytes", atomic.LoadInt64(&conn.downBytes),
			"err", r.Context().Err().Error(),
		)
	}
}

func resolveSecret(cfg *ServerConfig, token string, sessionID []byte) ([]byte, string) {
	if len(cfg.SharedSecret) == 32 {
		k := DeriveKeys(cfg.SharedSecret)
		if VerifyAuthToken(k.Auth, token, sessionID) {
			return cfg.SharedSecret, "default"
		}
	}
	if cfg.GetUsers == nil {
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
	probeClockDriftOnFailure(cfg, token, sessionID)
	return nil, ""
}

func probeClockDriftOnFailure(cfg *ServerConfig, token string, sessionID []byte) {
	if len(cfg.SharedSecret) == 32 {
		k := DeriveKeys(cfg.SharedSecret)
		if drift, found := ProbeClockDrift(k.Auth, token, sessionID); found {
			traceLog.Warnw("whispera_auth_clock_drift_suspected", "user", "default", "drift_windows", drift, "drift_seconds", drift*authWindowSeconds)
			return
		}
	}
	if cfg.GetUsers == nil {
		return
	}
	for _, u := range cfg.GetUsers() {
		if len(u.PSK) != 32 {
			continue
		}
		k := DeriveKeys(u.PSK)
		if drift, found := ProbeClockDrift(k.Auth, token, sessionID); found {
			traceLog.Warnw("whispera_auth_clock_drift_suspected", "user", u.UserID, "drift_windows", drift, "drift_seconds", drift*authWindowSeconds)
			return
		}
	}
}
