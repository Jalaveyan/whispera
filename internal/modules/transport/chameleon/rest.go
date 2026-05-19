package chameleon

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	crand "crypto/rand"
	"crypto/tls"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// mp4FtypAtom is a minimal valid MP4 ftyp box prepended to every download
// response so the first bytes match the MP4 signature that DPI sniffers check.
// size=24 "ftyp" major="isom" ver=0x200 compat="isom","mp42"
var mp4FtypAtom = [24]byte{
	0x00, 0x00, 0x00, 0x18,
	0x66, 0x74, 0x79, 0x70,
	0x69, 0x73, 0x6F, 0x6D,
	0x00, 0x00, 0x02, 0x00,
	0x69, 0x73, 0x6F, 0x6D,
	0x6D, 0x70, 0x34, 0x32,
}

// ── REST path tables ────────────────────────────────────────────────────────

var restDownloadPaths = []string{
	"/api/v1/events",
	"/api/v2/events",
	"/api/v1/stream",
	"/api/v2/stream",
	"/api/v1/notifications",
	"/api/v2/feed",
	"/api/v1/subscribe",
	"/api/v2/updates",
}

var restUploadPathsByMethod = map[string][]string{
	http.MethodPost: {
		"/api/v1/messages",
		"/api/v2/messages",
		"/api/v1/actions",
		"/api/v2/data",
		"/api/v1/events",
		"/api/v2/upload",
	},
	http.MethodPut: {
		"/api/v1/session",
		"/api/v2/session",
		"/api/v1/state",
		"/api/v2/state",
	},
	http.MethodPatch: {
		"/api/v1/settings",
		"/api/v2/settings",
		"/api/v1/config",
		"/api/v2/preferences",
	},
}

// POST 60%, PUT 20%, PATCH 20%
var restUploadMethods = []string{
	http.MethodPost, http.MethodPost, http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
}

var restDecoyDeletePaths = []string{
	"/api/v1/cache",
	"/api/v2/cache",
	"/api/v1/temp",
	"/api/v2/temp",
}

func restDownloadPath(seed uint64) string {
	return restDownloadPaths[int(seed>>32)%len(restDownloadPaths)]
}


func restUploadPath(method string) string {
	paths := restUploadPathsByMethod[method]
	if len(paths) == 0 {
		paths = restUploadPathsByMethod[http.MethodPost]
	}
	return paths[mrand.Intn(len(paths))]
}

// ── GAN shaping interface ────────────────────────────────────────────────────

// GANAction is returned by GANDecideFunc to shape individual writes.
type GANAction struct {
	SleepMs  float64 // sleep before the write to match target IAT distribution
	PaddingN int     // bytes of padding to inject between data writes (0 = none)
}

// GANDecideFunc is called on every write with live flow stats.
// iatMean — mean inter-write interval (seconds) so far in this session.
// sizeMean — mean write size (bytes) so far.
// upRatio — fraction of bytes that were uploads (for server-side always 0).
type GANDecideFunc func(iatMean, sizeMean, upRatio float64) GANAction

// ── Server-side session ──────────────────────────────────────────────────────

// restSession is created by the GET handler and written to by POST/PUT/PATCH handlers.
// secret is cached so upload handlers don't need to call resolveSecret on every request.
type restSession struct {
	uploadCh chan []byte
	closed   chan struct{}
	secret   []byte
}

// ── Server-side net.Conn ─────────────────────────────────────────────────────

type restServerConn struct {
	sess    *restSession
	readBuf []byte

	w       io.Writer
	flusher http.Flusher

	done    chan struct{}
	once    sync.Once
	onClose func()

	localAddr  net.Addr
	remoteAddr net.Addr

	// live flow stats for GAN shaping
	ganDecide  GANDecideFunc
	lastWrite  time.Time
	iatSum     float64
	sizeSum    float64
	writeCount float64
}

func newRestServerConn(sess *restSession, w http.ResponseWriter, local, remote net.Addr, onClose func(), ganDecide GANDecideFunc) *restServerConn {
	flusher, _ := w.(http.Flusher)
	return &restServerConn{
		sess:      sess,
		w:         w,
		flusher:   flusher,
		ganDecide: ganDecide,
		done:       make(chan struct{}),
		onClose:    onClose,
		localAddr:  local,
		remoteAddr: remote,
	}
}

func (c *restServerConn) Read(b []byte) (int, error) {
	for {
		if len(c.readBuf) > 0 {
			n := copy(b, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}
		select {
		case chunk, ok := <-c.sess.uploadCh:
			if !ok {
				return 0, io.EOF
			}
			n := copy(b, chunk)
			if n < len(chunk) {
				c.readBuf = append(c.readBuf[:0], chunk[n:]...)
			}
			return n, nil
		case <-c.done:
			return 0, io.EOF
		}
	}
}

func (c *restServerConn) Write(b []byte) (n int, err error) {
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, io.ErrClosedPipe
		}
	}()

	// GAN-driven timing shaping.
	if c.ganDecide != nil {
		now := time.Now()
		if !c.lastWrite.IsZero() {
			iat := now.Sub(c.lastWrite).Seconds()
			c.iatSum += iat
		}
		c.sizeSum += float64(len(b))
		c.writeCount++
		iatMean := 0.0
		if c.writeCount > 1 {
			iatMean = c.iatSum / (c.writeCount - 1)
		}
		action := c.ganDecide(iatMean, c.sizeSum/c.writeCount, 0)
		if action.SleepMs > 0.5 {
			time.Sleep(time.Duration(action.SleepMs * float64(time.Millisecond)))
		}
		c.lastWrite = time.Now()
	}

	n, err = c.w.Write(b)
	if err != nil {
		c.Close()
		return n, err
	}
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return n, nil
}

func (c *restServerConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *restServerConn) LocalAddr() net.Addr               { return c.localAddr }
func (c *restServerConn) RemoteAddr() net.Addr              { return c.remoteAddr }
func (c *restServerConn) SetDeadline(t time.Time) error     { return nil }
func (c *restServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *restServerConn) SetWriteDeadline(t time.Time) error { return nil }

// ── Client-side net.Conn ─────────────────────────────────────────────────────

type restClientConn struct {
	// Read side: GET response body piped here
	readConn net.Conn
	readPeer net.Conn

	// Write side: queued data sent as POST/PUT/PATCH chunks
	uploadCh chan []byte

	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newRestClientConn(ctx context.Context, cancel context.CancelFunc, local, remote net.Addr) *restClientConn {
	rc, rp := net.Pipe()
	return &restClientConn{
		readConn:   rc,
		readPeer:   rp,
		uploadCh:   make(chan []byte, 512),
		ctx:        ctx,
		cancel:     cancel,
		localAddr:  local,
		remoteAddr: remote,
	}
}

func (c *restClientConn) Read(b []byte) (int, error) { return c.readConn.Read(b) }

// Write enqueues b for upload. Times out after 5s so a stalled network
// cannot block yamux keepalives indefinitely.
func (c *restClientConn) Write(b []byte) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case c.uploadCh <- cp:
		return len(b), nil
	case <-c.ctx.Done():
		return 0, io.ErrClosedPipe
	case <-time.After(5 * time.Second):
		return 0, fmt.Errorf("chameleon: upload channel full")
	}
}

func (c *restClientConn) Close() error {
	c.once.Do(func() {
		c.readConn.Close()
		c.readPeer.Close()
		c.cancel()
	})
	return nil
}

func (c *restClientConn) LocalAddr() net.Addr               { return c.localAddr }
func (c *restClientConn) RemoteAddr() net.Addr              { return c.remoteAddr }
func (c *restClientConn) SetDeadline(t time.Time) error     { return c.readConn.SetDeadline(t) }
func (c *restClientConn) SetReadDeadline(t time.Time) error  { return c.readConn.SetReadDeadline(t) }
func (c *restClientConn) SetWriteDeadline(t time.Time) error { return nil }


// ── Client goroutines ────────────────────────────────────────────────────────

// runRESTUpload drains uploadCh and sends data as sequential POST/PUT/PATCH
// requests. Sequential ordering is required: FrameConn uses a per-frame counter
// as the ChaCha20-Poly1305 nonce — concurrent requests can arrive at the server
// out of order and break the counter sequence, causing MAC failures.
func runRESTUpload(ctx context.Context, client *http.Client, serverAddr, sni, origin, sessionHdr, token string, uploadCh <-chan []byte) {
	var buf []byte
	for {
		buf = buf[:0]

		// Block until first chunk — zero spin when idle.
		select {
		case data := <-uploadCh:
			buf = append(buf, data...)
		case <-ctx.Done():
			return
		}

		// Non-blocking drain: grab everything already queued without waiting.
		// Sparse traffic (pings, DNS) sends immediately; bulk traffic batches
		// naturally because the channel is already full.
	drain:
		for len(buf) < 32*1024 {
			select {
			case data := <-uploadCh:
				buf = append(buf, data...)
			case <-ctx.Done():
				return
			default:
				break drain
			}
		}

		method := restUploadMethods[mrand.Intn(len(restUploadMethods))]
		path := restUploadPath(method)
		url := fmt.Sprintf("https://%s%s", serverAddr, path)

		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(buf))
		if err != nil {
			continue
		}
		req.Host = sni
		req.Header.Set("Content-Type", contentType)
		req.Header.Set(headerToken, "Bearer "+token)
		req.Header.Set(headerSession, sessionHdr)
		req.Header.Set("X-Transport", "rest")
		applyBrowserHeaders(req, origin)

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// runRESTDecoy sends periodic DELETE and OPTIONS requests (no auth) to simulate
// normal browser cache cleanup and CORS preflight activity.
func runRESTDecoy(ctx context.Context, client *http.Client, serverAddr, sni, origin string) {
	doDelete := func() {
		path := restDecoyDeletePaths[mrand.Intn(len(restDecoyDeletePaths))]
		suffix := hex.EncodeToString([]byte{byte(mrand.Intn(256)), byte(mrand.Intn(256)), byte(mrand.Intn(256))})
		url := fmt.Sprintf("https://%s%s/%s", serverAddr, path, suffix)
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
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

	doOptions := func() {
		paths := restUploadPathsByMethod[http.MethodPost]
		path := paths[mrand.Intn(len(paths))]
		url := fmt.Sprintf("https://%s%s", serverAddr, path)
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, url, nil)
		if err != nil {
			return
		}
		req.Host = sni
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type,authorization")
		applyBrowserHeaders(req, origin)
		if resp, err := client.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(30000+mrand.Intn(60000)) * time.Millisecond):
				doDelete()
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(10000+mrand.Intn(20000)) * time.Millisecond):
				doOptions()
			}
		}
	}()
}

// ── RESTClient ───────────────────────────────────────────────────────────────

// RESTClient connects to the chameleon server using the REST transport:
// a persistent GET for the download channel and short POST/PUT/PATCH chunks
// for the upload channel, together resembling a real-time web app.
func RESTClient(ctx context.Context, cfg *Config) (net.Conn, error) {
	sessionID := make([]byte, 16)
	if _, err := crand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("chameleon: session id: %w", err)
	}
	anchor := time.Now().UTC().Truncate(time.Second)

	keys := DeriveKeys(cfg.SharedSecret, true)
	sched := NewWindowScheduler(keys.Behavior, sessionID, anchor)

	windowIdx := sched.CurrentIndex()
	bp := DeriveBehaviorParams(keys.Behavior, windowIdx, sessionID)
	token := AuthToken(keys.Auth, anchor.Unix()/30, sessionID)
	sessionHdr := encodeSession(sessionID, anchor)

	sni := pickSNI(cfg)
	origin := "https://" + sni

	helloID := chromeHelloPool[mrand.Intn(len(chromeHelloPool))]

	h2t := &http2.Transport{
		ReadIdleTimeout:           0,
		MaxDecoderHeaderTableSize: 65536,
		MaxHeaderListSize:         262144,
		DialTLSContext: func(dialCtx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			rawConn, err := d.DialContext(dialCtx, network, addr)
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
			if err := uConn.HandshakeContext(dialCtx); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("chameleon: utls handshake: %w", err)
			}
			return uConn, nil
		},
	}

	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())

	local := staticAddr{"tcp", cfg.ServerAddr}
	remote := staticAddr{"tcp", cfg.ServerAddr}

	conn := newRestClientConn(tunnelCtx, tunnelCancel, local, remote)
	client := &http.Client{Transport: h2t}

	// Start GET goroutine first; signal when server returns 200 (session ready).
	getReady := make(chan error, 1)
	go func() {
		path := restDownloadPath(bp.PathSeed)
		url := fmt.Sprintf("https://%s%s", cfg.ServerAddr, path)

		req, err := http.NewRequestWithContext(tunnelCtx, http.MethodGet, url, nil)
		if err != nil {
			conn.readPeer.Close()
			getReady <- err
			return
		}
		req.Host = sni
		req.Header.Set("Accept", contentTypeDownload)
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set(headerToken, "Bearer "+token)
		req.Header.Set(headerSession, sessionHdr)
		req.Header.Set("X-Transport", "rest")
		applyBrowserHeaders(req, origin)

		resp, err := client.Do(req)
		if err != nil {
			conn.readPeer.Close()
			getReady <- err
			return
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			conn.readPeer.Close()
			getReady <- fmt.Errorf("chameleon: GET %d", resp.StatusCode)
			return
		}

		// GET established — signal success, skip MP4 header, then pipe.
		getReady <- nil
		defer resp.Body.Close()
		io.ReadFull(resp.Body, make([]byte, len(mp4FtypAtom)))
		io.Copy(conn.readPeer, resp.Body)
		conn.readPeer.Close()
	}()

	// Wait for the GET stream to establish before accepting the conn.
	select {
	case err := <-getReady:
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("chameleon: REST GET: %w", err)
		}
	case <-time.After(10 * time.Second):
		conn.Close()
		return nil, fmt.Errorf("chameleon: REST GET timeout")
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}

	// Upload and decoy goroutines start only after GET is live.
	go runRESTUpload(tunnelCtx, client, cfg.ServerAddr, sni, origin, sessionHdr, token, conn.uploadCh)
	go runRESTDecoy(tunnelCtx, client, cfg.ServerAddr, sni, origin)

	fc, err := NewFrameConn(conn, keys.DataSend, keys.DataRecv)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("chameleon: frame conn: %w", err)
	}

	return fc, nil
}

// ── Server handlers ──────────────────────────────────────────────────────────

// handleRESTDownload handles GET requests that establish the download channel.
func handleRESTDownload(w http.ResponseWriter, r *http.Request, cfg *Config) {
	tokenHdr := r.Header.Get(headerToken)
	sessionHdr := r.Header.Get(headerSession)

	if len(tokenHdr) < 8 || tokenHdr[:7] != "Bearer " {
		serveDecoy(w, r, cfg)
		return
	}
	token := tokenHdr[7:]

	sessionID, _, err := decodeSession(sessionHdr)
	if err != nil {
		serveDecoy(w, r, cfg)
		return
	}

	secret, userID := resolveSecret(cfg, token, sessionID)
	if secret == nil {
		log.Printf("chameleon: REST auth failed from %s", r.RemoteAddr)
		serveDecoy(w, r, cfg)
		return
	}

	keys := DeriveKeys(secret, false)
	log.Printf("chameleon: REST authenticated user=%s from %s", userID, r.RemoteAddr)

	// Store session before sending 200 so that upload handlers can find it
	// immediately after the client receives the OK response.
	sess := &restSession{
		uploadCh: make(chan []byte, 128),
		closed:   make(chan struct{}),
		secret:   secret,
	}
	sessionKey := hex.EncodeToString(sessionID)
	cfg.sessions.Store(sessionKey, sess)
	defer func() {
		close(sess.closed)
		cfg.sessions.Delete(sessionKey)
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("chameleon: REST ResponseWriter not a Flusher")
		return
	}

	w.Header().Set("Content-Type", contentTypeDownload)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write(mp4FtypAtom[:])
	flusher.Flush()

	local := staticAddr{"tcp", r.Host}
	remote := staticAddr{"tcp", r.RemoteAddr}

	done := make(chan struct{})
	conn := newRestServerConn(sess, w, local, remote, func() { close(done) }, cfg.GANDecide)

	// Close conn if the HTTP request context dies (client disconnect).
	go func() {
		select {
		case <-r.Context().Done():
			conn.Close()
		case <-done:
		}
	}()

	fc, err := NewFrameConn(conn, keys.DataSend, keys.DataRecv)
	if err != nil {
		log.Printf("chameleon: REST frame conn: %v", err)
		return
	}

	// Padding goroutine: inject encrypted random-byte frames on a fixed cadence
	// to break per-packet size fingerprinting while the tunnel is active.
	if cfg.GANDecide != nil {
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					action := cfg.GANDecide(0, 0, 0)
					if action.PaddingN > 0 {
						fc.WritePad(action.PaddingN) //nolint:errcheck
					}
				}
			}
		}()
	}

	if cfg.OnConn != nil {
		cfg.OnConn(fc, userID)
	}

	<-done
}

// handleRESTUpload handles POST/PUT/PATCH requests that feed the upload channel.
// Authentication is implicit: the 16-byte random sessionID is a capability token —
// only a client that received a valid GET 200 knows it. No resolveSecret needed.
func handleRESTUpload(w http.ResponseWriter, r *http.Request, cfg *Config) {
	sessionHdr := r.Header.Get(headerSession)

	sessionID, _, err := decodeSession(sessionHdr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionKey := hex.EncodeToString(sessionID)

	// Wait up to 3s for the GET handler to register the session.
	var sess *restSession
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if val, ok := cfg.sessions.Load(sessionKey); ok {
			sess = val.(*restSession)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sess == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 700*1024))
	r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(body) > 0 {
		select {
		case sess.uploadCh <- body:
		case <-sess.closed:
			w.WriteHeader(http.StatusGone)
			return
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusRequestTimeout)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"ok":true}`)); err != nil {
		log.Printf("chameleon: REST upload response: %v", err)
	}
}

// handleRESTOptions returns CORS preflight response (decoy + real functionality).
func handleRESTOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Id, X-Transport")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

// handleRESTDelete returns a realistic DELETE response (decoy).
func handleRESTDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"deleted":true}`)); err != nil {
		log.Printf("chameleon: REST delete response: %v", err)
	}
}
