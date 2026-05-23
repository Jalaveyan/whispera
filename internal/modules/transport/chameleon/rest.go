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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// ── HLS path helpers ─────────────────────────────────────────────────────────

func hlsSessionKey(sessionID []byte) string { return hex.EncodeToString(sessionID) }

func hlsPlaylistPath(sessionID []byte) string {
	return "/video/" + hlsSessionKey(sessionID) + "/index.m3u8"
}

func hlsSegmentPath(sessionID []byte, n uint64) string {
	return fmt.Sprintf("/video/%s/seg%04d.ts", hlsSessionKey(sessionID), n)
}

// hlsKeyFromPath extracts the 32-hex session key from an HLS URL path.
func hlsKeyFromPath(path string) string {
	parts := strings.SplitN(path, "/", 4) // ["","video","{key}","seg*.ts"]
	if len(parts) < 4 || parts[1] != "video" || len(parts[2]) != 32 {
		return ""
	}
	return parts[2]
}

// hlsM3U8 returns a minimal live-HLS playlist; segment names are relative.
func hlsM3U8(startSeg uint64) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:4\n")
	fmt.Fprintf(&sb, "#EXT-X-MEDIA-SEQUENCE:%d\n", startSeg)
	for i := uint64(0); i < 3; i++ {
		fmt.Fprintf(&sb, "#EXTINF:3.840,\nseg%04d.ts\n", startSeg+i)
	}
	return sb.String()
}

// ── HLS segment routing ──────────────────────────────────────────────────────

// segSlot carries one HTTP response writer to the segmentRouter.
// The segment handler blocks until done is closed by the router.
type segSlot struct {
	w     io.Writer
	flush func()
	done  chan struct{}
}

// segmentRouter implements io.Writer, routing FrameConn frames across sequential
// HTTP segment responses. Each call to Write() is one complete encrypted frame.
// A segment ends (at a frame boundary) once its byte budget is exhausted.
type segmentRouter struct {
	sess        *restSession
	behaviorKey []byte
	connDone    chan struct{}

	mu         sync.Mutex
	curSlot    *segSlot
	bytesInSeg int
	segSize    int
	segIdx     uint64
}

func newSegmentRouter(sess *restSession, behaviorKey []byte, connDone chan struct{}) *segmentRouter {
	return &segmentRouter{sess: sess, behaviorKey: behaviorKey, connDone: connDone}
}

func (r *segmentRouter) acquireSlot() (*segSlot, error) {
	r.mu.Lock()
	s := r.curSlot
	r.mu.Unlock()
	if s != nil {
		return s, nil
	}
	select {
	case s, ok := <-r.sess.segCh:
		if !ok {
			return nil, io.ErrClosedPipe
		}
		r.mu.Lock()
		r.curSlot = &s
		r.bytesInSeg = 0
		r.segSize = DeriveSegmentSize(r.behaviorKey, r.segIdx)
		r.mu.Unlock()
		return &s, nil
	case <-r.connDone:
		return nil, io.ErrClosedPipe
	}
}

// Write routes one encrypted frame to the current segment, rotating to the
// next segment after the budget is reached.
func (r *segmentRouter) Write(b []byte) (int, error) {
	s, err := r.acquireSlot()
	if err != nil {
		return 0, err
	}

	n, err := s.w.Write(b)
	s.flush()

	r.mu.Lock()
	r.bytesInSeg += n
	full := r.bytesInSeg >= r.segSize
	if full {
		r.curSlot = nil
		r.segIdx++
	}
	r.mu.Unlock()

	if full {
		close(s.done)
	}
	return n, err
}

// ── REST path tables ────────────────────────────────────────────────────────

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
// upRatio — fraction of bytes that were uploads (upload/(upload+download)).
type GANDecideFunc func(iatMean, sizeMean, upRatio float64) GANAction

// StreamingBiasGANDecide returns a GANDecideFunc that injects padding bytes into
// the download stream to maintain the target download/upload ratio.
// targetRatio = desired download-to-upload ratio (e.g. 10.0 for HLS video streaming).
// When the observed upRatio is above target, padding nudges the ratio back down.
func StreamingBiasGANDecide(targetRatio float64) GANDecideFunc {
	targetUpRatio := 1.0 / (1.0 + targetRatio)
	return func(_, _, upRatio float64) GANAction {
		if upRatio <= targetUpRatio*1.5 {
			return GANAction{}
		}
		excess := upRatio - targetUpRatio
		paddingN := int(excess * 32 * 1024)
		if paddingN > 32*1024 {
			paddingN = 32 * 1024
		}
		if paddingN < 128 {
			return GANAction{}
		}
		return GANAction{PaddingN: paddingN}
	}
}

// ── Server-side session ──────────────────────────────────────────────────────

// restSession is created by the download handler and written to by upload handlers.
type restSession struct {
	uploadCh      chan []byte
	segCh         chan segSlot // HLS: sequential segment writers arrive here (buffered 1)
	closed        chan struct{}
	secret        []byte
	uploadBytes   int64 // atomic — cumulative upload bytes for upRatio computation
	downloadBytes int64 // atomic — cumulative download bytes for upRatio computation
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

func newRestServerConn(sess *restSession, w io.Writer, local, remote net.Addr, onClose func(), ganDecide GANDecideFunc) *restServerConn {
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
		up := float64(atomic.LoadInt64(&c.sess.uploadBytes))
		down := float64(atomic.LoadInt64(&c.sess.downloadBytes))
		upRatio := 0.0
		if up+down > 0 {
			upRatio = up / (up + down)
		}
		action := c.ganDecide(iatMean, c.sizeSum/c.writeCount, upRatio)
		if action.SleepMs > 0.5 {
			time.Sleep(time.Duration(action.SleepMs * float64(time.Millisecond)))
		}
		c.lastWrite = time.Now()
	}

	n, err = c.w.Write(b)
	if n > 0 {
		atomic.AddInt64(&c.sess.downloadBytes, int64(n))
	}
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
		for len(buf) < 512*1024 {
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
		applyBrowserHeaders(req, origin)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionHdr})

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
	token := AuthToken(keys.Auth, anchor.Unix()/30, sessionID)
	sessionHdr := encodeSession(sessionID, anchor)

	sni := pickSNI(cfg)
	origin := "https://" + sni

	helloID := chromeHelloPool[mrand.Intn(len(chromeHelloPool))]

	h2t := &http2.Transport{
		ReadIdleTimeout:           0,
		MaxDecoderHeaderTableSize: 65536,
		MaxHeaderListSize:         262144,
		DisableCompression:        true,
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

	// hlsGet issues one authenticated GET and returns the response.
	hlsGet := func(path string) (*http.Response, error) {
		u := fmt.Sprintf("https://%s%s", cfg.ServerAddr, path)
		req, err := http.NewRequestWithContext(tunnelCtx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Host = sni
		req.Header.Set(headerToken, "Bearer "+token)
		applyBrowserHeaders(req, origin)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionHdr})
		return client.Do(req)
	}

	// 1. GET playlist — establishes the session on the server.
	playlistReady := make(chan error, 1)
	go func() {
		resp, err := hlsGet(hlsPlaylistPath(sessionID))
		if err != nil {
			playlistReady <- fmt.Errorf("chameleon: HLS playlist: %w", err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			playlistReady <- fmt.Errorf("chameleon: HLS playlist %d", resp.StatusCode)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		playlistReady <- nil
	}()

	select {
	case err := <-playlistReady:
		if err != nil {
			conn.Close()
			return nil, err
		}
	case <-time.After(10 * time.Second):
		conn.Close()
		return nil, fmt.Errorf("chameleon: HLS playlist timeout")
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}

	// 2. Sequential segment GETs with 1-slot pre-fetch.
	// Pre-fetching starts immediately when a segment response arrives (before
	// reading its body), giving the full segment read time as pre-fetch window.
	type segResult struct {
		resp *http.Response
		err  error
	}
	fetchSeg := func(n uint64) <-chan segResult {
		ch := make(chan segResult, 1)
		go func() {
			resp, err := hlsGet(hlsSegmentPath(sessionID, n))
			if err != nil {
				ch <- segResult{nil, err}
				return
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				ch <- segResult{nil, fmt.Errorf("chameleon: HLS seg%d %d", n, resp.StatusCode)}
				return
			}
			ch <- segResult{resp, nil}
		}()
		return ch
	}

	go func() {
		defer conn.readPeer.Close()
		nextCh := fetchSeg(0)
		for segIdx := uint64(0); ; segIdx++ {
			res := <-nextCh
			if res.err != nil {
				return
			}
			// Pre-fetch next segment while reading current one.
			nextCh = fetchSeg(segIdx + 1)
			if _, err := io.Copy(conn.readPeer, res.resp.Body); err != nil {
				res.resp.Body.Close()
				return
			}
			res.resp.Body.Close()
		}
	}()

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
	sessCookie, cookieErr := r.Cookie(sessionCookie)

	if len(tokenHdr) < 8 || tokenHdr[:7] != "Bearer " {
		serveDecoy(w, r, cfg)
		return
	}
	token := tokenHdr[7:]

	if cookieErr != nil {
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
		log.Printf("chameleon: REST auth failed from %s", r.RemoteAddr)
		serveDecoy(w, r, cfg)
		return
	}

	keys := DeriveKeys(secret, false)
	log.Printf("chameleon: REST authenticated user=%s from %s", userID, r.RemoteAddr)

	// Store session before sending 200 so that upload handlers can find it
	// immediately after the client receives the OK response.
	sess := &restSession{
		uploadCh: make(chan []byte, 512),
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

	decide := cfg.GANDecide
	if decide == nil {
		ratio := cfg.AsymBiasRatio
		if ratio <= 0 {
			ratio = 5.0 // REST default: streaming API is ~5:1 down:up
		}
		decide = StreamingBiasGANDecide(ratio)
	}

	done := make(chan struct{})
	conn := newRestServerConn(sess, w, local, remote, func() { close(done) }, decide)

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

	// Padding goroutine: inject encrypted random-byte frames to break size
	// fingerprinting and maintain the target download/upload ratio.
	if decide != nil {
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					up := float64(atomic.LoadInt64(&sess.uploadBytes))
					down := float64(atomic.LoadInt64(&sess.downloadBytes))
					upRatio := 0.0
					if up+down > 0 {
						upRatio = up / (up + down)
					}
					action := decide(0, 0, upRatio)
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

// ── HLS server handlers ──────────────────────────────────────────────────────

// handleHLSPlaylist handles GET /video/{sid}/index.m3u8 — authenticates the
// client, creates the session, sends an HLS playlist, then blocks while
// sequential segment handlers fill the FrameConn download stream.
func handleHLSPlaylist(w http.ResponseWriter, r *http.Request, cfg *Config) {
	tokenHdr := r.Header.Get(headerToken)
	sessCookie, cookieErr := r.Cookie(sessionCookie)

	if len(tokenHdr) < 8 || tokenHdr[:7] != "Bearer " {
		serveDecoy(w, r, cfg)
		return
	}
	token := tokenHdr[7:]

	if cookieErr != nil {
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
		log.Printf("chameleon: HLS auth failed from %s", r.RemoteAddr)
		serveDecoy(w, r, cfg)
		return
	}

	keys := DeriveKeys(secret, false)
	log.Printf("chameleon: HLS authenticated user=%s from %s", userID, r.RemoteAddr)

	sess := &restSession{
		uploadCh: make(chan []byte, 512),
		segCh:    make(chan segSlot, 1),
		closed:   make(chan struct{}),
		secret:   secret,
	}
	sessionKey := hlsSessionKey(sessionID)
	cfg.sessions.Store(sessionKey, sess)
	defer func() {
		close(sess.closed)
		cfg.sessions.Delete(sessionKey)
	}()

	// Send the HLS playlist immediately so the client can start requesting segments.
	playlist := hlsM3U8(0)
	w.Header().Set("Content-Type", "application/x-mpegURL")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(playlist)))
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, playlist)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	local := staticAddr{"tcp", r.Host}
	remote := staticAddr{"tcp", r.RemoteAddr}

	decide := cfg.GANDecide
	if decide == nil {
		ratio := cfg.AsymBiasRatio
		if ratio <= 0 {
			ratio = 10.0 // HLS default: video streaming is ~10:1 down:up
		}
		decide = StreamingBiasGANDecide(ratio)
	}

	done := make(chan struct{})
	segRouter := newSegmentRouter(sess, keys.Behavior, done)

	// restServerConn handles the Read (upload) side; writes go through segRouter.
	conn := newRestServerConn(sess, segRouter, local, remote, func() { close(done) }, decide)

	go func() {
		select {
		case <-r.Context().Done():
			conn.Close()
		case <-done:
		}
	}()

	fc, err := NewFrameConn(conn, keys.DataSend, keys.DataRecv)
	if err != nil {
		log.Printf("chameleon: HLS frame conn: %v", err)
		return
	}

	if decide != nil {
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					up := float64(atomic.LoadInt64(&sess.uploadBytes))
					down := float64(atomic.LoadInt64(&sess.downloadBytes))
					upRatio := 0.0
					if up+down > 0 {
						upRatio = up / (up + down)
					}
					action := decide(0, 0, upRatio)
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

// handleHLSSegment handles GET /video/{sid}/seg{n}.ts — delivers exactly one
// HLS segment worth of FrameConn data and returns when the budget is exhausted.
func handleHLSSegment(w http.ResponseWriter, r *http.Request, cfg *Config) {
	sessionKey := hlsKeyFromPath(r.URL.Path)
	if sessionKey == "" {
		serveDecoy(w, r, cfg)
		return
	}

	val, ok := cfg.sessions.Load(sessionKey)
	if !ok {
		// Session not ready yet — wait up to 3s (race between playlist and first segment).
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			if val, ok = cfg.sessions.Load(sessionKey); ok {
				break
			}
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	sess := val.(*restSession)

	flusher, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "video/MP2T")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	slotDone := make(chan struct{})
	slot := segSlot{w: w, flush: flusher.Flush, done: slotDone}

	select {
	case sess.segCh <- slot:
	case <-sess.closed:
		return
	case <-r.Context().Done():
		return
	}

	select {
	case <-slotDone:
	case <-sess.closed:
	case <-r.Context().Done():
	}
}

// handleRESTUpload handles POST/PUT/PATCH requests that feed the upload channel.
// Authentication is implicit: the 16-byte random sessionID is a capability token —
// only a client that received a valid GET 200 knows it. No resolveSecret needed.
func handleRESTUpload(w http.ResponseWriter, r *http.Request, cfg *Config) {
	sessCookie, err := r.Cookie(sessionCookie)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionID, _, err := decodeSession(sessCookie.Value)
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
		atomic.AddInt64(&sess.uploadBytes, int64(len(body)))
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
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
