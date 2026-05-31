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

	"whispera/internal/buf"
)

const uploadBodyMax = 700 * 1024

type uploadBody struct {
	data []byte
}

var uploadBodyPool = sync.Pool{
	New: func() any { return &uploadBody{data: make([]byte, uploadBodyMax)} },
}

func acquireUploadBody() *uploadBody {
	ub := uploadBodyPool.Get().(*uploadBody)
	ub.data = ub.data[:cap(ub.data)]
	return ub
}

func releaseUploadBody(ub *uploadBody) {
	if ub == nil {
		return
	}
	ub.data = ub.data[:cap(ub.data)]
	uploadBodyPool.Put(ub)
}

var mp4FtypAtom = [24]byte{
	0x00, 0x00, 0x00, 0x18,
	0x66, 0x74, 0x79, 0x70,
	0x69, 0x73, 0x6F, 0x6D,
	0x00, 0x00, 0x02, 0x00,
	0x69, 0x73, 0x6F, 0x6D,
	0x6D, 0x70, 0x34, 0x32,
}


func hlsSessionKey(sessionID []byte) string { return hex.EncodeToString(sessionID) }

func hlsPlaylistPath(sessionID []byte) string {
	return "/video/" + hlsSessionKey(sessionID) + "/index.m3u8"
}

func hlsSegmentPath(sessionID []byte, n uint64) string {
	return fmt.Sprintf("/video/%s/seg%04d.ts", hlsSessionKey(sessionID), n)
}

func hlsKeyFromPath(path string) string {
	parts := strings.SplitN(path, "/", 4)
	if len(parts) < 4 || parts[1] != "video" || len(parts[2]) != 32 {
		return ""
	}
	return parts[2]
}

func hlsM3U8(startSeg uint64) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:4\n")
	fmt.Fprintf(&sb, "#EXT-X-MEDIA-SEQUENCE:%d\n", startSeg)
	for i := uint64(0); i < 3; i++ {
		fmt.Fprintf(&sb, "#EXTINF:3.840,\nseg%04d.ts\n", startSeg+i)
	}
	return sb.String()
}


type segSlot struct {
	w     io.Writer
	flush func()
	done  chan struct{}
}

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
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
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
	case <-t.C:
		return nil, fmt.Errorf("chameleon: no segment in 10s")
	}
}

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


type GANAction struct {
	SleepMs  float64
	PaddingN int
}

type GANDecideFunc func(iatMean, sizeMean, upRatio float64) GANAction

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


type restSession struct {
	uploadCh      chan *uploadBody
	segCh         chan segSlot
	closed        chan struct{}
	secret        []byte
	uploadBytes   int64
	downloadBytes int64
}


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
		case ub, ok := <-c.sess.uploadCh:
			if !ok {
				return 0, io.EOF
			}
			n := copy(b, ub.data)
			if n < len(ub.data) {
				c.readBuf = append(c.readBuf[:0], ub.data[n:]...)
			}
			releaseUploadBody(ub)
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
		if action.SleepMs > 0.5 && action.SleepMs <= 2.0 {
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


type restClientConn struct {
	bodyCh  chan io.ReadCloser
	curBody io.ReadCloser

	uploadCh chan *buf.Buffer

	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newRestClientConn(ctx context.Context, cancel context.CancelFunc, local, remote net.Addr) *restClientConn {
	return &restClientConn{
		bodyCh:     make(chan io.ReadCloser, 4),
		uploadCh:   make(chan *buf.Buffer, 512),
		ctx:        ctx,
		cancel:     cancel,
		localAddr:  local,
		remoteAddr: remote,
	}
}

func (c *restClientConn) Read(b []byte) (int, error) {
	for {
		if c.curBody != nil {
			n, err := c.curBody.Read(b)
			if n > 0 {
				return n, nil
			}
			c.curBody.Close()
			c.curBody = nil
			if err == io.EOF {
				continue
			}
			return 0, err
		}
		select {
		case body, ok := <-c.bodyCh:
			if !ok || body == nil {
				return 0, io.EOF
			}
			c.curBody = body
		case <-c.ctx.Done():
			return 0, io.EOF
		}
	}
}

func (c *restClientConn) Write(p []byte) (int, error) {
	b := buf.NewSize(len(p))
	b.Write(p)
	select {
	case c.uploadCh <- b:
		return len(p), nil
	case <-c.ctx.Done():
		b.Release()
		return 0, io.ErrClosedPipe
	}
}

func (c *restClientConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		go func() {
			for body := range c.bodyCh {
				if body != nil {
					body.Close()
				}
			}
		}()
	})
	return nil
}

func (c *restClientConn) LocalAddr() net.Addr               { return c.localAddr }
func (c *restClientConn) RemoteAddr() net.Addr              { return c.remoteAddr }
func (c *restClientConn) SetDeadline(t time.Time) error     { return nil }
func (c *restClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *restClientConn) SetWriteDeadline(t time.Time) error { return nil }



func runRESTUpload(ctx context.Context, client *http.Client, serverAddr, sni, origin, sessionHdr, token string, uploadCh <-chan *buf.Buffer) {
	var coalesce []byte
	for {
		coalesce = coalesce[:0]

		select {
		case b := <-uploadCh:
			coalesce = append(coalesce, b.Bytes()...)
			b.Release()
		case <-ctx.Done():
			return
		}

	drain:
		for len(coalesce) < 512*1024 {
			select {
			case b := <-uploadCh:
				coalesce = append(coalesce, b.Bytes()...)
				b.Release()
			case <-ctx.Done():
				return
			default:
				break drain
			}
		}

		method := restUploadMethods[mrand.Intn(len(restUploadMethods))]
		path := restUploadPath(method)
		url := fmt.Sprintf("https://%s%s", serverAddr, path)

		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(coalesce))
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


func RESTClient(ctx context.Context, cfg *Config) (net.Conn, error) {
	sessionID := make([]byte, 16)
	if _, err := crand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("chameleon: session id: %w", err)
	}
	anchor := time.Now().UTC().Truncate(time.Second)

	keys := DeriveKeys(cfg.SharedSecret)
	token := AuthToken(keys.Auth, anchor.Unix()/30, sessionID)
	sessionHdr := encodeSession(sessionID, anchor)

	sni := pickSNI(cfg)
	origin := "https://" + sni

	helloID := chromeHelloPool[mrand.Intn(len(chromeHelloPool))]

	h2t := newH2Transport(func(dialCtx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
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
	})

	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())

	local := staticAddr{"tcp", cfg.ServerAddr}
	remote := staticAddr{"tcp", cfg.ServerAddr}

	conn := newRestClientConn(tunnelCtx, tunnelCancel, local, remote)
	client := &http.Client{Transport: h2t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

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
		defer close(conn.bodyCh)
		nextCh := fetchSeg(0)
		for segIdx := uint64(0); ; segIdx++ {
			var res segResult
			select {
			case res = <-nextCh:
			case <-tunnelCtx.Done():
				return
			}
			if res.err != nil {
				return
			}
			nextCh = fetchSeg(segIdx + 1)
			select {
			case conn.bodyCh <- res.resp.Body:
			case <-tunnelCtx.Done():
				res.resp.Body.Close()
				return
			}
		}
	}()

	go runRESTUpload(tunnelCtx, client, cfg.ServerAddr, sni, origin, sessionHdr, token, conn.uploadCh)
	go runRESTDecoy(tunnelCtx, client, cfg.ServerAddr, sni, origin)

	return NewFrameConn(conn), nil
}


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

	log.Printf("chameleon: REST authenticated user=%s from %s", userID, r.RemoteAddr)

	sess := &restSession{
		uploadCh: make(chan *uploadBody, 512),
		closed:   make(chan struct{}),
		secret:   secret,
	}
	sessionKey := hex.EncodeToString(sessionID)
	cfg.storeSession(sessionKey, sess)
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

	done := make(chan struct{})
	conn := newRestServerConn(sess, w, local, remote, func() { close(done) }, decide)

	go func() {
		select {
		case <-r.Context().Done():
			conn.Close()
		case <-done:
		}
	}()

	fc := NewFrameConn(conn)

	if decide != nil {
		go func() {
			var prevDown int64
			for {
				jitter := time.Duration(mrand.Intn(100)-50) * time.Millisecond
				t := time.NewTimer(200*time.Millisecond + jitter)
				select {
				case <-done:
					t.Stop()
					return
				case <-t.C:
				}
				curDown := atomic.LoadInt64(&sess.downloadBytes)
				rate := curDown - prevDown
				prevDown = curDown
				if rate > 2*1024*1024 {
					continue
				}
				up := float64(atomic.LoadInt64(&sess.uploadBytes))
				down := float64(curDown)
				upRatio := 0.0
				if up+down > 0 {
					upRatio = up / (up + down)
				}
				action := decide(0, 0, upRatio)
				if action.PaddingN > 0 {
					if err := fc.WritePad(action.PaddingN); err != nil {
						return
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

	keys := DeriveKeys(secret)
	log.Printf("chameleon: HLS authenticated user=%s from %s", userID, r.RemoteAddr)

	sess := &restSession{
		uploadCh: make(chan *uploadBody, 512),
		segCh:    make(chan segSlot, 1),
		closed:   make(chan struct{}),
		secret:   secret,
	}
	sessionKey := hlsSessionKey(sessionID)
	cfg.storeSession(sessionKey, sess)

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

	go func() {
		defer func() {
			close(sess.closed)
			cfg.sessions.Delete(sessionKey)
		}()

		done := make(chan struct{})
		segRouter := newSegmentRouter(sess, keys.Behavior, done)
		conn := newRestServerConn(sess, segRouter, local, remote, func() { close(done) }, decide)

		fc := NewFrameConn(conn)

		if decide != nil {
			go func() {
				var prevDown int64
				for {
					jitter := time.Duration(mrand.Intn(100)-50) * time.Millisecond
					t := time.NewTimer(200*time.Millisecond + jitter)
					select {
					case <-done:
						t.Stop()
						return
					case <-t.C:
					}
					curDown := atomic.LoadInt64(&sess.downloadBytes)
					rate := curDown - prevDown
					prevDown = curDown
					if rate > 2*1024*1024 {
						continue
					}
					up := float64(atomic.LoadInt64(&sess.uploadBytes))
					down := float64(curDown)
					upRatio := 0.0
					if up+down > 0 {
						upRatio = up / (up + down)
					}
					action := decide(0, 0, upRatio)
					if action.PaddingN > 0 {
						if err := fc.WritePad(action.PaddingN); err != nil {
							return
						}
					}
				}
			}()
		}

		if cfg.OnConn != nil {
			cfg.OnConn(fc, userID)
		}
		<-done
	}()
}

func handleHLSSegment(w http.ResponseWriter, r *http.Request, cfg *Config) {
	sessionKey := hlsKeyFromPath(r.URL.Path)
	if sessionKey == "" {
		serveDecoy(w, r, cfg)
		return
	}

	sess, ok := cfg.waitSession(sessionKey, 3*time.Second)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

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

func handleRESTUpload(w http.ResponseWriter, r *http.Request, cfg *Config) {
	sessCookie, err := r.Cookie(sessionCookie)
	if err != nil {
		log.Printf("chameleon: upload from %s: no session cookie (400)", r.RemoteAddr)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionID, _, err := decodeSession(sessCookie.Value)
	if err != nil {
		log.Printf("chameleon: upload from %s: bad cookie (400)", r.RemoteAddr)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionKey := hex.EncodeToString(sessionID)

	sess, ok := cfg.waitSession(sessionKey, 3*time.Second)
	if !ok {
		log.Printf("chameleon: upload from %s: session %s not found (503)", r.RemoteAddr, sessionKey[:8])
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	ub := acquireUploadBody()
	n, err := io.ReadFull(io.LimitReader(r.Body, int64(len(ub.data))), ub.data)
	r.Body.Close()
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		releaseUploadBody(ub)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ub.data = ub.data[:n]

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	if n == 0 {
		releaseUploadBody(ub)
		return
	}

	atomic.AddInt64(&sess.uploadBytes, int64(n))
	select {
	case sess.uploadCh <- ub:
	case <-sess.closed:
		releaseUploadBody(ub)
	case <-r.Context().Done():
		releaseUploadBody(ub)
	}
}

func handleRESTOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

func handleRESTDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"deleted":true}`)); err != nil {
		log.Printf("chameleon: REST delete response: %v", err)
	}
}
