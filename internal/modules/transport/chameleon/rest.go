package chameleon

import (
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
		base := DeriveSegmentSize(r.behaviorKey, r.segIdx)
		if atomic.LoadInt32(&r.sess.bulkMode) == 0 {
			shrink := float64(atomic.LoadInt64(&r.sess.segShrinkPerMille)) / 1000.0
			r.segSize = base - int(float64(base)*shrink)
			if r.segSize < base/4 {
				r.segSize = base / 4
			}
		} else {
			r.segSize = base
		}
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

type GANAction struct {
	SleepMs   float64
	PaddingN  int
	SegShrink float64
}

type GANDecideFunc func(iatMean, sizeMean, upRatio float64) GANAction

type restSession struct {
	uploadCh          chan *uploadBody
	segCh             chan segSlot
	closed            chan struct{}
	secret            []byte
	uploadBytes       int64
	downloadBytes     int64
	segShrinkPerMille int64
	bulkMode          int32
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

	ganDecide     GANDecideFunc
	lastWrite     time.Time
	iatSum        float64
	sizeSum       float64
	writeCount    float64
	lastGANUpdate time.Time
	smoothedIAT   float64
	smoothedSize  float64
	lastGANAction GANAction
}

func ganEMA(prev, next, alpha float64) float64 {
	if prev == 0 {
		return next
	}
	return prev*(1-alpha) + next*alpha
}

func newRestServerConn(sess *restSession, w io.Writer, local, remote net.Addr, onClose func(), ganDecide GANDecideFunc) *restServerConn {
	flusher, _ := w.(http.Flusher)
	return &restServerConn{
		sess:       sess,
		w:          w,
		flusher:    flusher,
		ganDecide:  ganDecide,
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
			c.iatSum += now.Sub(c.lastWrite).Seconds()
		}
		c.sizeSum += float64(len(b))
		c.writeCount++
		c.lastWrite = now

		const ganInterval = 100 * time.Millisecond
		if now.Sub(c.lastGANUpdate) >= ganInterval {
			iatMean := 0.0
			if c.writeCount > 1 {
				iatMean = c.iatSum / (c.writeCount - 1)
			}
			c.smoothedIAT = ganEMA(c.smoothedIAT, iatMean, 0.1)
			c.smoothedSize = ganEMA(c.smoothedSize, c.sizeSum/c.writeCount, 0.1)
			up := float64(atomic.LoadInt64(&c.sess.uploadBytes))
			down := float64(atomic.LoadInt64(&c.sess.downloadBytes))
			upRatio := 0.0
			if up+down > 0 {
				upRatio = up / (up + down)
			}
			c.lastGANAction = c.ganDecide(c.smoothedIAT, c.smoothedSize, upRatio)
			atomic.StoreInt64(&c.sess.segShrinkPerMille, int64(c.lastGANAction.SegShrink*1000))
			c.lastGANUpdate = now
		}

		if atomic.LoadInt32(&c.sess.bulkMode) == 0 {
			a := c.lastGANAction
			if c.smoothedIAT > 0.03 && a.SleepMs > 0.5 {
				sleep := a.SleepMs
				if sleep > 15 {
					sleep = 15
				}
				time.Sleep(time.Duration(sleep * float64(time.Millisecond)))
			}
		}
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

func (c *restServerConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *restServerConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *restServerConn) SetDeadline(t time.Time) error      { return nil }
func (c *restServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *restServerConn) SetWriteDeadline(t time.Time) error { return nil }

func handleRESTDownload(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
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
					atomic.StoreInt32(&sess.bulkMode, 1)
					continue
				}
				atomic.StoreInt32(&sess.bulkMode, 0)
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

func handleHLSPlaylist(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
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
						atomic.StoreInt32(&sess.bulkMode, 1)
						continue
					}
					atomic.StoreInt32(&sess.bulkMode, 0)
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

func handleHLSSegment(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
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

func handleRESTUpload(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
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
