package splithttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("splithttp")

const (
	ModuleName    = "transport.splithttp"
	ModuleVersion = "1.0.0"

	maxChunkSize = 1 << 17
)

type Config struct {
	BaseURL string
	Host    string
	Path    string

	ServerMode bool
	TLSCert    string
	TLSKey     string
}

func DefaultConfig() *Config {
	return &Config{
		Path: "/",
	}
}

func (c *Config) Validate() error {
	if !c.ServerMode && c.BaseURL == "" {
		return fmt.Errorf("splithttp: base URL required")
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config
	client *http.Client

	sessions   sync.Map
	acceptCh   chan net.Conn
	httpServer *http.Server

	activeConns int64
	totalConns  uint64
	bytesIn     uint64
	bytesOut    uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportSplitHTTP }


func (t *Transport) Listen(addr string) error {
	t.acceptCh = make(chan net.Conn, 64)

	mux := http.NewServeMux()
	mux.HandleFunc("/", t.handleHTTP)

	t.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("splithttp: listen %s: %w", addr, err)
	}

	if t.config.TLSCert != "" && t.config.TLSKey != "" {
		log.Info("splithttp: server listening on %s (TLS)", addr)
		go t.httpServer.ServeTLS(ln, t.config.TLSCert, t.config.TLSKey)
	} else {
		log.Info("splithttp: server listening on %s (plain HTTP)", addr)
		go t.httpServer.Serve(ln)
	}

	return nil
}

type serverSession struct {
	conn *serverSplitConn
	once sync.Once
}

type serverSplitConn struct {
	t         *Transport
	sessionID string

	recvPr *io.PipeReader
	recvPw *io.PipeWriter

	sendPr *io.PipeReader
	sendPw *io.PipeWriter

	done chan struct{}
	once sync.Once
}

func newServerSplitConn(t *Transport, sessionID string) *serverSplitConn {
	recvPr, recvPw := io.Pipe()
	sendPr, sendPw := io.Pipe()
	return &serverSplitConn{
		t:         t,
		sessionID: sessionID,
		recvPr:    recvPr,
		recvPw:    recvPw,
		sendPr:    sendPr,
		sendPw:    sendPw,
		done:      make(chan struct{}),
	}
}

func (t *Transport) getOrCreateSession(sessionID string) *serverSession {
	val, loaded := t.sessions.LoadOrStore(sessionID, &serverSession{})
	sess := val.(*serverSession)
	if !loaded {
		conn := newServerSplitConn(t, sessionID)
		sess.conn = conn
		atomic.AddUint64(&t.totalConns, 1)
		atomic.AddInt64(&t.activeConns, 1)
		t.acceptCh <- conn
	}
	return sess
}

func (t *Transport) handleHTTP(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "missing session", http.StatusBadRequest)
		return
	}

	sess := t.getOrCreateSession(sessionID)
	conn := sess.conn

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, hasFlusher := w.(http.Flusher)
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-conn.done:
				return
			default:
			}
			n, err := conn.sendPr.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if hasFlusher {
					flusher.Flush()
				}
				atomic.AddUint64(&t.bytesOut, uint64(n))
			}
			if err != nil {
				return
			}
		}

	case http.MethodPost:
		n, err := io.Copy(conn.recvPw, r.Body)
		if n > 0 {
			atomic.AddUint64(&t.bytesIn, uint64(n))
		}
		if err != nil && err != io.ErrClosedPipe {
			http.Error(w, "write error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *serverSplitConn) Read(b []byte) (int, error) {
	return c.recvPr.Read(b)
}

func (c *serverSplitConn) Write(b []byte) (int, error) {
	return c.sendPw.Write(b)
}

func (c *serverSplitConn) closeOnce() {
	c.once.Do(func() {
		close(c.done)
		c.recvPw.Close()
		c.sendPw.Close()
		atomic.AddInt64(&c.t.activeConns, -1)
		c.t.sessions.Delete(c.sessionID)
	})
}

func (c *serverSplitConn) Close() error {
	c.closeOnce()
	return nil
}

func (c *serverSplitConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *serverSplitConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *serverSplitConn) SetDeadline(_ time.Time) error     { return nil }
func (c *serverSplitConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *serverSplitConn) SetWriteDeadline(_ time.Time) error { return nil }

func (t *Transport) Accept() (net.Conn, error) {
	conn, ok := <-t.acceptCh
	if !ok {
		return nil, io.EOF
	}
	return conn, nil
}

func (t *Transport) Close() error {
	if t.httpServer != nil {
		return t.httpServer.Close()
	}
	return nil
}


func (t *Transport) Dial(ctx context.Context, _ string) (net.Conn, error) {
	b := make([]byte, 16)
	rand.Read(b)
	sessionID := hex.EncodeToString(b)

	pr, pw := io.Pipe()
	conn := &splitHTTPConn{
		t:         t,
		sessionID: sessionID,
		recvPipe:  pr,
		sendCh:    make(chan []byte, 64),
		done:      make(chan struct{}),
	}

	go conn.startRecvStream(ctx)
	go conn.sendLoop(ctx, pw)

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	log.Info("splithttp: connection established, session=%s", sessionID)
	return conn, nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	s.Details["server_mode"] = t.config.ServerMode
	return s
}

type splitHTTPConn struct {
	t         *Transport
	sessionID string

	mu       sync.Mutex
	pending  []byte
	recvPipe *io.PipeReader
	sendCh   chan []byte
	done     chan struct{}
	once     sync.Once
}

func (c *splitHTTPConn) startRecvStream(ctx context.Context) {
	url := c.t.config.BaseURL + "?session=" + c.sessionID

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	if c.t.config.Host != "" {
		req.Host = c.t.config.Host
	}

	resp, err := c.t.client.Do(req)
	if err != nil {
		c.closeOnce()
		return
	}
	defer resp.Body.Close()

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, err := resp.Body.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			c.mu.Lock()
			c.pending = append(c.pending, data...)
			c.mu.Unlock()
			atomic.AddUint64(&c.t.bytesIn, uint64(n))
		}
		if err != nil {
			c.closeOnce()
			return
		}
	}
}

func (c *splitHTTPConn) sendLoop(ctx context.Context, pw *io.PipeWriter) {
	defer pw.Close()
	for {
		select {
		case <-c.done:
			return
		case data := <-c.sendCh:
			url := c.t.config.BaseURL + "?session=" + c.sessionID
			req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
			if err != nil {
				continue
			}
			if c.t.config.Host != "" {
				req.Host = c.t.config.Host
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := c.t.client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			atomic.AddUint64(&c.t.bytesOut, uint64(len(data)))
		}
	}
}

func (c *splitHTTPConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.pending) > 0 {
			n := copy(b, c.pending)
			c.pending = c.pending[n:]
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()

		select {
		case <-c.done:
			return 0, io.EOF
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (c *splitHTTPConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	case c.sendCh <- append([]byte(nil), b...):
		return len(b), nil
	}
}

func (c *splitHTTPConn) closeOnce() {
	c.once.Do(func() {
		close(c.done)
		atomic.AddInt64(&c.t.activeConns, -1)
	})
}

func (c *splitHTTPConn) Close() error {
	c.closeOnce()
	return nil
}

func (c *splitHTTPConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *splitHTTPConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *splitHTTPConn) SetDeadline(_ time.Time) error     { return nil }
func (c *splitHTTPConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *splitHTTPConn) SetWriteDeadline(_ time.Time) error { return nil }

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: config,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}
	return t, nil
}
