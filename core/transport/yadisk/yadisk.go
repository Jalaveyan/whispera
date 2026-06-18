package yadisk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"whispera/common/runtime/base"
	"whispera/common/runtime/interfaces"
	"whispera/common/runtime/registry"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "transport.yadisk"
	ModuleVersion = "1.0.0"

	webdavBase   = "https://webdav.yandex.ru"
	diskBase     = "https://cloud-api.yandex.net/v1/disk/resources"
	pollInterval = 50 * time.Millisecond
	chunkTimeout = 5 * time.Second
	maxChunkSize = 512 * 1024
)

type Config struct {
	ServerMode bool

	OAuthToken string

	SessionID string

	BufferSize int
}

func DefaultConfig() *Config {
	return &Config{BufferSize: 64 * 1024}
}

type Transport struct {
	*base.Module
	config *Config
	client *http.Client

	writeSeq uint64
	readSeq  uint64

	writeDir string
	readDir  string

	dataIn  chan []byte
	dataOut chan []byte

	connOnce sync.Once
	connCh   chan net.Conn
	stopCh   chan struct{}
	stopOnce sync.Once
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	c, ok := cfg.(*Config)
	if !ok {
		c = DefaultConfig()
	}
	return New(c)
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 64 * 1024
	}
	t := &Transport{
		Module:  base.NewModule(ModuleName, ModuleVersion, nil),
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		dataIn:  make(chan []byte, 128),
		dataOut: make(chan []byte, 128),
		connCh:  make(chan net.Conn, 1),
		stopCh:  make(chan struct{}),
	}

	base := "/whispera/" + cfg.SessionID
	if cfg.ServerMode {
		t.readDir = base + "/c2s"
		t.writeDir = base + "/s2c"
	} else {
		t.writeDir = base + "/c2s"
		t.readDir = base + "/s2c"
	}

	return t, nil
}

func (t *Transport) Start() error {
	if t.config.OAuthToken == "" {
		return fmt.Errorf("yadisk: OAuthToken is required")
	}
	if t.config.SessionID == "" {
		return fmt.Errorf("yadisk: SessionID is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for _, dir := range []string{
		"/whispera",
		"/whispera/" + t.config.SessionID,
		t.writeDir,
	} {
		if err := t.mkdir(ctx, dir); err != nil {
		}
	}

	go t.sendLoop()
	go t.recvLoop()

	conn := &diskConn{t: t}
	t.connCh <- conn

	return nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportYaDisk }

func (t *Transport) Stop() error {
	t.stopOnce.Do(func() { close(t.stopCh) })
	return nil
}

func (t *Transport) Dial(ctx context.Context, _ string) (net.Conn, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.stopCh:
		return nil, fmt.Errorf("yadisk: stopped")
	}
}

func (t *Transport) Accept() (net.Conn, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-t.stopCh:
		return nil, fmt.Errorf("yadisk: stopped")
	}
}

func (t *Transport) sendLoop() {
	for {
		select {
		case <-t.stopCh:
			return
		case data := <-t.dataOut:
			seq := atomic.AddUint64(&t.writeSeq, 1) - 1
			path := fmt.Sprintf("%s/%010d", t.writeDir, seq)
			ctx, cancel := context.WithTimeout(context.Background(), chunkTimeout)
			_ = t.putFile(ctx, path, data)
			cancel()
		}
	}
}

func (t *Transport) recvLoop() {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			seq := atomic.LoadUint64(&t.readSeq)
			path := fmt.Sprintf("%s/%010d", t.readDir, seq)
			ctx, cancel := context.WithTimeout(context.Background(), chunkTimeout)
			data, err := t.getFile(ctx, path)
			cancel()
			if err != nil {
				continue
			}
			atomic.AddUint64(&t.readSeq, 1)
			go t.deleteFile(context.Background(), path)

			select {
			case t.dataIn <- data:
			case <-t.stopCh:
				return
			}
		}
	}
}

func (t *Transport) auth(req *http.Request) {
	req.Header.Set("Authorization", "OAuth "+t.config.OAuthToken)
}

func (t *Transport) putFile(ctx context.Context, path string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, "PUT",
		webdavBase+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	t.auth(req)
	req.ContentLength = int64(len(data))
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (t *Transport) getFile(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", webdavBase+path, nil)
	if err != nil {
		return nil, err
	}
	t.auth(req)
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxChunkSize))
}

func (t *Transport) deleteFile(ctx context.Context, path string) {
	req, _ := http.NewRequestWithContext(ctx, "DELETE", webdavBase+path, nil)
	t.auth(req)
	resp, _ := t.client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
}

func (t *Transport) mkdir(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, "MKCOL", webdavBase+path, nil)
	if err != nil {
		return err
	}
	t.auth(req)
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 201 && resp.StatusCode != 405 {
		return fmt.Errorf("MKCOL HTTP %d", resp.StatusCode)
	}
	return nil
}

type diskConn struct {
	t   *Transport
	buf []byte
	mu  sync.Mutex
}

func (c *diskConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	select {
	case data := <-c.t.dataIn:
		n := copy(p, data)
		if n < len(data) {
			c.mu.Lock()
			c.buf = append(c.buf, data[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	case <-c.t.stopCh:
		return 0, fmt.Errorf("yadisk: closed")
	}
}

func (c *diskConn) Write(p []byte) (int, error) {
	for len(p) > 0 {
		end := len(p)
		if end > maxChunkSize {
			end = maxChunkSize
		}
		cp := make([]byte, end)
		copy(cp, p[:end])
		select {
		case c.t.dataOut <- cp:
		case <-c.t.stopCh:
			return 0, fmt.Errorf("yadisk: closed")
		}
		p = p[end:]
	}
	return len(p), nil
}

func (c *diskConn) Close() error                       { return c.t.Stop() }
func (c *diskConn) SetDeadline(t time.Time) error      { return nil }
func (c *diskConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *diskConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *diskConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *diskConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
