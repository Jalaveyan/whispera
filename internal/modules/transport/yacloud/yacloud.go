package yacloud


import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("yacloud")

const (
	ModuleName    = "transport.yacloud"
	ModuleVersion = "1.0.0"
)

type Config struct {
	GatewayURL string

	ServerMode bool
	ListenAddr string

	ExtraHeaders map[string]string

	BufferSize int
}

func DefaultConfig() *Config {
	return &Config{
		BufferSize: 32 * 1024,
		ListenAddr: ":8443",
	}
}

type Transport struct {
	*base.Module
	config *Config
	srv    *http.Server

	connCh   chan net.Conn
	stopOnce sync.Once
	stopCh   chan struct{}
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
		cfg.BufferSize = 32 * 1024
	}
	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		connCh: make(chan net.Conn, 8),
		stopCh: make(chan struct{}),
	}
	return t, nil
}

func (t *Transport) Start() error {
	if t.config.ServerMode {
		mux := http.NewServeMux()
		mux.HandleFunc("/ws", t.wsHandler)
		t.srv = &http.Server{Addr: t.config.ListenAddr, Handler: mux}
		go func() {
			log.Printf("yacloud server listening on %s", t.config.ListenAddr)
			if err := t.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("server error: %v", err)
			}
		}()
	}
	return nil
}

func (t *Transport) Stop() error {
	t.stopOnce.Do(func() {
		close(t.stopCh)
		if t.srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			t.srv.Shutdown(ctx)
		}
	})
	return nil
}

func (t *Transport) Dial(ctx context.Context, _ string) (net.Conn, error) {
	if t.config.GatewayURL == "" {
		return nil, fmt.Errorf("yacloud: GatewayURL is not set")
	}

	opts := &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Origin":     []string{"https://console.cloud.yandex.ru"},
			"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		},
	}
	for k, v := range t.config.ExtraHeaders {
		opts.HTTPHeader.Set(k, v)
	}

	ws, _, err := websocket.Dial(ctx, t.config.GatewayURL, opts)
	if err != nil {
		return nil, fmt.Errorf("yacloud dial %s: %w", t.config.GatewayURL, err)
	}
	ws.SetReadLimit(int64(t.config.BufferSize) * 4)

	log.Printf("yacloud: connected to %s", t.config.GatewayURL)
	return newWSConn(ws, t.config.GatewayURL), nil
}

func (t *Transport) Accept() (net.Conn, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-t.stopCh:
		return nil, fmt.Errorf("yacloud: stopped")
	}
}

func (t *Transport) wsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("yacloud: ws accept error: %v", err)
		return
	}
	ws.SetReadLimit(int64(t.config.BufferSize) * 4)
	conn := newWSConn(ws, r.RemoteAddr)
	select {
	case t.connCh <- conn:
	case <-t.stopCh:
		ws.Close(websocket.StatusGoingAway, "stopped")
	}
}

type wsConn struct {
	ws       *websocket.Conn
	addr     string
	buf      []byte
	bufStart int
	mu       sync.Mutex
}

func newWSConn(ws *websocket.Conn, addr string) *wsConn {
	return &wsConn{ws: ws, addr: addr}
}

func (c *wsConn) Read(p []byte) (int, error) {
	if c.bufStart < len(c.buf) {
		n := copy(p, c.buf[c.bufStart:])
		c.bufStart += n
		return n, nil
	}

	_, data, err := c.ws.Read(context.Background())
	if err != nil {
		return 0, err
	}
	n := copy(p, data)
	if n < len(data) {
		c.buf = data
		c.bufStart = n
	} else {
		c.buf = nil
		c.bufStart = 0
	}
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.ws.Write(context.Background(), websocket.MessageBinary, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error {
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

func (c *wsConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *wsConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *wsConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("0.0.0.0")} }
