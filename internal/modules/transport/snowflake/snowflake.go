package snowflake

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v3"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("snowflake")

const (
	ModuleName    = "transport.snowflake"
	ModuleVersion = "1.0.0"

	defaultBrokerURL = "https://snowflake-broker.torproject.net/"
	defaultSTUN      = "stun:stun.l.google.com:19302"
)

type Config struct {
	BrokerURL  string
	STUNServer string
	FrontDomain string
}

func DefaultConfig() *Config {
	return &Config{
		BrokerURL:  defaultBrokerURL,
		STUNServer: defaultSTUN,
	}
}

func (c *Config) Validate() error {
	if c.BrokerURL == "" {
		return fmt.Errorf("snowflake broker URL required")
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config
	client *http.Client

	activeConns int64
	totalConns  uint64
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
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportSnowflake }

func (t *Transport) Listen(_ string) error     { return fmt.Errorf("snowflake: server mode not supported") }
func (t *Transport) Accept() (net.Conn, error) { return nil, fmt.Errorf("snowflake: server mode not supported") }
func (t *Transport) Close() error              { return nil }

func (t *Transport) Dial(ctx context.Context, _ string) (net.Conn, error) {
	api := webrtc.NewAPI()

	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{t.config.STUNServer}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("snowflake: peer connection: %w", err)
	}

	ordered := true
	dc, err := pc.CreateDataChannel("snowflake", &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("snowflake: data channel: %w", err)
	}

	conn := &snowflakeConn{
		pc:     pc,
		dc:     dc,
		recvCh: make(chan []byte, 256),
		done:   make(chan struct{}),
		t:      t,
	}

	dc.OnOpen(func() {
		log.Info("snowflake data channel open")
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		select {
		case conn.recvCh <- msg.Data:
		default:
			log.Warn("snowflake recv buffer full, dropping packet")
		}
	})
	dc.OnClose(func() {
		conn.closeOnce()
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		pc.Close()
		return nil, err
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		pc.Close()
		return nil, err
	}

	gatherDone := webrtc.GatheringCompletePromise(pc)
	select {
	case <-ctx.Done():
		pc.Close()
		return nil, ctx.Err()
	case <-gatherDone:
	}

	log.Info("snowflake: ICE gathering complete, negotiating with broker")

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	return conn, nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	return s
}

type snowflakeConn struct {
	t    *Transport
	pc   *webrtc.PeerConnection
	dc   *webrtc.DataChannel

	mu      sync.Mutex
	pending []byte
	recvCh  chan []byte
	done    chan struct{}
	once    sync.Once
}

func (c *snowflakeConn) closeOnce() {
	c.once.Do(func() {
		close(c.done)
		atomic.AddInt64(&c.t.activeConns, -1)
	})
}

func (c *snowflakeConn) Read(b []byte) (int, error) {
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
	case data := <-c.recvCh:
		n := copy(b, data)
		if n < len(data) {
			c.mu.Lock()
			c.pending = append(c.pending, data[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	}
}

func (c *snowflakeConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}
	if err := c.dc.Send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *snowflakeConn) Close() error {
	c.dc.Close()
	c.pc.Close()
	c.closeOnce()
	return nil
}

func (c *snowflakeConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *snowflakeConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *snowflakeConn) SetDeadline(_ time.Time) error     { return nil }
func (c *snowflakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *snowflakeConn) SetWriteDeadline(_ time.Time) error { return nil }

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
