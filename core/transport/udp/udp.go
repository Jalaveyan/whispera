package udp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"whispera/common/runtime/base"
	"whispera/common/runtime/events"
	"whispera/common/runtime/interfaces"
	"whispera/common/runtime/registry"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "transport.udp"
	ModuleVersion = "1.0.0"
)

type Config struct {
	ListenAddr    string
	MaxPacketSize int
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	BufferSize    int
	WorkerCount   int
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:    ":8443",
		MaxPacketSize: 65535,
		ReadTimeout:   0,
		WriteTimeout:  10 * time.Second,
		BufferSize:    32768,
		WorkerCount:   16,
	}
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.MaxPacketSize <= 0 {
		c.MaxPacketSize = 65535
	}
	return nil
}

type Transport struct {
	*base.Module
	config      *Config
	conn        *net.UDPConn
	mu          sync.RWMutex
	workerPool  *base.WorkerPool
	rateLimiter *base.RateLimiter
	metrics     *base.Metrics
	bufferPool  *sync.Pool

	xudpManager *XUDPManager

	onPacket func(data []byte, addr net.Addr)

	packetsRx uint64
	packetsTx uint64
	bytesRx   uint64
	bytesTx   uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		config:      cfg,
		workerPool:  base.NewWorkerPool(cfg.WorkerCount, cfg.BufferSize),
		rateLimiter: base.NewRateLimiter(1000000, 100000),
		metrics:     base.NewMetrics(),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, cfg.MaxPacketSize)
			},
		},
	}

	t.xudpManager = NewXUDPManager(t)

	return t, nil
}

func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if udpCfg, ok := cfg.(*Config); ok {
		t.config = udpCfg
	}

	return nil
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", t.config.ListenAddr)
	if err != nil {
		t.SetHealthy(false, fmt.Sprintf("failed to resolve address: %v", err))
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.SetHealthy(false, fmt.Sprintf("failed to listen: %v", err))
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	_ = conn.SetReadBuffer(32 * 1024 * 1024)
	_ = conn.SetWriteBuffer(32 * 1024 * 1024)

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()

	t.workerPool.Start()

	go t.readLoop()

	t.SetHealthy(true, fmt.Sprintf("listening on %s", t.config.ListenAddr))
	t.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": t.config.ListenAddr,
	})

	return nil
}

func (t *Transport) Stop() error {
	t.mu.Lock()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.mu.Unlock()

	t.workerPool.Stop()

	t.PublishEvent(events.EventTypeModuleStopped, nil)
	return t.Module.Stop()
}

func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportUDP
}

func (t *Transport) Listen(addr string) error {
	return nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, udpAddr)
}

func (t *Transport) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("Accept() not supported for UDP transport")
}

func (t *Transport) Close() error {
	return t.Stop()
}

func (t *Transport) ReadFrom(buf []byte) (n int, addr net.Addr, err error) {
	t.mu.RLock()
	conn := t.conn
	t.mu.RUnlock()

	if conn == nil {
		return 0, nil, fmt.Errorf("transport not running")
	}

	n, udpAddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}

	atomic.AddUint64(&t.packetsRx, 1)
	atomic.AddUint64(&t.bytesRx, uint64(n))
	t.UpdateActivity()

	return n, udpAddr, nil
}

func (t *Transport) WriteTo(buf []byte, addr net.Addr) (n int, err error) {
	t.mu.RLock()
	conn := t.conn
	t.mu.RUnlock()

	if conn == nil {
		return 0, fmt.Errorf("transport not running")
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("address must be *net.UDPAddr")
	}

	n, err = conn.WriteToUDP(buf, udpAddr)
	if err != nil {
		return 0, err
	}

	atomic.AddUint64(&t.packetsTx, 1)
	atomic.AddUint64(&t.bytesTx, uint64(n))
	t.UpdateActivity()

	return n, nil
}

func (t *Transport) OnPacket(handler func(data []byte, addr net.Addr)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onPacket = handler
}

func (t *Transport) readLoop() {
	for t.IsRunning() {
		buf := t.bufferPool.Get().([]byte)
		buf = buf[:cap(buf)]

		n, addr, err := t.ReadFrom(buf)
		if err != nil {
			t.bufferPool.Put(buf)

			if !t.IsRunning() {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			t.metrics.Increment("read_errors")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if !t.rateLimiter.Allow() {
			t.metrics.Increment("rate_limited")
			t.bufferPool.Put(buf)
			continue
		}

		submitted := t.workerPool.TrySubmit(func() {
			t.handlePacket(buf[:n], addr)
			t.bufferPool.Put(buf)
		})

		if !submitted {
			t.metrics.Increment("queue_full_drops")
			t.bufferPool.Put(buf)
		}
	}
}

func (t *Transport) handlePacket(data []byte, addr net.Addr) {
	t.mu.RLock()
	handler := t.onPacket
	t.mu.RUnlock()

	if handler != nil {
		handler(data, addr)
	}

	t.PublishEvent(events.EventTypePacketReceived, map[string]interface{}{
		"size":    len(data),
		"address": addr.String(),
	})
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	status := t.Module.HealthCheck()
	status.Details["packets_rx"] = atomic.LoadUint64(&t.packetsRx)
	status.Details["packets_tx"] = atomic.LoadUint64(&t.packetsTx)
	status.Details["bytes_rx"] = atomic.LoadUint64(&t.bytesRx)
	status.Details["bytes_tx"] = atomic.LoadUint64(&t.bytesTx)
	status.Details["listen_addr"] = t.config.ListenAddr
	return status
}

func (t *Transport) Stats() TransportStats {
	return TransportStats{
		PacketsRx: atomic.LoadUint64(&t.packetsRx),
		PacketsTx: atomic.LoadUint64(&t.packetsTx),
		BytesRx:   atomic.LoadUint64(&t.bytesRx),
		BytesTx:   atomic.LoadUint64(&t.bytesTx),
	}
}

func (t *Transport) GetXUDPManager() *XUDPManager {
	return t.xudpManager
}

func (t *Transport) HandleXUDPPacket(data []byte, addr net.Addr) ([]byte, *XUDPSession, error) {
	if t.xudpManager == nil {
		return data, nil, nil
	}
	return t.xudpManager.HandlePacket(data, addr)
}

type TransportStats struct {
	PacketsRx uint64
	PacketsTx uint64
	BytesRx   uint64
	BytesTx   uint64
}

func (t *Transport) GetConnection() *net.UDPConn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn
}

func (t *Transport) SetRateLimit(rate float64, burst int) {
	t.rateLimiter.SetRate(rate, burst)
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
