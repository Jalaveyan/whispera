// Package udp provides UDP transport module implementation
package udp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "transport.udp"
	ModuleVersion = "1.0.0"
)

// Config holds UDP transport configuration
type Config struct {
	ListenAddr    string
	MaxPacketSize int
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	BufferSize    int
	WorkerCount   int
}

// DefaultConfig returns default UDP configuration
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:    ":8443",
		MaxPacketSize: 65535, // Increased from 1472 to 65535 to completely fix Discord Voice and large UDP packets truncation
		ReadTimeout:   0,     // No timeout by default
		WriteTimeout:  10 * time.Second,
		BufferSize:    4096,
		WorkerCount:   16,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.MaxPacketSize <= 0 {
		c.MaxPacketSize = 65535
	}
	return nil
}

// Transport implements interfaces.PacketTransport for UDP
type Transport struct {
	*base.Module
	config      *Config
	conn        *net.UDPConn
	mu          sync.RWMutex
	workerPool  *base.WorkerPool
	rateLimiter *base.RateLimiter
	metrics     *base.Metrics
	bufferPool  *sync.Pool

	// XUDP support for Full Cone NAT
	xudpManager *XUDPManager

	// Callbacks for packet handling
	onPacket func(data []byte, addr net.Addr)

	// Stats
	packetsRx uint64
	packetsTx uint64
	bytesRx   uint64
	bytesTx   uint64
}

// New creates a new UDP transport module
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
		rateLimiter: base.NewRateLimiter(1000000, 100000), // ОПТИМИЗИРОВАНО: 1M packets/sec with burst of 100k
		metrics:     base.NewMetrics(),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, cfg.MaxPacketSize)
			},
		},
	}

	// Initialize XUDP manager for Full Cone NAT support
	t.xudpManager = NewXUDPManager(t)

	return t, nil
}

// Init initializes the transport
func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}

	// Parse config if provided
	if udpCfg, ok := cfg.(*Config); ok {
		t.config = udpCfg
	}

	return nil
}

// Start starts the UDP transport
func (t *Transport) Start() error {
	fmt.Printf("[UDP] Start() called, ListenAddr=%s\n", t.config.ListenAddr)

	if err := t.Module.Start(); err != nil {
		fmt.Printf("[UDP] Module.Start() failed: %v\n", err)
		return err
	}

	// Resolve UDP address
	fmt.Printf("[UDP] Resolving address: %s\n", t.config.ListenAddr)
	addr, err := net.ResolveUDPAddr("udp", t.config.ListenAddr)
	if err != nil {
		fmt.Printf("[UDP] ResolveUDPAddr failed: %v\n", err)
		t.SetHealthy(false, fmt.Sprintf("failed to resolve address: %v", err))
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}
	fmt.Printf("[UDP] Resolved to: %v\n", addr)

	// Listen on UDP
	fmt.Printf("[UDP] Calling net.ListenUDP on %v\n", addr)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("[UDP] ListenUDP FAILED: %v\n", err)
		t.SetHealthy(false, fmt.Sprintf("failed to listen: %v", err))
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	// Optimize UDP buffers for high throughput
	// 8MB buffers to handle micro-bursts without packet loss
	if err := conn.SetReadBuffer(8 * 1024 * 1024); err != nil {
		fmt.Printf("[UDP] Failed to set ReadBuffer: %v\n", err)
	}
	if err := conn.SetWriteBuffer(8 * 1024 * 1024); err != nil {
		fmt.Printf("[UDP] Failed to set WriteBuffer: %v\n", err)
	}

	fmt.Printf("[UDP] SUCCESS! Listening on UDP %s\n", conn.LocalAddr().String())

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()

	// Start worker pool
	t.workerPool.Start()

	// Start read loop
	go t.readLoop()

	t.SetHealthy(true, fmt.Sprintf("listening on %s", t.config.ListenAddr))
	t.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": t.config.ListenAddr,
	})

	fmt.Printf("[UDP] Start() completed successfully\n")
	return nil
}

// Stop stops the UDP transport
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

// Type returns the transport type
func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportUDP
}

// Listen starts listening (already done in Start)
func (t *Transport) Listen(addr string) error {
	// For UDP, we listen in Start()
	return nil
}

// Dial connects to a remote UDP address
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, udpAddr)
}

// Accept is not applicable for UDP
func (t *Transport) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("Accept() not supported for UDP transport")
}

// Close closes the transport
func (t *Transport) Close() error {
	return t.Stop()
}

// ReadFrom reads a packet from the UDP connection
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

// WriteTo writes a packet to the specified address
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

// OnPacket sets the packet handler callback
func (t *Transport) OnPacket(handler func(data []byte, addr net.Addr)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onPacket = handler
}

// readLoop is the main packet reading loop
func (t *Transport) readLoop() {
	fmt.Printf("[UDP] readLoop started (Zero-Alloc Mode)\n")

	for t.IsRunning() {
		// Zero-Alloc: Get buffer from pool
		buf := t.bufferPool.Get().([]byte)
		// Reset capacity to max (important!)
		buf = buf[:cap(buf)]

		n, addr, err := t.ReadFrom(buf)
		if err != nil {
			t.bufferPool.Put(buf) // Return buffer on error

			if !t.IsRunning() {
				return
			}
			// Handle temporary errors
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				fmt.Printf("[UDP] Temporary read error: %v\n", err)
				continue
			}
			// Log and continue for other errors
			fmt.Printf("[UDP] Read error: %v\n", err)
			t.metrics.Increment("read_errors")
			time.Sleep(100 * time.Millisecond) // Prevent busy loop
			continue
		}

		// fmt.Printf("[UDP] Read %d bytes from %s\n", n, addr.String())

		// Rate limit check
		if !t.rateLimiter.Allow() {
			t.metrics.Increment("rate_limited")
			t.bufferPool.Put(buf) // Return buffer if dropped
			continue
		}

		// Submit to worker pool
		// We pass the SLICE (buf[:n]) to the handler
		// And return the backing array (buf) to the pool after processing
		t.workerPool.SubmitAsync(func() {
			t.handlePacket(buf[:n], addr)
			t.bufferPool.Put(buf)
		})
	}
}

// handlePacket processes a received packet
func (t *Transport) handlePacket(data []byte, addr net.Addr) {
	t.mu.RLock()
	handler := t.onPacket
	t.mu.RUnlock()

	if handler != nil {
		handler(data, addr)
	}

	// Publish event
	t.PublishEvent(events.EventTypePacketReceived, map[string]interface{}{
		"size":    len(data),
		"address": addr.String(),
	})
}

// HealthCheck returns detailed health status
func (t *Transport) HealthCheck() interfaces.HealthStatus {
	status := t.Module.HealthCheck()
	status.Details["packets_rx"] = atomic.LoadUint64(&t.packetsRx)
	status.Details["packets_tx"] = atomic.LoadUint64(&t.packetsTx)
	status.Details["bytes_rx"] = atomic.LoadUint64(&t.bytesRx)
	status.Details["bytes_tx"] = atomic.LoadUint64(&t.bytesTx)
	status.Details["listen_addr"] = t.config.ListenAddr
	return status
}

// Stats returns transport statistics
func (t *Transport) Stats() TransportStats {
	return TransportStats{
		PacketsRx: atomic.LoadUint64(&t.packetsRx),
		PacketsTx: atomic.LoadUint64(&t.packetsTx),
		BytesRx:   atomic.LoadUint64(&t.bytesRx),
		BytesTx:   atomic.LoadUint64(&t.bytesTx),
	}
}

// GetXUDPManager returns the XUDP manager for Full Cone NAT support
func (t *Transport) GetXUDPManager() *XUDPManager {
	return t.xudpManager
}

// HandleXUDPPacket processes an XUDP packet and returns payload + session
func (t *Transport) HandleXUDPPacket(data []byte, addr net.Addr) ([]byte, *XUDPSession, error) {
	if t.xudpManager == nil {
		return data, nil, nil
	}
	return t.xudpManager.HandlePacket(data, addr)
}

// TransportStats holds transport statistics
type TransportStats struct {
	PacketsRx uint64
	PacketsTx uint64
	BytesRx   uint64
	BytesTx   uint64
}

// GetConnection returns the underlying UDP connection (for advanced usage)
func (t *Transport) GetConnection() *net.UDPConn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn
}

// SetRateLimit updates the rate limiter configuration
func (t *Transport) SetRateLimit(rate float64, burst int) {
	t.rateLimiter.SetRate(rate, burst)
}

// Factory creates UDP transport modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
