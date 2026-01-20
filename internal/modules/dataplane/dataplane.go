// Package dataplane provides the data plane packet processing module
package dataplane

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
	ModuleName    = "dataplane.processor"
	ModuleVersion = "1.0.0"

	// Default packet sizes
	DefaultMTU    = 1420
	MaxPacketSize = 65535
	MinPacketSize = 20 // Minimum IP header size
)

// Config holds data plane configuration
type Config struct {
	MTU                 int
	WorkerCount         int
	BufferSize          int
	EnableNAT           bool
	EnableFragmentation bool
	MaxFragmentSize     int
}

// DefaultConfig returns default data plane configuration
func DefaultConfig() *Config {
	return &Config{
		MTU:                 DefaultMTU,
		WorkerCount:         16,    // Optimized for high concurrency
		BufferSize:          65536, // Increased buffer to prevent packet drops at 500Mbps
		EnableNAT:           true,
		EnableFragmentation: true,
		MaxFragmentSize:     1400,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.MTU <= 0 || c.MTU > MaxPacketSize {
		c.MTU = DefaultMTU
	}
	if c.WorkerCount <= 0 {
		c.WorkerCount = 8
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 4096
	}
	if c.MaxFragmentSize <= 0 {
		c.MaxFragmentSize = 1400
	}
	return nil
}

// Processor implements interfaces.DataPlane
type Processor struct {
	*base.Module
	config *Config

	// Dependencies
	tun            interfaces.TUNDevice
	router         interfaces.Router
	obfuscator     interfaces.Obfuscator
	sessionManager interfaces.SessionManager

	// Worker pool
	workerPool *base.WorkerPool

	// Packet queues
	inboundQueue  chan *packetJob
	outboundQueue chan *packetJob

	// NAT table (for NAT mode)
	natTable   map[string]*natEntry
	natTableMu sync.RWMutex

	// Stats
	packetsIn      uint64
	packetsOut     uint64
	bytesIn        uint64
	bytesOut       uint64
	packetsDropped uint64
	natEntries     uint64
}

// packetJob represents a packet processing job
type packetJob struct {
	Packet  *interfaces.Packet
	Session interfaces.Session
	Data    []byte
}

// natEntry represents a NAT table entry
type natEntry struct {
	SrcAddr   net.Addr
	DstAddr   net.Addr
	SessionID uint32
	StreamID  uint16
	CreatedAt time.Time
	LastUsed  time.Time
}

// New creates a new data plane processor
func New(cfg *Config) (*Processor, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	p := &Processor{
		Module:        base.NewModule(ModuleName, ModuleVersion, []string{"session.manager", "routing.engine"}),
		config:        cfg,
		workerPool:    base.NewWorkerPool(cfg.WorkerCount, cfg.BufferSize),
		inboundQueue:  make(chan *packetJob, cfg.BufferSize),
		outboundQueue: make(chan *packetJob, cfg.BufferSize),
		natTable:      make(map[string]*natEntry),
	}

	return p, nil
}

// Init initializes the data plane
func (p *Processor) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := p.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if dpCfg, ok := cfg.(*Config); ok {
		p.config = dpCfg
	}

	return nil
}

// Start starts the data plane
func (p *Processor) Start() error {
	if err := p.Module.Start(); err != nil {
		return err
	}

	// Start worker pool
	p.workerPool.Start()

	// Start processing goroutines
	go p.inboundProcessor()
	go p.outboundProcessor()

	// Start NAT cleanup if enabled
	if p.config.EnableNAT {
		go p.natCleanupLoop()
	}

	p.SetHealthy(true, "data plane running")
	p.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"mtu":     p.config.MTU,
		"workers": p.config.WorkerCount,
	})

	return nil
}

// Stop stops the data plane
func (p *Processor) Stop() error {
	close(p.inboundQueue)
	close(p.outboundQueue)
	p.workerPool.Stop()

	p.PublishEvent(events.EventTypeModuleStopped, nil)
	return p.Module.Stop()
}

// SetDependencies sets module dependencies
func (p *Processor) SetDependencies(
	router interfaces.Router,
	obfuscator interfaces.Obfuscator,
	sessionMgr interfaces.SessionManager,
) {
	p.router = router
	p.obfuscator = obfuscator
	p.sessionManager = sessionMgr
}

// SetTUN sets the TUN interface
func (p *Processor) SetTUN(tun interfaces.TUNDevice) {
	p.tun = tun
}

// ProcessInbound processes an inbound packet
func (p *Processor) ProcessInbound(ctx context.Context, packet *interfaces.Packet, session interfaces.Session) error {
	p.UpdateActivity()
	atomic.AddUint64(&p.packetsIn, 1)
	atomic.AddUint64(&p.bytesIn, uint64(len(packet.Payload)))

	// Validate packet
	if len(packet.Payload) < MinPacketSize {
		atomic.AddUint64(&p.packetsDropped, 1)
		return fmt.Errorf("packet too small: %d bytes", len(packet.Payload))
	}

	// Decrypt if session provided
	if session != nil {
		decrypted, err := session.Decrypt(packet.Seq, nil, packet.Payload)
		if err != nil {
			atomic.AddUint64(&p.packetsDropped, 1)
			return fmt.Errorf("decryption failed: %w", err)
		}
		packet.Payload = decrypted
	}

	// De-obfuscate if obfuscator available
	if p.obfuscator != nil {
		deobfuscated, _, err := p.obfuscator.Process(packet.Payload, interfaces.DirectionInbound)
		if err != nil {
			atomic.AddUint64(&p.packetsDropped, 1)
			return fmt.Errorf("deobfuscation failed: %w", err)
		}
		packet.Payload = deobfuscated
	}

	// Route packet
	if p.router != nil {
		dest, err := p.router.Route(ctx, packet)
		if err != nil {
			atomic.AddUint64(&p.packetsDropped, 1)
			return fmt.Errorf("routing failed: %w", err)
		}

		switch dest.Type {
		case interfaces.DestinationBlock:
			atomic.AddUint64(&p.packetsDropped, 1)
			return nil // Silently drop
		case interfaces.DestinationTUN:
			return p.writeToTUN(packet.Payload)
		case interfaces.DestinationDirect:
			return p.writeToTUN(packet.Payload)
		case interfaces.DestinationProxy:
			// Would forward to proxy - not implemented in this module
			return p.writeToTUN(packet.Payload)
		}
	}

	// Default: write to TUN
	return p.writeToTUN(packet.Payload)
}

// ProcessOutbound processes an outbound packet
func (p *Processor) ProcessOutbound(ctx context.Context, data []byte, session interfaces.Session) error {
	p.UpdateActivity()
	atomic.AddUint64(&p.packetsOut, 1)
	atomic.AddUint64(&p.bytesOut, uint64(len(data)))

	// Validate packet
	if len(data) < MinPacketSize {
		atomic.AddUint64(&p.packetsDropped, 1)
		return fmt.Errorf("packet too small: %d bytes", len(data))
	}

	processed := data

	// Obfuscate if obfuscator available
	if p.obfuscator != nil {
		obfuscated, delay, err := p.obfuscator.Process(processed, interfaces.DirectionOutbound)
		if err != nil {
			atomic.AddUint64(&p.packetsDropped, 1)
			return fmt.Errorf("obfuscation failed: %w", err)
		}
		processed = obfuscated

		// Apply timing delay if needed
		// OPTIMIZATION: Removed sleep for maximum throughput
		// Data plane should process packets as fast as possible.
		// Artificial delays cause TCP/QUIC retransmissions.
		_ = delay
		// if delay > 0 {
		// 	time.Sleep(delay)
		// }
	}

	// Fragment if needed
	if p.config.EnableFragmentation && len(processed) > p.config.MaxFragmentSize {
		return p.sendFragmented(processed, session)
	}

	// Encrypt if session provided
	if session != nil {
		// Get next sequence number
		// Note: This is a simplified approach
		encrypted, err := session.Encrypt(0, nil, processed)
		if err != nil {
			atomic.AddUint64(&p.packetsDropped, 1)
			return fmt.Errorf("encryption failed: %w", err)
		}
		processed = encrypted
	}

	// Send packet
	p.PublishEvent(events.EventTypePacketSent, map[string]interface{}{
		"size": len(processed),
	})

	return nil
}

// writeToTUN writes a packet to the TUN interface
func (p *Processor) writeToTUN(data []byte) error {
	if p.tun == nil {
		return fmt.Errorf("TUN device not set")
	}

	n, err := p.tun.Write(data)
	if err != nil {
		return fmt.Errorf("TUN write failed: %w", err)
	}

	if n != len(data) {
		return fmt.Errorf("TUN write incomplete: wrote %d of %d bytes", n, len(data))
	}

	return nil
}

// sendFragmented sends a large packet in fragments
func (p *Processor) sendFragmented(data []byte, session interfaces.Session) error {
	fragmentSize := p.config.MaxFragmentSize
	fragments := (len(data) + fragmentSize - 1) / fragmentSize

	for i := 0; i < fragments; i++ {
		start := i * fragmentSize
		end := start + fragmentSize
		if end > len(data) {
			end = len(data)
		}

		fragment := data[start:end]

		// Process fragment
		if session != nil {
			encrypted, err := session.Encrypt(0, nil, fragment)
			if err != nil {
				return fmt.Errorf("fragment encryption failed: %w", err)
			}
			_ = encrypted // Would send encrypted fragment
		}
	}

	return nil
}

// inboundProcessor processes inbound packets from queue
func (p *Processor) inboundProcessor() {
	for job := range p.inboundQueue {
		if job == nil {
			continue
		}

		if err := p.ProcessInbound(context.Background(), job.Packet, job.Session); err != nil {
			p.PublishEvent(events.EventTypePacketDropped, map[string]interface{}{
				"direction": "inbound",
				"error":     err.Error(),
			})
		}
	}
}

// outboundProcessor processes outbound packets from queue
func (p *Processor) outboundProcessor() {
	for job := range p.outboundQueue {
		if job == nil {
			continue
		}

		if err := p.ProcessOutbound(context.Background(), job.Data, job.Session); err != nil {
			p.PublishEvent(events.EventTypePacketDropped, map[string]interface{}{
				"direction": "outbound",
				"error":     err.Error(),
			})
		}
	}
}

// QueueInbound queues an inbound packet for processing
func (p *Processor) QueueInbound(packet *interfaces.Packet, session interfaces.Session) bool {
	job := &packetJob{
		Packet:  packet,
		Session: session,
	}

	select {
	case p.inboundQueue <- job:
		return true
	default:
		atomic.AddUint64(&p.packetsDropped, 1)
		return false
	}
}

// QueueOutbound queues an outbound packet for processing
func (p *Processor) QueueOutbound(data []byte, session interfaces.Session) bool {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	job := &packetJob{
		Data:    dataCopy,
		Session: session,
	}

	select {
	case p.outboundQueue <- job:
		return true
	default:
		atomic.AddUint64(&p.packetsDropped, 1)
		return false
	}
}

// AddNATEntry adds a NAT table entry
func (p *Processor) AddNATEntry(key string, srcAddr, dstAddr net.Addr, sessionID uint32, streamID uint16) {
	p.natTableMu.Lock()
	defer p.natTableMu.Unlock()

	p.natTable[key] = &natEntry{
		SrcAddr:   srcAddr,
		DstAddr:   dstAddr,
		SessionID: sessionID,
		StreamID:  streamID,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	atomic.StoreUint64(&p.natEntries, uint64(len(p.natTable)))
}

// LookupNATEntry looks up a NAT table entry
func (p *Processor) LookupNATEntry(key string) (*natEntry, bool) {
	p.natTableMu.RLock()
	defer p.natTableMu.RUnlock()

	entry, ok := p.natTable[key]
	if ok {
		entry.LastUsed = time.Now()
	}
	return entry, ok
}

// natCleanupLoop cleans up expired NAT entries
func (p *Processor) natCleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for p.IsRunning() {
		select {
		case <-p.Context().Done():
			return
		case <-ticker.C:
			p.cleanupNAT()
		}
	}
}

// cleanupNAT removes expired NAT entries
func (p *Processor) cleanupNAT() {
	p.natTableMu.Lock()
	defer p.natTableMu.Unlock()

	now := time.Now()
	for key, entry := range p.natTable {
		if now.Sub(entry.LastUsed) > 5*time.Minute {
			delete(p.natTable, key)
		}
	}

	atomic.StoreUint64(&p.natEntries, uint64(len(p.natTable)))
}

// HealthCheck returns health status
func (p *Processor) HealthCheck() interfaces.HealthStatus {
	status := p.Module.HealthCheck()

	status.Details["packets_in"] = atomic.LoadUint64(&p.packetsIn)
	status.Details["packets_out"] = atomic.LoadUint64(&p.packetsOut)
	status.Details["bytes_in"] = atomic.LoadUint64(&p.bytesIn)
	status.Details["bytes_out"] = atomic.LoadUint64(&p.bytesOut)
	status.Details["packets_dropped"] = atomic.LoadUint64(&p.packetsDropped)
	status.Details["nat_entries"] = atomic.LoadUint64(&p.natEntries)
	status.Details["inbound_queue_size"] = len(p.inboundQueue)
	status.Details["outbound_queue_size"] = len(p.outboundQueue)
	status.Details["mtu"] = p.config.MTU

	if p.tun != nil {
		status.Details["tun_name"] = p.tun.Name()
	}

	return status
}

// Stats returns data plane statistics
type Stats struct {
	PacketsIn      uint64
	PacketsOut     uint64
	BytesIn        uint64
	BytesOut       uint64
	PacketsDropped uint64
	NATEntries     uint64
}

// GetStats returns current statistics
func (p *Processor) GetStats() Stats {
	return Stats{
		PacketsIn:      atomic.LoadUint64(&p.packetsIn),
		PacketsOut:     atomic.LoadUint64(&p.packetsOut),
		BytesIn:        atomic.LoadUint64(&p.bytesIn),
		BytesOut:       atomic.LoadUint64(&p.bytesOut),
		PacketsDropped: atomic.LoadUint64(&p.packetsDropped),
		NATEntries:     atomic.LoadUint64(&p.natEntries),
	}
}

// Factory creates data plane modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
