package dataplane

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
	"whispera/common/util"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "dataplane.processor"
	ModuleVersion = "1.0.0"

	DefaultMTU    = 1420
	MaxPacketSize = 65535
	MinPacketSize = 20
)

type Config struct {
	MTU                 int
	WorkerCount         int
	BufferSize          int
	EnableNAT           bool
	EnableFragmentation bool
	MaxFragmentSize     int
}

func DefaultConfig() *Config {
	return &Config{
		MTU:                 DefaultMTU,
		WorkerCount:         64,
		BufferSize:          524288,
		EnableNAT:           true,
		EnableFragmentation: true,
		MaxFragmentSize:     1400,
	}
}

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

type Processor struct {
	*base.Module
	config *Config

	tun            interfaces.TUNDevice
	router         interfaces.Router
	obfuscator     interfaces.Obfuscator
	sessionManager interfaces.SessionManager

	outboundManager *OutboundManager

	workerPool *base.WorkerPool

	inboundQueue  chan *packetJob
	outboundQueue chan *packetJob
	natTable      map[string]*natEntry
	natTableMu    sync.RWMutex

	packetsIn      uint64
	packetsOut     uint64
	bytesIn        uint64
	bytesOut       uint64
	packetsDropped uint64
	natEntries     uint64
}

type packetJob struct {
	Packet  *interfaces.Packet
	Session interfaces.Session
	Data    []byte
}

type natEntry struct {
	SrcAddr      net.Addr
	DstAddr      net.Addr
	SessionID    uint32
	StreamID     uint16
	Destination  *interfaces.Destination
	CreatedAt    time.Time
	LastUsed     time.Time
	lastUsedNano int64
}

func New(cfg *Config) (*Processor, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	om := NewOutboundManager()

	p := &Processor{
		Module:          base.NewModule(ModuleName, ModuleVersion, []string{"session.manager", "routing.engine"}),
		config:          cfg,
		workerPool:      base.NewWorkerPool(cfg.WorkerCount, cfg.BufferSize),
		inboundQueue:    make(chan *packetJob, cfg.BufferSize),
		outboundQueue:   make(chan *packetJob, cfg.BufferSize),
		natTable:        make(map[string]*natEntry),
		outboundManager: om,
	}

	return p, nil
}

func (p *Processor) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := p.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if dpCfg, ok := cfg.(*Config); ok {
		p.config = dpCfg
	}

	return nil
}

func (p *Processor) Start() error {
	if err := p.Module.Start(); err != nil {
		return err
	}

	p.workerPool.Start()

	go p.inboundProcessor()
	go p.outboundProcessor()

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

func (p *Processor) Stop() error {
	close(p.inboundQueue)
	close(p.outboundQueue)
	p.workerPool.Stop()

	p.PublishEvent(events.EventTypeModuleStopped, nil)
	return p.Module.Stop()
}

func (p *Processor) SetDependencies(
	router interfaces.Router,
	obfuscator interfaces.Obfuscator,
	sessionMgr interfaces.SessionManager,
) {
	p.router = router
	p.obfuscator = obfuscator
	p.sessionManager = sessionMgr
}

func (p *Processor) SetTUN(tun interfaces.TUNDevice) {
	p.tun = tun
}

func (p *Processor) GetOutboundManager() *OutboundManager {
	return p.outboundManager
}

func (p *Processor) SetStealthMode(mode string) {
	if p.outboundManager != nil {
		p.outboundManager.SetStealthMode(mode)
	}
}
func (p *Processor) ProcessInbound(ctx context.Context, packet *interfaces.Packet, session interfaces.Session) error {
	p.UpdateActivity()
	atomic.AddUint64(&p.packetsIn, 1)
	atomic.AddUint64(&p.bytesIn, uint64(len(packet.Payload)))

	if len(packet.Payload) < MinPacketSize {
		atomic.AddUint64(&p.packetsDropped, 1)
		return fmt.Errorf("packet too small: %d bytes", len(packet.Payload))
	}
	if session != nil {
		decrypted, err := session.Decrypt(packet.Seq, nil, packet.Payload)
		if err != nil {
			atomic.AddUint64(&p.packetsDropped, 1)
			return fmt.Errorf("decryption failed: %w", err)
		}
		packet.Payload = decrypted
	}

	key := packet.SrcAddr.String() + "->" + packet.DstAddr.String()
	if entry, ok := p.LookupNATEntry(key); ok {
		return p.handleDestination(packet.Payload, entry.Destination)
	}
	if p.router != nil {
		dest, err := p.router.Route(ctx, packet)
		if err != nil {
			atomic.AddUint64(&p.packetsDropped, 1)
			return fmt.Errorf("routing failed: %w", err)
		}

		p.AddNATEntry(key, packet.SrcAddr, packet.DstAddr, packet.SessionID, packet.StreamID, dest)

		return p.handleDestination(packet.Payload, dest)
	}

	return p.writeToTUN(packet.Payload)
}

func (p *Processor) handleDestination(data []byte, dest *interfaces.Destination) error {
	switch dest.Type {
	case interfaces.DestinationBlock:
		atomic.AddUint64(&p.packetsDropped, 1)
		return nil
	case interfaces.DestinationTUN:
		return p.writeToTUN(data)
	case interfaces.DestinationDirect:
		return p.writeToTUN(data)
	case interfaces.DestinationProxy:
		if p.outboundManager != nil {
			return p.outboundManager.ForwardPacket(data, dest.Tag)
		}
		return p.writeToTUN(data)
	}
	return p.writeToTUN(data)
}

func (p *Processor) ProcessOutbound(ctx context.Context, data []byte, session interfaces.Session) error {
	p.UpdateActivity()
	atomic.AddUint64(&p.packetsOut, 1)
	atomic.AddUint64(&p.bytesOut, uint64(len(data)))

	if len(data) < MinPacketSize {
		atomic.AddUint64(&p.packetsDropped, 1)
		return fmt.Errorf("packet too small: %d bytes", len(data))
	}

	processed := data

	if p.obfuscator != nil {
		obfuscated, delay, err := p.obfuscator.Process(processed, interfaces.DirectionOutbound)
		if err != nil {
			atomic.AddUint64(&p.packetsDropped, 1)
			return fmt.Errorf("obfuscation failed: %w", err)
		}
		processed = obfuscated

		_ = delay
	}

	if p.config.EnableFragmentation && len(processed) > p.config.MaxFragmentSize {
		return p.sendFragmented(processed, session)
	}

	if session != nil {
		encrypted, err := session.Encrypt(0, nil, processed)
		if err != nil {
			atomic.AddUint64(&p.packetsDropped, 1)
			return fmt.Errorf("encryption failed: %w", err)
		}
		processed = encrypted
	}

	p.PublishEvent(events.EventTypePacketSent, map[string]interface{}{
		"size": len(processed),
	})

	return nil
}

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

func (p *Processor) InjectPacket(data []byte) error {
	return p.writeToTUN(data)
}
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

		if session != nil {
			encrypted, err := session.Encrypt(0, nil, fragment)
			if err != nil {
				return fmt.Errorf("fragment encryption failed: %w", err)
			}
			_ = encrypted
		}
	}

	return nil
}

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

func (p *Processor) AddNATEntry(key string, srcAddr, dstAddr net.Addr, sessionID uint32, streamID uint16, dest *interfaces.Destination) {
	p.natTableMu.Lock()
	defer p.natTableMu.Unlock()

	now := time.Now()
	p.natTable[key] = &natEntry{
		SrcAddr:      srcAddr,
		DstAddr:      dstAddr,
		SessionID:    sessionID,
		StreamID:     streamID,
		Destination:  dest,
		CreatedAt:    now,
		LastUsed:     now,
		lastUsedNano: now.UnixNano(),
	}

	atomic.StoreUint64(&p.natEntries, uint64(len(p.natTable)))
}

func (p *Processor) LookupNATEntry(key string) (*natEntry, bool) {
	p.natTableMu.RLock()
	defer p.natTableMu.RUnlock()

	entry, ok := p.natTable[key]
	if ok {
		atomic.StoreInt64(&entry.lastUsedNano, util.GetGlobalTimeCache().NowNano())
	}
	return entry, ok
}

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

func (p *Processor) cleanupNAT() {
	p.natTableMu.Lock()
	defer p.natTableMu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute).UnixNano()
	for key, entry := range p.natTable {
		if atomic.LoadInt64(&entry.lastUsedNano) < cutoff {
			delete(p.natTable, key)
		}
	}

	atomic.StoreUint64(&p.natEntries, uint64(len(p.natTable)))
}

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

type Stats struct {
	PacketsIn      uint64
	PacketsOut     uint64
	BytesIn        uint64
	BytesOut       uint64
	PacketsDropped uint64
	NATEntries     uint64
}

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

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
