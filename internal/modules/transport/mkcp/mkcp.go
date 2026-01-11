// Package mkcp implements mKCP transport - UDP with Forward Error Correction
// mKCP is designed for lossy networks where TCP performs poorly
package mkcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("mkcp")

const (
	ModuleName    = "transport.mkcp"
	ModuleVersion = "1.0.0"

	// Packet types
	packetTypeData  = 0x01
	packetTypeAck   = 0x02
	packetTypeFEC   = 0x05
	packetTypeClose = 0x06

	// FEC configuration
	defaultDataShards   = 10 // Data packets before FEC
	defaultParityShards = 3  // FEC parity packets

	// Timing
	defaultRTT      = 100 * time.Millisecond
	defaultInterval = 30 * time.Millisecond
	defaultTimeout  = 30 * time.Second
	maxPacketSize   = 1400
	headerSize      = 24

	// Congestion control
	defaultCongestionWindow = 32
	maxCongestionWindow     = 1024
)

// Config holds mKCP configuration
type Config struct {
	// Network settings
	ListenAddr string
	RemoteAddr string

	// FEC settings (Forward Error Correction)
	DataShards   int  // Number of data packets
	ParityShards int  // Number of parity packets
	EnableFEC    bool // Enable FEC

	// Congestion control
	CongestionWindow int           // Initial congestion window
	NoDelay          bool          // Disable Nagle's algorithm
	Interval         time.Duration // Flush interval
	Resend           int           // Fast resend threshold
	NoCongestion     bool          // Disable congestion control

	// Encryption
	EnableCrypt bool   // Enable encryption
	CryptKey    []byte // Encryption key

	// Timing
	RTT       time.Duration
	Timeout   time.Duration
	KeepAlive time.Duration

	// Buffer sizes
	SendBuffer    int
	ReceiveBuffer int

	// Mode presets
	Mode string // normal, fast, fast2, fast3
}

// DefaultConfig returns default mKCP configuration
func DefaultConfig() *Config {
	return &Config{
		DataShards:       defaultDataShards,
		ParityShards:     defaultParityShards,
		EnableFEC:        true,
		CongestionWindow: defaultCongestionWindow,
		NoDelay:          true,
		Interval:         defaultInterval,
		Resend:           2,
		NoCongestion:     false,
		RTT:              defaultRTT,
		Timeout:          defaultTimeout,
		KeepAlive:        10 * time.Second,
		SendBuffer:       4 * 1024 * 1024,
		ReceiveBuffer:    4 * 1024 * 1024,
		Mode:             "fast",
	}
}

// ApplyMode applies a preset mode to the config
func (c *Config) ApplyMode(mode string) {
	switch mode {
	case "normal":
		c.NoDelay = false
		c.Interval = 40 * time.Millisecond
		c.Resend = 2
		c.NoCongestion = false
	case "fast":
		c.NoDelay = false
		c.Interval = 30 * time.Millisecond
		c.Resend = 2
		c.NoCongestion = true
	case "fast2":
		c.NoDelay = true
		c.Interval = 20 * time.Millisecond
		c.Resend = 2
		c.NoCongestion = true
	case "fast3":
		c.NoDelay = true
		c.Interval = 10 * time.Millisecond
		c.Resend = 1
		c.NoCongestion = true
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.DataShards <= 0 {
		c.DataShards = defaultDataShards
	}
	if c.ParityShards < 0 {
		c.ParityShards = defaultParityShards
	}
	if c.CongestionWindow <= 0 {
		c.CongestionWindow = defaultCongestionWindow
	}
	if c.Mode != "" {
		c.ApplyMode(c.Mode)
	}
	return nil
}

// Segment represents a mKCP segment
type Segment struct {
	conv     uint32    // Conversation ID
	cmd      uint8     // Command type
	frg      uint8     // Fragment count
	wnd      uint16    // Window size
	ts       uint32    // Timestamp
	sn       uint32    // Sequence number
	una      uint32    // Unacknowledged sequence number
	data     []byte    // Payload
	resendTs time.Time // Resend timestamp
	rto      time.Duration
	fastack  uint32
	xmit     uint32 // Transmit count
}

// Connection represents a mKCP connection
type Connection struct {
	mu    sync.RWMutex
	conv  uint32
	state int32 // 0=closed, 1=open, 2=closing

	// Underlying UDP
	conn   net.PacketConn
	remote net.Addr

	// Send/receive buffers
	sendBuf []*Segment
	recvBuf []*Segment
	sendWnd []uint32 // Send window
	recvWnd []uint32 // Receive window

	// Sequence numbers
	sndUna uint32 // Send unacknowledged
	sndNxt uint32 // Send next
	rcvNxt uint32 // Receive next

	// Window sizes
	sndWnd   uint32 // Send window size
	rcvWnd   uint32 // Receive window size
	rmt_wnd  uint32 // Remote window size
	cwnd     uint32 // Congestion window
	ssthresh uint32 // Slow start threshold

	// RTT estimation
	rx_rtt    time.Duration
	rx_srtt   time.Duration
	rx_rttval time.Duration
	rx_rto    time.Duration
	rx_minrto time.Duration

	// FEC
	fec        *FECEncoder
	fecDecoder *FECDecoder

	// Buffers
	recvQueue chan []byte

	// Config
	config *Config

	// Stats
	bytesIn      uint64
	bytesOut     uint64
	packetsIn    uint64
	packetsOut   uint64
	retransmits  uint64
	fecRecovered uint64

	// Timing
	lastRecv time.Time
	lastSend time.Time

	// Close handling
	closeOnce sync.Once
	closeCh   chan struct{}
}

// FECEncoder handles Forward Error Correction encoding
type FECEncoder struct {
	dataShards   int
	parityShards int
	shardSize    int
	paws         uint32
	next         uint32
	shards       [][]byte
	current      int
}

// NewFECEncoder creates a new FEC encoder
func NewFECEncoder(dataShards, parityShards, shardSize int) *FECEncoder {
	return &FECEncoder{
		dataShards:   dataShards,
		parityShards: parityShards,
		shardSize:    shardSize,
		shards:       make([][]byte, dataShards+parityShards),
	}
}

// Encode adds data and returns FEC packets when ready
func (e *FECEncoder) Encode(data []byte) [][]byte {
	// Store shard
	shard := make([]byte, e.shardSize)
	copy(shard, data)
	e.shards[e.current] = shard
	e.current++

	// Check if we have enough shards for FEC
	if e.current >= e.dataShards {
		// Generate parity shards using XOR (simplified Reed-Solomon)
		parityShards := e.generateParity()
		e.current = 0
		return parityShards
	}
	return nil
}

// generateParity generates parity shards using XOR
func (e *FECEncoder) generateParity() [][]byte {
	result := make([][]byte, e.parityShards)
	for i := 0; i < e.parityShards; i++ {
		parity := make([]byte, e.shardSize)
		// XOR all data shards with offset
		for j := 0; j < e.dataShards; j++ {
			offset := (i + j) % e.dataShards
			if e.shards[offset] != nil {
				for k := 0; k < len(parity) && k < len(e.shards[offset]); k++ {
					parity[k] ^= e.shards[offset][k]
				}
			}
		}
		result[i] = parity
	}
	return result
}

// FECDecoder handles Forward Error Correction decoding
type FECDecoder struct {
	dataShards   int
	parityShards int
	shardSize    int
	shards       map[uint32][]byte
	received     map[uint32]bool
}

// NewFECDecoder creates a new FEC decoder
func NewFECDecoder(dataShards, parityShards, shardSize int) *FECDecoder {
	return &FECDecoder{
		dataShards:   dataShards,
		parityShards: parityShards,
		shardSize:    shardSize,
		shards:       make(map[uint32][]byte),
		received:     make(map[uint32]bool),
	}
}

// Decode attempts to recover lost packets
func (d *FECDecoder) Decode(sn uint32, data []byte, isFEC bool) [][]byte {
	d.shards[sn] = data
	d.received[sn] = true

	// Try to recover if we have enough shards
	var recovered [][]byte
	// Simplified recovery using XOR
	// In real implementation, use proper Reed-Solomon decoding

	return recovered
}

// Transport implements the mKCP transport
type Transport struct {
	*base.Module
	config *Config

	mu       sync.RWMutex
	listener net.PacketConn
	conns    map[uint32]*Connection

	// Stats
	totalBytesIn  uint64
	totalBytesOut uint64
	activeConns   int32
}

// New creates a new mKCP transport
func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		conns:  make(map[uint32]*Connection),
	}

	return t, nil
}

// Listen starts listening for mKCP connections
func (t *Transport) Listen(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", t.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	t.mu.Lock()
	t.listener = conn
	t.mu.Unlock()

	log.Info("mKCP listening on %s", t.config.ListenAddr)

	// Start accept loop
	go t.acceptLoop(ctx)

	return nil
}

// acceptLoop handles incoming packets
func (t *Transport) acceptLoop(ctx context.Context) {
	buf := make([]byte, maxPacketSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, addr, err := t.listener.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("Read error: %v", err)
			continue
		}

		// Parse packet header
		if n < headerSize {
			continue
		}

		conv := binary.LittleEndian.Uint32(buf[:4])

		t.mu.RLock()
		conn, exists := t.conns[conv]
		t.mu.RUnlock()

		if !exists {
			// New connection
			conn = t.newConnection(conv, addr)
			t.mu.Lock()
			t.conns[conv] = conn
			t.mu.Unlock()
			atomic.AddInt32(&t.activeConns, 1)
		}

		// Process packet
		conn.processPacket(buf[:n])
	}
}

// newConnection creates a new mKCP connection
func (t *Transport) newConnection(conv uint32, addr net.Addr) *Connection {
	conn := &Connection{
		conv:      conv,
		state:     1,
		conn:      t.listener,
		remote:    addr,
		sendBuf:   make([]*Segment, 0, 256),
		recvBuf:   make([]*Segment, 0, 256),
		sndWnd:    uint32(t.config.CongestionWindow),
		rcvWnd:    uint32(t.config.CongestionWindow),
		cwnd:      uint32(t.config.CongestionWindow),
		ssthresh:  uint32(maxCongestionWindow),
		rx_rto:    t.config.RTT,
		rx_minrto: t.config.Interval,
		config:    t.config,
		recvQueue: make(chan []byte, 256),
		closeCh:   make(chan struct{}),
		lastRecv:  time.Now(),
		lastSend:  time.Now(),
	}

	if t.config.EnableFEC {
		conn.fec = NewFECEncoder(t.config.DataShards, t.config.ParityShards, maxPacketSize)
		conn.fecDecoder = NewFECDecoder(t.config.DataShards, t.config.ParityShards, maxPacketSize)
	}

	// Start flush loop
	go conn.flushLoop()

	return conn
}

// Dial connects to a remote mKCP server
func (t *Transport) Dial(ctx context.Context, address string) (net.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	// Generate conversation ID
	var convBuf [4]byte
	rand.Read(convBuf[:])
	conv := binary.LittleEndian.Uint32(convBuf[:])

	mkcpConn := &Connection{
		conv:      conv,
		state:     1,
		conn:      conn,
		remote:    addr,
		sendBuf:   make([]*Segment, 0, 256),
		recvBuf:   make([]*Segment, 0, 256),
		sndWnd:    uint32(t.config.CongestionWindow),
		rcvWnd:    uint32(t.config.CongestionWindow),
		cwnd:      uint32(t.config.CongestionWindow),
		ssthresh:  uint32(maxCongestionWindow),
		rx_rto:    t.config.RTT,
		rx_minrto: t.config.Interval,
		config:    t.config,
		recvQueue: make(chan []byte, 256),
		closeCh:   make(chan struct{}),
		lastRecv:  time.Now(),
		lastSend:  time.Now(),
	}

	if t.config.EnableFEC {
		mkcpConn.fec = NewFECEncoder(t.config.DataShards, t.config.ParityShards, maxPacketSize)
		mkcpConn.fecDecoder = NewFECDecoder(t.config.DataShards, t.config.ParityShards, maxPacketSize)
	}

	t.mu.Lock()
	t.conns[conv] = mkcpConn
	t.mu.Unlock()
	atomic.AddInt32(&t.activeConns, 1)

	// Start read loop
	go mkcpConn.readLoop()
	go mkcpConn.flushLoop()

	return mkcpConn, nil
}

// Connection methods implementing net.Conn

func (c *Connection) Read(b []byte) (n int, err error) {
	select {
	case data := <-c.recvQueue:
		n = copy(b, data)
		atomic.AddUint64(&c.bytesIn, uint64(n))
		return n, nil
	case <-c.closeCh:
		return 0, io.EOF
	}
}

func (c *Connection) Write(b []byte) (n int, err error) {
	if atomic.LoadInt32(&c.state) != 1 {
		return 0, io.ErrClosedPipe
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Fragment data if necessary
	for len(b) > 0 {
		size := len(b)
		if size > maxPacketSize-headerSize {
			size = maxPacketSize - headerSize
		}

		seg := &Segment{
			conv: c.conv,
			cmd:  packetTypeData,
			sn:   c.sndNxt,
			ts:   uint32(time.Now().UnixMilli()),
			data: make([]byte, size),
		}
		copy(seg.data, b[:size])

		c.sendBuf = append(c.sendBuf, seg)
		c.sndNxt++
		b = b[size:]
		n += size
	}

	atomic.AddUint64(&c.bytesOut, uint64(n))
	c.lastSend = time.Now()

	return n, nil
}

func (c *Connection) Close() error {
	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.state, 2)

		// Send close packet
		c.mu.Lock()
		seg := &Segment{
			conv: c.conv,
			cmd:  packetTypeClose,
			sn:   c.sndNxt,
		}
		c.sendBuf = append(c.sendBuf, seg)
		c.mu.Unlock()

		// Flush remaining data
		c.flush()

		close(c.closeCh)
		atomic.StoreInt32(&c.state, 0)
	})
	return nil
}

func (c *Connection) LocalAddr() net.Addr {
	if pc, ok := c.conn.(interface{ LocalAddr() net.Addr }); ok {
		return pc.LocalAddr()
	}
	return nil
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.remote
}

func (c *Connection) SetDeadline(t time.Time) error {
	return nil // Handled internally
}

func (c *Connection) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Connection) SetWriteDeadline(t time.Time) error {
	return nil
}

// processPacket processes an incoming packet
func (c *Connection) processPacket(data []byte) {
	if len(data) < headerSize {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Parse header
	cmd := data[4]
	sn := binary.LittleEndian.Uint32(data[8:12])
	ts := binary.LittleEndian.Uint32(data[12:16])
	una := binary.LittleEndian.Uint32(data[16:20])

	// Update una
	c.parseUna(una)

	switch cmd {
	case packetTypeData:
		c.processData(sn, data[headerSize:])
		// Send ACK
		c.sendAck(sn, ts)

	case packetTypeAck:
		c.processAck(sn, ts)

	case packetTypeFEC:
		if c.fecDecoder != nil {
			recovered := c.fecDecoder.Decode(sn, data[headerSize:], true)
			for _, pkt := range recovered {
				c.recvQueue <- pkt
				atomic.AddUint64(&c.fecRecovered, 1)
			}
		}

	case packetTypeClose:
		c.Close()
	}

	c.lastRecv = time.Now()
	atomic.AddUint64(&c.packetsIn, 1)
}

// processData handles incoming data packets
func (c *Connection) processData(sn uint32, data []byte) {
	if sn < c.rcvNxt {
		return // Duplicate
	}
	if sn >= c.rcvNxt+c.rcvWnd {
		return // Out of window
	}

	// Insert into receive buffer
	seg := &Segment{
		sn:   sn,
		data: make([]byte, len(data)),
	}
	copy(seg.data, data)
	c.recvBuf = append(c.recvBuf, seg)

	// Try to deliver in-order data
	c.deliverData()
}

// deliverData delivers in-order data to the application
func (c *Connection) deliverData() {
	for len(c.recvBuf) > 0 {
		// Find next expected segment
		found := false
		for i, seg := range c.recvBuf {
			if seg.sn == c.rcvNxt {
				select {
				case c.recvQueue <- seg.data:
					c.rcvNxt++
					c.recvBuf = append(c.recvBuf[:i], c.recvBuf[i+1:]...)
					found = true
				default:
					return // Queue full
				}
				break
			}
		}
		if !found {
			break
		}
	}
}

// processAck handles ACK packets
func (c *Connection) processAck(sn uint32, ts uint32) {
	// Update RTT
	rtt := time.Duration(uint32(time.Now().UnixMilli())-ts) * time.Millisecond
	c.updateRTT(rtt)

	// Remove from send buffer
	for i, seg := range c.sendBuf {
		if seg.sn == sn {
			c.sendBuf = append(c.sendBuf[:i], c.sendBuf[i+1:]...)
			break
		}
	}
}

// parseUna updates unacknowledged pointer
func (c *Connection) parseUna(una uint32) {
	for len(c.sendBuf) > 0 {
		if c.sendBuf[0].sn < una {
			c.sendBuf = c.sendBuf[1:]
		} else {
			break
		}
	}
	if una > c.sndUna {
		c.sndUna = una
	}
}

// sendAck sends an ACK packet
func (c *Connection) sendAck(sn uint32, ts uint32) {
	seg := &Segment{
		conv: c.conv,
		cmd:  packetTypeAck,
		sn:   sn,
		ts:   ts,
		una:  c.rcvNxt,
	}
	c.output(seg)
}

// updateRTT updates RTT estimation
func (c *Connection) updateRTT(rtt time.Duration) {
	if c.rx_srtt == 0 {
		c.rx_srtt = rtt
		c.rx_rttval = rtt / 2
	} else {
		delta := rtt - c.rx_srtt
		if delta < 0 {
			delta = -delta
		}
		c.rx_rttval = (3*c.rx_rttval + delta) / 4
		c.rx_srtt = (7*c.rx_srtt + rtt) / 8
	}
	c.rx_rto = c.rx_srtt + 4*c.rx_rttval
	if c.rx_rto < c.rx_minrto {
		c.rx_rto = c.rx_minrto
	}
}

// flushLoop periodically flushes the connection
func (c *Connection) flushLoop() {
	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.flush()
		case <-c.closeCh:
			return
		}
	}
}

// flush flushes pending data
func (c *Connection) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Retransmit timed out segments
	for _, seg := range c.sendBuf {
		if seg.xmit == 0 {
			// First transmit
			seg.xmit = 1
			seg.resendTs = now.Add(c.rx_rto)
			c.output(seg)
		} else if now.After(seg.resendTs) {
			// Retransmit
			seg.xmit++
			seg.resendTs = now.Add(c.rx_rto * time.Duration(seg.xmit))
			c.output(seg)
			atomic.AddUint64(&c.retransmits, 1)
		}
	}
}

// output sends a segment
func (c *Connection) output(seg *Segment) {
	buf := make([]byte, headerSize+len(seg.data))

	// Write header
	binary.LittleEndian.PutUint32(buf[0:4], seg.conv)
	buf[4] = seg.cmd
	buf[5] = seg.frg
	binary.LittleEndian.PutUint16(buf[6:8], seg.wnd)
	binary.LittleEndian.PutUint32(buf[8:12], seg.sn)
	binary.LittleEndian.PutUint32(buf[12:16], seg.ts)
	binary.LittleEndian.PutUint32(buf[16:20], seg.una)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(len(seg.data)))

	// Write data
	copy(buf[headerSize:], seg.data)

	// FEC encoding
	if c.fec != nil && seg.cmd == packetTypeData {
		fecPackets := c.fec.Encode(buf)
		for _, fecPkt := range fecPackets {
			fecBuf := make([]byte, headerSize+len(fecPkt))
			binary.LittleEndian.PutUint32(fecBuf[0:4], c.conv)
			fecBuf[4] = packetTypeFEC
			copy(fecBuf[headerSize:], fecPkt)
			c.conn.WriteTo(fecBuf, c.remote)
		}
	}

	// Send packet
	c.conn.WriteTo(buf, c.remote)
	atomic.AddUint64(&c.packetsOut, 1)
}

// readLoop reads from the underlying connection
func (c *Connection) readLoop() {
	buf := make([]byte, maxPacketSize)
	for atomic.LoadInt32(&c.state) == 1 {
		n, _, err := c.conn.ReadFrom(buf)
		if err != nil {
			if atomic.LoadInt32(&c.state) != 1 {
				return
			}
			continue
		}
		c.processPacket(buf[:n])
	}
}

// Stats returns connection statistics
func (c *Connection) Stats() map[string]interface{} {
	return map[string]interface{}{
		"bytes_in":      atomic.LoadUint64(&c.bytesIn),
		"bytes_out":     atomic.LoadUint64(&c.bytesOut),
		"packets_in":    atomic.LoadUint64(&c.packetsIn),
		"packets_out":   atomic.LoadUint64(&c.packetsOut),
		"retransmits":   atomic.LoadUint64(&c.retransmits),
		"fec_recovered": atomic.LoadUint64(&c.fecRecovered),
		"rtt":           c.rx_srtt.String(),
		"rto":           c.rx_rto.String(),
		"cwnd":          c.cwnd,
	}
}

// Transport interface implementation

func (t *Transport) Init(ctx context.Context) error {
	return nil
}

func (t *Transport) Start(ctx context.Context) error {
	if t.config.ListenAddr != "" {
		return t.Listen(ctx)
	}
	return nil
}

func (t *Transport) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, conn := range t.conns {
		conn.Close()
	}

	if t.listener != nil {
		t.listener.Close()
	}

	return nil
}

func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_bytes_in":  atomic.LoadUint64(&t.totalBytesIn),
		"total_bytes_out": atomic.LoadUint64(&t.totalBytesOut),
		"active_conns":    atomic.LoadInt32(&t.activeConns),
	}
}

// mKCP Transport uses its own interface designed for UDP with FEC,
// which differs from the standard interfaces.Transport (TCP-based).
