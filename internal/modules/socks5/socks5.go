// Package socks5 provides SOCKS5 proxy module for Whispera client
// This module receives SOCKS5 connections from Mihomo and routes them through
// the encrypted VPN tunnel using the relay protocol.
package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/modules/relay"
	"whispera/internal/proxy"
)

const (
	ModuleName    = "socks5"
	ModuleVersion = "2.0.0" // v2 - relay protocol integration
)

// Config holds SOCKS5 module configuration
type Config struct {
	ListenAddr    string
	Debug         bool
	VPNServerAddr string // VPN server address (excluded from routing)
	MTU           int    // Max packet size for data chunks
}

// Module implements SOCKS5 proxy module with relay protocol support
type Module struct {
	*base.Module
	config   *Config
	server   *proxy.SOCKS5Server
	listener net.Listener
	tunnel   TunnelManager
	mu       sync.RWMutex

	// Stream management for multiplexed connections
	streams   map[uint16]*ClientStream
	streamsMu sync.RWMutex
	streamID  uint32 // Atomic counter for stream IDs

	// Receive buffer for incoming frames from tunnel
	recvChan chan *relay.Frame
}

// streamBufferPool recycles 64KB+ buffers for individual client streams
var streamBufferPool = sync.Pool{
	New: func() interface{} {
		// 64KB (Max Payload) + 8B (Header)
		// Using 66KB to be safe and aligned
		return make([]byte, 66*1024)
	},
}

// TunnelManager interface for tunnel operations
type TunnelManager interface {
	// IsConnected returns true if tunnel is connected
	IsConnected() bool
	// Send sends data through the tunnel
	Send(data []byte) error
	// Receive receives data from the tunnel
	Receive(buf []byte) (int, error)
	// ReceivePacket returns zero-copy packet
	ReceivePacket() ([]byte, error)
	// Recycle returns packet to pool
	Recycle(buf []byte)
}

// DataPacket wrapper to pass ownership + payload range
type DataPacket struct {
	Raw     []byte // The full buffer to recycle
	Payload []byte // The payload slice to write
}

// ClientStream represents a client-side stream (one SOCKS5 connection)
type ClientStream struct {
	ID         uint16
	TargetAddr string
	TargetPort uint16
	Connected  bool
	Closed     bool

	// Data channels - strongly typed to avoid interface{} boxing allocations
	dataChan  chan DataPacket
	closeChan chan struct{}
	closeOnce sync.Once // Prevents panic on double-close

	mu sync.Mutex
}

// New creates a new SOCKS5 module
func New(cfg *Config) (*Module, error) {
	if cfg == nil {
		cfg = &Config{
			ListenAddr: "127.0.0.1:10800",
		}
	}

	// Set reasonable default MTU if missing
	if cfg.MTU <= 0 || cfg.MTU > 65535 {
		cfg.MTU = 65535 // Max MTU for throughput (64KB chunks)
	}

	m := &Module{
		Module:   base.NewModule(ModuleName, ModuleVersion, nil),
		config:   cfg,
		streams:  make(map[uint16]*ClientStream),
		recvChan: make(chan *relay.Frame, 32000),
	}

	return m, nil
}

// Init initializes the module
func (m *Module) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	return m.Module.Init(ctx, cfg)
}

// Start starts the SOCKS5 server
func (m *Module) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	// Create SOCKS5 server with connection handler
	m.server = proxy.NewSOCKS5Server(m.config.ListenAddr, m.handleConnection)
	m.server.SetUDPHandler(m.handleUDPConnection)

	// Start frame receiver goroutine
	go m.receiveFrames()

	// Start listening in a goroutine
	go func() {
		stdlog.Printf("[SOCKS5] Starting server on %s (relay mode)", m.config.ListenAddr)
		if err := m.server.ListenAndServe(); err != nil {
			stdlog.Printf("[SOCKS5] Server error: %v", err)
		}
	}()

	m.SetHealthy(true, "SOCKS5 server running (relay mode)")
	return nil
}

// Stop stops the SOCKS5 server
func (m *Module) Stop() error {
	m.mu.Lock()
	if m.listener != nil {
		m.listener.Close()
	}
	m.mu.Unlock()

	// Close all streams
	m.streamsMu.Lock()
	for _, stream := range m.streams {
		close(stream.closeChan)
	}
	m.streams = make(map[uint16]*ClientStream)
	m.streamsMu.Unlock()

	return m.Module.Stop()
}

// SetTunnel sets the tunnel manager for routing traffic
func (m *Module) SetTunnel(tunnel TunnelManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnel = tunnel
	stdlog.Printf("[SOCKS5] Tunnel set for encrypted relay routing")
}

// receiveFrames receives frames from tunnel and dispatches to streams using Sharded Workers
func (m *Module) receiveFrames() {
	stdlog.Printf("[SOCKS5] receiveFrames started (Sharded Worker Mode)")

	type packetReq struct {
		pkt    []byte
		tunnel TunnelManager
	}

	const numWorkers = 16
	workerChans := make([]chan packetReq, numWorkers)

	// Start Workers
	for i := 0; i < numWorkers; i++ {
		workerChans[i] = make(chan packetReq, 2048) // Buffer per worker to absorb micro-bursts
		go func(ch chan packetReq) {
			for req := range ch {
				pkt := req.pkt
				tunnel := req.tunnel

				// Parse Header (already checked len in dispatcher)
				streamID := binary.BigEndian.Uint16(pkt[0:2])
				fType := pkt[2]
				payloadLen := binary.BigEndian.Uint32(pkt[4:8])

				// Construct DataPacket
				dp := DataPacket{
					Raw:     pkt,
					Payload: pkt[8 : 8+int(payloadLen)],
				}

				m.handleIncomingFrame(streamID, fType, dp, tunnel)
			}
		}(workerChans[i])
	}

	for {
		m.mu.RLock()
		tunnel := m.tunnel
		m.mu.RUnlock()

		if tunnel == nil || !tunnel.IsConnected() {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Zero-Copy Read
		pkt, err := tunnel.ReceivePacket()
		if err != nil {
			if err != io.EOF {
				// Log?
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		// Parse Header (8 bytes) to get StreamID for sharding
		if len(pkt) < 8 {
			tunnel.Recycle(pkt)
			continue
		}

		streamID := binary.BigEndian.Uint16(pkt[0:2])
		payloadLen := binary.BigEndian.Uint32(pkt[4:8])

		// Safety check length
		if int(payloadLen)+8 > len(pkt) {
			tunnel.Recycle(pkt)
			continue
		}

		// Dispatch to Worker
		shardID := streamID % uint16(numWorkers)

		// BLOCKING Dispatch to Worker Queue.
		// If a specific worker is backed up, we block here.
		// This means severe congestion on one shard CAN eventually block the dispatcher.
		// However, with 16 workers and 2048 queue size, this is highly resilient.
		workerChans[shardID] <- packetReq{pkt: pkt, tunnel: tunnel}
	}
}

// handleIncomingFrame processes frames received from server (Executed by Worker)
func (m *Module) handleIncomingFrame(streamID uint16, fType byte, dp DataPacket, tunnel TunnelManager) {
	m.streamsMu.RLock()
	stream, exists := m.streams[streamID]
	m.streamsMu.RUnlock()

	if !exists {
		tunnel.Recycle(dp.Raw)
		return
	}

	switch fType {
	case relay.FrameConnectOK:
		if m.config.Debug {
			stdlog.Printf("[SOCKS5] Stream %d connected", stream.ID)
		}
		stream.mu.Lock()
		stream.Connected = true
		stream.mu.Unlock()
		tunnel.Recycle(dp.Raw)

	case relay.FrameConnectFail:
		stdlog.Printf("[SOCKS5] Stream %d connect failed", stream.ID)
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		stream.closeOnce.Do(func() { close(stream.closeChan) })
		tunnel.Recycle(dp.Raw)

	case relay.FrameData, relay.FrameUDPData:
		// Push DataPacket to channel (BLOCKING with Backpressure)
		// We are now inside a Sharded Worker. Blocking here only stalls this shard (1/16th of streams).
		select {
		case stream.dataChan <- dp:
			// Success
		case <-stream.closeChan:
			tunnel.Recycle(dp.Raw)
		}

	case relay.FrameClose:
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		close(stream.closeChan)
		tunnel.Recycle(dp.Raw)

	default:
		tunnel.Recycle(dp.Raw)
	}
}

// nextStreamID returns next unique stream ID
func (m *Module) nextStreamID() uint16 {
	for {
		id := atomic.AddUint32(&m.streamID, 1)
		sid := uint16(id % 65535)
		if sid == 0 {
			continue
		}

		// Critical Fix: Skip StreamIDs that mimic TLS headers.
		// The tunnel reader peeks 5 bytes to detect TLS (masquerade/handshake).
		// Frame Header: [StreamID:2][Type:1]...
		// If StreamID in BigEndian is [0x14..0x17][0x00..0x04], the reader
		// misinterprets it as a TLS record and discards it.
		// Range: HighByte 20-23 (0x14-0x17), LowByte 0-3 (0x00-0x03) (Checks <= 0x04)
		hb := sid >> 8
		lb := sid & 0xFF
		if hb >= 0x14 && hb <= 0x17 && lb <= 0x04 {
			if m.config.Debug {
				stdlog.Printf("[SOCKS5] Skipping unsafe StreamID: %d (0x%04x) to avoid TLS collision", sid, sid)
			}
			continue
		}

		return sid
	}
}

// handleConnection handles a SOCKS5 connection request through relay protocol
func (m *Module) handleConnection(clientConn net.Conn, targetAddr string, targetPort uint16) error {
	m.mu.RLock()
	tunnel := m.tunnel
	m.mu.RUnlock()

	// Wait for tunnel to become ready (Kill Switch)
	// Strategy: We wait a bit. If tunnel comes up, great.
	// If it doesn't, we DO NOT fail the connection (returning error causes browsers/Mihomo to fallback to DIRECT -> LEAK).
	// Instead, we proceed, but the data transfer loop will block until tunnel is ready.
	timeout := time.After(5 * time.Second) // Short wait for fast start
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

Loop:
	for {
		m.mu.RLock()
		tunnel = m.tunnel
		m.mu.RUnlock()

		if tunnel != nil && tunnel.IsConnected() {
			break Loop
		}

		select {
		case <-timeout:
			stdlog.Printf("[SOCKS5] Tunnel (still) not ready after 5s. Proceeding in Blocking Mode (Kill Switch active)")
			break Loop // Break, don't return error
		case <-ticker.C:
			continue
		}
	}

	// Note: We deliberately do NOT return error here if tunnel is down.
	// We let the logic proceed to 'handleConnection' body which sets up the stream.
	// The actual data transfer loop (goroutine) will check tunnel status before sending.

	// Create stream
	// CRITICAL: Optimize Local TCP Connection (Browser <-> Client)
	// The default buffer is too small for 500Mbps, causing the internal buffer to fill up.
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(512 * 1024)  // 512KB
		tcpConn.SetWriteBuffer(512 * 1024) // 512KB
		tcpConn.SetNoDelay(true)
	}

	streamID := m.nextStreamID()
	stream := &ClientStream{
		ID:         streamID,
		TargetAddr: targetAddr,
		TargetPort: targetPort,
		dataChan:   make(chan DataPacket, 4096), // Tuned: 4096 * 64KB = ~256MB. Balanced for High BDP links.
		closeChan:  make(chan struct{}),
	}

	m.streamsMu.Lock()
	m.streams[streamID] = stream
	m.streamsMu.Unlock()

	defer func() {
		m.streamsMu.Lock()
		delete(m.streams, streamID)
		m.streamsMu.Unlock()
	}()

	if m.config.Debug {
		stdlog.Printf("[SOCKS5] Stream %d: connecting to %s:%d via tunnel",
			streamID, targetAddr, targetPort)
	}

	// Send CONNECT frame
	addrType := relay.AddrTypeDomain
	if ip := net.ParseIP(targetAddr); ip != nil {
		if ip.To4() != nil {
			addrType = relay.AddrTypeIPv4
		} else {
			addrType = relay.AddrTypeIPv6
		}
	}

	connectFrame := relay.NewConnectFrame(streamID, relay.ProtoTCP, addrType, targetAddr, targetPort)
	frameData, err := connectFrame.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode CONNECT frame: %v", err)
	}

	// Kill Switch Blocking Loop for Initial Connect
	// We must block here too, otherwise the connection drops before data transfer starts.
	for {
		if err := tunnel.Send(frameData); err != nil {
			// Check if we should retry
			if !tunnel.IsConnected() {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			stdlog.Printf("[SOCKS5] Handler failed: failed to send CONNECT frame: %v", err)
			return fmt.Errorf("failed to send CONNECT frame: %w", err)
		}
		break
	}

	// Wait for CONNECT_OK or timeout
	connectTimeout := time.After(15 * time.Second)
	for {
		stream.mu.Lock()
		connected := stream.Connected
		closed := stream.Closed
		stream.mu.Unlock()

		if connected {
			break
		}
		if closed {
			return fmt.Errorf("connection refused by server")
		}

		select {
		case <-connectTimeout:
			stdlog.Printf("[SOCKS5] Stream %d: connection timeout waiting for ConnectOK", streamID)
			return fmt.Errorf("connection timeout")
		case <-stream.closeChan:
			return fmt.Errorf("stream closed")
		case <-time.After(10 * time.Millisecond):
			// Check again
		}
	}

	if m.config.Debug {
		stdlog.Printf("[SOCKS5] Stream %d: established to %s:%d", streamID, targetAddr, targetPort)
	}

	// Bidirectional data transfer
	errChan := make(chan error, 2)

	// Client -> Server (via tunnel)
	// Client -> Server (via tunnel)
	go func() {
		// ZERO-COPY OPTIMIZATION with sync.Pool
		// Use pooled buffer to avoid GC on every new connection
		const headerSize = 8 // relay.HeaderSize
		buf := streamBufferPool.Get().([]byte)
		defer streamBufferPool.Put(buf)

		for {
			// Read directly into the payload area, skipping header space
			n, err := clientConn.Read(buf[headerSize:])

			// Check if stream was closed remotely (Graceful Drain Mode)
			stream.mu.Lock()
			closed := stream.Closed
			stream.mu.Unlock()

			if closed {
				// We are in draining mode (CloseWrite already sent FIN)
				// If we receive data, we discard it to prevent RST
				// If we receive Error (EOF/Timeout), we exit cleanly
				if err != nil {
					// Treat any error during drain as clean exit
					errChan <- nil
					return
				}
				// Discard data and continue draining
				continue
			}

			if err != nil {
				errChan <- err
				return
			}

			// Manually construct Frame Header in-place
			// Format: [StreamID:2][Type:1][Flags:1][Length:4]
			// StreamID
			buf[0] = byte(streamID >> 8)
			buf[1] = byte(streamID & 0xff)
			// Type (FrameData = 0x04)
			buf[2] = 0x04
			// Flags (0)
			buf[3] = 0x00
			// Length
			buf[4] = byte(n >> 24)
			buf[5] = byte(n >> 16)
			buf[6] = byte(n >> 8)
			buf[7] = byte(n & 0xff)

			// Slice the buffer to include header + data
			frameData := buf[:headerSize+n]

			// Kill Switch Blocking Loop for Send
			// If Send fails because tunnel is down, we wait.
			retryCount := 0
			for {
				if err := tunnel.Send(frameData); err != nil {
					// Check if we should retry
					if !tunnel.IsConnected() {
						time.Sleep(500 * time.Millisecond)
						continue
					}
					// Transient error? Retry a few times
					if retryCount < 3 {
						retryCount++
						time.Sleep(10 * time.Millisecond)
						continue
					}
					errChan <- err
					return
				}
				break
			}
		}
	}()

	// Server -> Client (from tunnel via stream.dataChan)
	go func() {
		var pendingWindow uint32
		for {
			select {
			case dp := <-stream.dataChan:
				n, err := clientConn.Write(dp.Payload)
				if err != nil {
					tunnel.Recycle(dp.Raw) // Recycle on error
					errChan <- err
					return
				}
				tunnel.Recycle(dp.Raw) // Recycle after write

				// Flow Control: Send WINDOW_UPDATE
				if n > 0 {
					pendingWindow += uint32(n)
					if pendingWindow >= 65536 { // 64KB threshold
						// Create and send WindowUpdate frame
						// We use a simple allocation here as it happens relatively infrequently (once per 64KB)
						wf := relay.NewWindowUpdateFrame(streamID, pendingWindow)
						if data, err := wf.Encode(); err == nil {
							tunnel.Send(data)
						}
						pendingWindow = 0
					}
				}
			case <-stream.closeChan:
				// GRACEFUL SHUTDOWN: Try CloseWrite first to send FIN instead of RST
				if tcpConn, ok := clientConn.(*net.TCPConn); ok {
					tcpConn.CloseWrite()
					// Set a deadline to force the client to close its side eventually
					// This triggers an error in the Read loop if the client doesn't close.
					tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
					// We return from this goroutine but DO NOT signal errChan yet.
					// We wait for the Read loop to hit EOF or Timeout.
					return
				}
				// For non-TCP (UDP relay link), we can't half-close.
				errChan <- io.EOF
				return
			}
		}
	}()

	// Wait for one direction to finish
	err = <-errChan

	// Send CLOSE frame
	closeFrame := relay.NewCloseFrame(streamID)
	frameData, _ = closeFrame.Encode()
	tunnel.Send(frameData)

	return err
}

// handleUDPConnection handles a UDP ASSOCIATE connection
func (m *Module) handleUDPConnection(tcpConn net.Conn) error {
	m.mu.RLock()
	tunnel := m.tunnel
	m.mu.RUnlock()

	// Wait for tunnel (Kill Switch)
	if tunnel == nil || !tunnel.IsConnected() {
		return fmt.Errorf("tunnel not ready")
	}

	// Create UDP listener for relay
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return fmt.Errorf("failed to create UDP listener: %w", err)
	}
	defer udpListener.Close()

	localAddr := udpListener.LocalAddr().(*net.UDPAddr)

	// Send success reply with relay address
	// SOCKS5 reply: VER REP RSV ATYP BND.ADDR BND.PORT
	reply := []byte{0x05, 0x00, 0x00, 0x01}
	reply = append(reply, localAddr.IP.To4()...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(localAddr.Port))
	reply = append(reply, portBuf...)

	if _, err := tcpConn.Write(reply); err != nil {
		return err
	}

	// Create Tunnel Stream for UDP
	streamID := m.nextStreamID()
	stream := &ClientStream{
		ID:         streamID,
		TargetAddr: "0.0.0.0",
		TargetPort: 0,
		dataChan:   make(chan DataPacket, 10000), // Optimized: 10000 packets for UDP
		closeChan:  make(chan struct{}),
	}

	m.streamsMu.Lock()
	m.streams[streamID] = stream
	m.streamsMu.Unlock()

	defer func() {
		m.streamsMu.Lock()
		delete(m.streams, streamID)
		m.streamsMu.Unlock()
		close(stream.closeChan)
	}()

	// Send CONNECT frame (UDP Mode)
	// Addr 0.0.0.0 signals Relay Mode on server
	connectFrame := relay.NewConnectFrame(streamID, relay.ProtoUDP, relay.AddrTypeIPv4, "0.0.0.0", 0)
	encFrame, _ := connectFrame.Encode()
	if err := tunnel.Send(encFrame); err != nil {
		return err
	}

	// Monitor TCP connection closing (signals end of association)
	go func() {
		buf := make([]byte, 1)
		tcpConn.Read(buf)
		udpListener.Close() // Force close listener to break loop
	}()

	// Bidirectional Copy
	errChan := make(chan error, 2)

	// Track client address safely
	var clientAddr atomic.Value

	// UDP -> Tunnel
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpListener.ReadFromUDP(buf)
			if err != nil {
				errChan <- err
				return
			}

			// Store/Update client address
			clientAddr.Store(addr)

			// SOCKS5 UDP Header: RSV(2) FRAG(1) ATYP(1) ...
			if n < 3 {
				continue
			}

			udpPayload := buf[3:n]

			// Parse SOCKS5 header from udpPayload
			if len(udpPayload) < 4 {
				continue
			}
			atyp := udpPayload[0]
			var dstAddr string
			var dstPort uint16
			var dataOffset int

			switch atyp {
			case 0x01: // IPv4
				if len(udpPayload) < 1+4+2 {
					continue
				}
				dstAddr = net.IP(udpPayload[1:5]).String()
				dstPort = binary.BigEndian.Uint16(udpPayload[5:7])
				dataOffset = 7
			case 0x03: // Domain
				if len(udpPayload) < 2 {
					continue
				}
				dlen := int(udpPayload[1])
				if len(udpPayload) < 2+dlen+2 {
					continue
				}
				dstAddr = string(udpPayload[2 : 2+dlen])
				dstPort = binary.BigEndian.Uint16(udpPayload[2+dlen : 2+dlen+2])
				dataOffset = 2 + dlen + 2
			case 0x04: // IPv6
				if len(udpPayload) < 1+16+2 {
					continue
				}
				dstAddr = net.IP(udpPayload[1:17]).String()
				dstPort = binary.BigEndian.Uint16(udpPayload[17:19])
				dataOffset = 19
			default:
				continue
			}

			data := udpPayload[dataOffset:]
			frame := relay.NewUDPDataFrame(streamID, atyp, dstAddr, dstPort, data)

			// Send to tunnel
			enc, _ := frame.Encode()
			if err := tunnel.Send(enc); err != nil {
				time.Sleep(10 * time.Millisecond)
				tunnel.Send(enc)
			}
		}
	}()

	// Tunnel -> UDP
	go func() {
		for {
			select {
			case dp := <-stream.dataChan:
				payload := dp.Payload

				// Payload is [ATYP][ADDR][PORT][DATA]

				// Get Client Address
				addrVal := clientAddr.Load()
				if addrVal == nil {
					// Drop if we don't know where to send yet
					tunnel.Recycle(dp.Raw)
					continue
				}
				addr := addrVal.(*net.UDPAddr)

				// Construct SOCKS5 Packet: [00 00 00] + payload
				pkt := make([]byte, 3+len(payload))
				pkt[0], pkt[1], pkt[2] = 0, 0, 0 // RSV, FRAG
				copy(pkt[3:], payload)

				_, err := udpListener.WriteToUDP(pkt, addr)
				if err != nil {
					// log or ignore
				}
				tunnel.Recycle(dp.Raw)

			case <-stream.closeChan:
				return
			}
		}
	}()

	return <-errChan
}
