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
	"strings"
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

		// Non-Blocking Dispatch to Worker Queue.
		// If a specific worker is backed up, we drop the packet for THAT shard
		// to avoid blocking the entire tunnel for everyone.
		// Non-Blocking Dispatch with Backpressure
		select {
		case workerChans[shardID] <- packetReq{pkt: pkt, tunnel: tunnel}:
			continue
		default:
			// Queue full - Retry with timeout (Backpressure)
			// This prevents dropping TCP packets during micro-bursts of CPU activity
		}

		select {
		case workerChans[shardID] <- packetReq{pkt: pkt, tunnel: tunnel}:
			// Recovered
		case <-time.After(5 * time.Millisecond):
			// Still full after backpressure - drop to prevent HoL blocking
			tunnel.Recycle(pkt)
		}
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

		// DEEP COPY Reversion: Detach payload from the underlying buffer
		// This fixes memory safety issues if the underlying buffer is reused/recycled too early,
		// and matches the original "append" behavior stability.
		payloadCopy := make([]byte, len(dp.Payload))
		copy(payloadCopy, dp.Payload)
		dp.Payload = payloadCopy

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
			// addrType = relay.AddrTypeIPv6
			// Force IPv4-only: Reject IPv6 connections to ensure fallback
			return fmt.Errorf("IPv6 not supported: %s", targetAddr)
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
		// Optimize MTU: Limit read size to prevent fragmentation/drops in tunnel
		// Optimize MTU: Limit read size to prevent fragmentation/drops in tunnel
		// Optimize MTU: Limit read size to prevent fragmentation/drops in tunnel
		// Standard MTU 1500 - overheads = ~1350 is safe.
		const safeMTU = 1350
		const headerSize = 8 // relay.HeaderSize

		for {
			// Alloc per packet for safety with Async Sends
			// This ensures no data corruption if the buffer is queued.
			buf := make([]byte, headerSize+safeMTU)

			// Read directly into the payload area
			readBuf := buf[headerSize:]
			n, err := clientConn.Read(readBuf)

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
					if pendingWindow >= 131072 { // 128KB threshold appropriate for high latency
						// Create and send WindowUpdate frame
						wf := relay.NewWindowUpdateFrame(streamID, pendingWindow)
						if data, err := wf.Encode(); err == nil {
							// Send synchronously. If this fails, we likely have bigger tunnel issues.
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
	// BIND FIX: Listen on 0.0.0.0 to allow traffic from containers/VMs/LAN
	// Force IPv4 (udp4) to prevent Windows "wsasendto" errors when writing to IPv4 from IPv6 socket
	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	if err != nil {
		return fmt.Errorf("failed to create UDP listener: %w", err)
	}
	udpListener.SetReadBuffer(8 * 1024 * 1024)
	udpListener.SetWriteBuffer(8 * 1024 * 1024)
	defer udpListener.Close()

	localAddr := udpListener.LocalAddr().(*net.UDPAddr)

	// Send success reply with relay address
	// Send success reply with relay address
	// SOCKS5 reply: VER REP RSV ATYP BND.ADDR BND.PORT
	// Fixed size for IPv4: 10 bytes (4 header + 4 IP + 2 Port)
	// We only support/detected IPv4 bind in the logic below usually.

	// Determine Bind IP
	var bindIP net.IP
	if localAddr.IP.IsUnspecified() {
		if tcpAddr, ok := tcpConn.LocalAddr().(*net.TCPAddr); ok && tcpAddr.IP.To4() != nil {
			bindIP = tcpAddr.IP.To4()
		} else {
			bindIP = net.ParseIP("127.0.0.1").To4()
		}
	} else {
		bindIP = localAddr.IP.To4()
	}

	// Construct reply buffer (10 bytes for IPv4)
	reply := make([]byte, 10)
	reply[0] = 0x05 // VER
	reply[1] = 0x00 // REP (Success)
	reply[2] = 0x00 // RSV
	reply[3] = 0x01 // ATYP (IPv4)

	copy(reply[4:8], bindIP)

	binary.BigEndian.PutUint16(reply[8:10], uint16(localAddr.Port))

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
		buf := make([]byte, 1024)
		for {
			// SOCKS5 UDP Associate check:
			// The TCP connection must be kept alive. If it closes, we close UDP.
			// Users might send Keep-Alive data, so we must drain it, not exit on first byte.
			_, err := tcpConn.Read(buf)
			if err != nil {
				// EOF or Error -> Connection closed
				udpListener.Close()
				break
			}
			// Received data (KeepAlive?) -> Ignore and continue monitoring
		}
	}()

	// Bidirectional Copy
	errChan := make(chan error, 2)

	// Track client address safely
	var clientAddr atomic.Value

	// UDP -> Tunnel
	go func() {
		// ZERO-COPY UDP ALIGNMENT MAGIC:
		// SOCKS5 UDP Packet: [RSV:2][FRAG:1][ATYP:1][ADDR:L][PORT:2][DATA...]
		// Relay UDP Frame:   [FrameHeader:8][ATYP:1][ADDR:L][PORT:2][DATA...]
		//
		// We want 'DATA' to align.
		// SOCKS Data starts at: ReadOffset + 3 (RSV+FRAG) + UDP_HDR_LEN
		// Relay Data starts at: 8 (FrameHeader) + UDP_HDR_LEN
		// Equation: ReadOffset + 3 = 8  =>  ReadOffset = 5
		//
		// If we read SOCKS packet into buf[5:], the ATYP/ADDR/PORT fields
		// align perfectly with where Relay expects them at buf[8:].
		// We just need to overwrite buf[0:8] with the FrameHeader,
		// putting the header "on top" of the unused pre-read space and SOCKS RSV/FRAG.

		const ReadOffset = 5
		const SOCKS_RSV_FRAG = 3
		const FrameHeaderSize = 8

		// Max UDP payload safe size + headroom
		buf := make([]byte, 65535+ReadOffset)

		for {
			// Read at Offset 5
			n, addr, err := udpListener.ReadFromUDP(buf[ReadOffset:])
			if err != nil {
				errChan <- err
				return
			}

			// Store/Update client address
			currentClient := clientAddr.Load()
			if currentClient == nil {
				clientAddr.Store(addr)
				if m.config.Debug {
					stdlog.Printf("[SOCKS5-UDP] Associated client: %s", addr.String())
				}
			} else {
				cAddr := currentClient.(*net.UDPAddr)
				if !cAddr.IP.Equal(addr.IP) || cAddr.Port != addr.Port {
					// Update client for NAT/roaming if IP matches
					if !cAddr.IP.Equal(addr.IP) {
						if m.config.Debug {
							stdlog.Printf("[SOCKS5-UDP] Dropping foreign packet: %s", addr)
						}
						continue
					}
					clientAddr.Store(addr)
				}
			}

			// Sanity check SOCKS header (RSV+FRAG+ATYP)
			if n < 4 {
				continue
			}

			// Bytes read start at buf[5]
			// SOCKS Header:
			// buf[5]: RSV
			// buf[6]: RSV
			// buf[7]: FRAG
			// buf[8]: ATYP (This MUST correspond to Relay ATYP)

			// Validate FRAG (Must be 0 for standard SOCKS5 UDP)
			if buf[7] != 0 {
				if m.config.Debug {
					stdlog.Printf("[SOCKS5-UDP] Dropping fragmented packet")
				}
				continue
			}

			// Calculate Total Frame Length
			// Input N = 3 (RSV/FRAG) + UDP_HDR + DATA
			// Relay N = 8 (Frame) + UDP_HDR + DATA
			// Diff = 5 bytes
			// TotalLen = N + 5
			totalLen := n + 5

			// Construct FrameHeader at buf[0:8]
			// StreamID (big-endian)
			binary.BigEndian.PutUint16(buf[0:2], streamID)
			// Type (FrameUDPData)
			buf[2] = relay.FrameUDPData
			// Flags
			buf[3] = 0
			// Length (Payload Length)
			// Payload = UDP_HDR + DATA
			// UDP_HDR starts at buf[8] (ATYP)
			// SOCKS read N bytes. PayloadLen for Relay = N - 3 (RSV/FRAG)
			payloadLen := n - 3
			binary.BigEndian.PutUint32(buf[4:8], uint32(payloadLen))

			// Buffer is now a valid Relay Frame!
			// [0-7] FrameHeader
			// [8]   ATYP
			// ...   ADDR/PORT/DATA

			// Zero-Copy Send
			if err := tunnel.Send(buf[:totalLen]); err != nil {
				// Retry / Log logic omitted for speed in this block
				// Just UDP, safe to drop or retry once
				if !tunnel.IsConnected() {
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	}()

	// Tunnel -> UDP
	go func() {
		for {
			select {
			case dp := <-stream.dataChan:
				payload := dp.Payload
				if len(payload) == 0 {
					continue
				}

				// Send payload directly
				// Remove legacy workaround for trailing zeros as header length is now trusted.

				// Helper to encapsulate and send
				sendFunc := func(data []byte) {
					pkt := make([]byte, 3+len(data))
					pkt[0] = 0x00 // RSV
					pkt[1] = 0x00 // RSV
					pkt[2] = 0x00 // FRAG
					copy(pkt[3:], data)

					// Determine client addr (use stored or remote addr)
					val := clientAddr.Load()
					if val == nil {
						return
					}
					addr := val.(net.Addr)

					_, err := udpListener.WriteToUDP(pkt, addr.(*net.UDPAddr))
					if err != nil {
						// Filter out benign errors:
						// 1. "connection refused" / "reset": Target closed port (normal)
						// 2. "wsasendto" / "message too large": PMTUD probes > MTU (normal for QUIC/Discord)
						errStr := err.Error()
						if !strings.Contains(errStr, "connection refused") &&
							!strings.Contains(errStr, "closed") &&
							!strings.Contains(errStr, "wsasendto") &&
							!strings.Contains(errStr, "message too large") {

							if m.config.Debug {
								stdlog.Printf("[SOCKS5-UDP] Write error: %v", err)
							}
						}
					}
				}

				// WORKAROUND: Restore logic for stripping trailing zeros and capping MTU.
				// Windows localhost MTU can handle large packets, but 'wsasendto' often fails
				// if the packet exceeds standard Ethernet MTU (1500) due to driver/stack limits.
				// Also, if the tunnel sends padded data, we must strip it.

				realLen := len(payload)
				for realLen > 0 && payload[realLen-1] == 0 {
					realLen--
				}

				if realLen < len(payload) {
					payload = payload[:realLen]
				}

				// Safety cap to MTU (1200 bytes for maximum compatibility)
				// Discord/Mihomo buffers might be small, and 1200 covers all Voice frames (~200b)
				// while truncating only large Jumbo/Probe packets (which is fine).
				if len(payload) > 1200 {
					payload = payload[:1200]
				}

				sendFunc(payload)

				// If we stripped significant data (zeros), sends specific variations if needed
				// (But for now, just sending the stripped/capped payload is usually sufficient for Discord/Game protocols)

				tunnel.Recycle(dp.Raw)

			case <-stream.closeChan:
				return
			}
		}
	}()

	return <-errChan
}
