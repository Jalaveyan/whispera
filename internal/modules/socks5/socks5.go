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

// TunnelManager interface for tunnel operations
type TunnelManager interface {
	// IsConnected returns true if tunnel is connected
	IsConnected() bool
	// Send sends data through the tunnel
	Send(data []byte) error
	// Receive receives data from the tunnel
	Receive(buf []byte) (int, error)
}

// ClientStream represents a client-side stream (one SOCKS5 connection)
type ClientStream struct {
	ID         uint16
	TargetAddr string
	TargetPort uint16
	Connected  bool
	Closed     bool

	// Data channels
	dataChan  chan []byte
	closeChan chan struct{}

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
		cfg.MTU = 1280 // Default safe MTU (IPv6 min) to prevent fragmentation
	}

	m := &Module{
		Module:   base.NewModule(ModuleName, ModuleVersion, nil),
		config:   cfg,
		streams:  make(map[uint16]*ClientStream),
		recvChan: make(chan *relay.Frame, 1000),
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

// receiveFrames receives frames from tunnel and dispatches to streams
func (m *Module) receiveFrames() {
	buf := make([]byte, 65536)
	var packetBuf []byte
	stdlog.Printf("[SOCKS5] receiveFrames goroutine started")

	for {
		m.mu.RLock()
		tunnel := m.tunnel
		m.mu.RUnlock()

		if tunnel == nil || !tunnel.IsConnected() {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n, err := tunnel.Receive(buf)
		if err != nil {
			if err != io.EOF {
				// Only log non-timeout errors
				if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					stdlog.Printf("[SOCKS5] Receive error: %v", err)
				}
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		if n > 0 {
			packetBuf = append(packetBuf, buf[:n]...)
		}

		// Process all complete frames in buffer
		for len(packetBuf) >= relay.HeaderSize {
			// Header: [StreamID:2][Type:1][Flags:1][Length:4]
			// We need to peek at the length field (offset 4, 4 bytes)
			payloadLen := binary.BigEndian.Uint32(packetBuf[4:8])
			frameSize := relay.HeaderSize + int(payloadLen)

			if len(packetBuf) < frameSize {
				// Wait for more data
				break
			}

			// Extract complete frame
			frameData := packetBuf[:frameSize]
			// Decode (this should succeed as we have the full frame)
			frame, err := relay.Decode(frameData)
			if err != nil {
				stdlog.Printf("[SOCKS5] Frame decode error: %v", err)
				// If decode fails on a sized chunk, the stream is likely desynchronized.
				// We drop this frame and shift (risky, but better than stuck)
				// Ideally, we should close the connection, but here we just drop.
			} else {
				m.handleIncomingFrame(frame)
			}

			// Slice buffer
			packetBuf = packetBuf[frameSize:]
		}

		// Safety cap to prevent memory leaks if stream is infinitely broken
		if len(packetBuf) > 4*1024*1024 { // 4MB
			stdlog.Printf("[SOCKS5] Buffer overflow, clearing accumulator")
			packetBuf = nil
		}
	}
}

// handleIncomingFrame processes frames received from server
func (m *Module) handleIncomingFrame(frame *relay.Frame) {
	m.streamsMu.RLock()
	stream, exists := m.streams[frame.StreamID]
	m.streamsMu.RUnlock()

	if !exists {
		if m.config.Debug || true {
			stdlog.Printf("[SOCKS5] Frame for unknown stream %d (Type=%d)", frame.StreamID, frame.Type)
		}
		return
	}

	switch frame.Type {
	case relay.FrameConnectOK:
		stdlog.Printf("[SOCKS5] Stream %d connected (ConnectOK received)", stream.ID)
		stream.mu.Lock()
		stream.Connected = true
		stream.mu.Unlock()

	case relay.FrameConnectFail:
		reason := string(frame.Payload)
		stdlog.Printf("[SOCKS5] Stream %d connect failed: %s", stream.ID, reason)
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		close(stream.closeChan)

	case relay.FrameData:
		select {
		case stream.dataChan <- frame.Payload:
		default:
			// Channel full, drop data
			if m.config.Debug {
				stdlog.Printf("[SOCKS5] Stream %d data dropped (buffer full)", stream.ID)
			}
		}

	case relay.FrameClose:
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		close(stream.closeChan)
	}
}

// nextStreamID returns next unique stream ID
func (m *Module) nextStreamID() uint16 {
	id := atomic.AddUint32(&m.streamID, 1)
	return uint16(id % 65535)
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
	streamID := m.nextStreamID()
	stream := &ClientStream{
		ID:         streamID,
		TargetAddr: targetAddr,
		TargetPort: targetPort,
		dataChan:   make(chan []byte, 100),
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

	connectFrame := relay.NewConnectFrame(streamID, relay.ProtoTCP, addrType, targetAddr, targetPort, relay.ProfilePersonal)
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
	connectTimeout := time.After(10 * time.Second)
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
	go func() {
		buf := make([]byte, m.config.MTU)
		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				errChan <- err
				return
			}

			dataFrame := relay.NewDataFrame(streamID, buf[:n])
			frameData, _ := dataFrame.Encode()

			// Kill Switch Blocking Loop for Send
			// If Send fails because tunnel is down, we wait.
			for {
				if err := tunnel.Send(frameData); err != nil {
					// Check if we should retry
					if !tunnel.IsConnected() {
						time.Sleep(500 * time.Millisecond)
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
		for {
			select {
			case data := <-stream.dataChan:
				if _, err := clientConn.Write(data); err != nil {
					errChan <- err
					return
				}
			case <-stream.closeChan:
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

// StartHevTunnel starts HevTunnel for TUN mode (no-op when using Mihomo)
func (m *Module) StartHevTunnel() error {
	stdlog.Printf("[SOCKS5] StartHevTunnel called - skipped (using Mihomo for TUN)")
	return nil
}
