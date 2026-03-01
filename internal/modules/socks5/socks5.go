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
	"whispera/internal/proxy"
)

const (
	ModuleName    = "socks5"
	ModuleVersion = "2.0.0"
)

type Config struct {
	ListenAddr    string
	Debug         bool
	VPNServerAddr string
	MTU           int
}

type Module struct {
	*base.Module
	config   *Config
	server   *proxy.SOCKS5Server
	listener net.Listener
	tunnel   TunnelManager
	mu       sync.RWMutex
	running  int32
}

type TunnelManager interface {
	IsConnected() bool
	OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error)
	DialStream(ctx context.Context, network, addr string) (net.Conn, error)
}

func New(cfg *Config) (*Module, error) {
	if cfg == nil {
		cfg = &Config{
			ListenAddr: "127.0.0.1:10800",
		}
	}
	if cfg.MTU <= 0 || cfg.MTU > 65535 {
		cfg.MTU = 65535
	}
	return &Module{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
	}, nil
}

func (m *Module) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	return m.Module.Init(ctx, cfg)
}

func (m *Module) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	m.server = proxy.NewSOCKS5Server(m.config.ListenAddr, m.handleConnection)
	m.server.SetUDPRelayHandler(m.handleUDPRelay)

	atomic.StoreInt32(&m.running, 1)

	go func() {
		backoff := 100 * time.Millisecond
		for {
			if atomic.LoadInt32(&m.running) == 0 {
				return
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						stdlog.Printf("[SOCKS5] CRITICAL PANIC in Listener: %v", r)
					}
				}()
				stdlog.Printf("[SOCKS5] Starting server on %s", m.config.ListenAddr)
				if err := m.server.ListenAndServe(); err != nil {
					if atomic.LoadInt32(&m.running) == 1 {
						stdlog.Printf("[SOCKS5] Server error: %v. Restarting in %v...", err, backoff)
					}
				}
			}()
			time.Sleep(backoff)
			if backoff < 3*time.Second {
				backoff *= 2
				if backoff > 3*time.Second {
					backoff = 3 * time.Second
				}
			}
		}
	}()

	m.SetHealthy(true, "SOCKS5 server running")
	return nil
}

func (m *Module) Stop() error {
	atomic.StoreInt32(&m.running, 0)
	m.mu.Lock()
	if m.listener != nil {
		m.listener.Close()
	}
	m.mu.Unlock()
	return m.Module.Stop()
}

func (m *Module) SetTunnel(tunnel TunnelManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnel = tunnel
	stdlog.Printf("[SOCKS5] Tunnel set")
}

// ── TCP handler ───────────────────────────────────────────────────────────────

func (m *Module) handleConnection(clientConn net.Conn, targetAddr string, targetPort uint16) error {
	defer func() {
		if r := recover(); r != nil {
			stdlog.Printf("[SOCKS5] PANIC in handleConnection: %v", r)
		}
	}()

	m.mu.RLock()
	tunnel := m.tunnel
	m.mu.RUnlock()

	deadline := time.Now().Add(5 * time.Second)
	for tunnel == nil || !tunnel.IsConnected() {
		if time.Now().After(deadline) {
			return fmt.Errorf("tunnel not ready")
		}
		time.Sleep(100 * time.Millisecond)
		m.mu.RLock()
		tunnel = m.tunnel
		m.mu.RUnlock()
	}

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(2 * 1024 * 1024)
		tcpConn.SetWriteBuffer(2 * 1024 * 1024)
		tcpConn.SetNoDelay(true)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := tunnel.OpenStream(ctx, 0x06, targetAddr, targetPort)
	if err != nil {
		return fmt.Errorf("relay connect: %w", err)
	}
	defer stream.Close()

	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 256*1024)
		_, err := io.CopyBuffer(stream, clientConn, buf)
		errCh <- err
	}()
	go func() {
		buf := make([]byte, 256*1024)
		_, err := io.CopyBuffer(clientConn, stream, buf)
		errCh <- err
	}()
	<-errCh
	return nil
}

// ── UDP relay handler ─────────────────────────────────────────────────────────

// handleUDPRelay handles a full SOCKS5 UDP ASSOCIATE session.
// udpConn is the UDP socket mihomo sends datagrams to.
// tcpConn is the control connection; closing it ends the relay.
func (m *Module) handleUDPRelay(udpConn *net.UDPConn, tcpConn net.Conn) {
	defer udpConn.Close()

	// Per-destination tunnel streams: "host:port" → net.Conn
	streams := make(map[string]net.Conn)
	var streamsMu sync.Mutex

	defer func() {
		streamsMu.Lock()
		for _, s := range streams {
			s.Close()
		}
		streamsMu.Unlock()
	}()

	// When the TCP control connection closes, stop the UDP relay.
	go func() {
		buf := make([]byte, 1)
		tcpConn.Read(buf)
		udpConn.Close()
	}()

	buf := make([]byte, 65535)
	var clientAddr *net.UDPAddr

	for {
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if clientAddr == nil {
			clientAddr = addr
		}

		if n < 4 || buf[2] != 0 { // ignore fragmented packets (FRAG != 0)
			continue
		}

		dstHost, dstPort, payload, err := parseUDPHeader(buf[:n])
		if err != nil {
			stdlog.Printf("[SOCKS5-UDP] bad header: %v", err)
			continue
		}

		dstKey := fmt.Sprintf("%s:%d", dstHost, dstPort)

		// Get or create tunnel stream for this destination.
		streamsMu.Lock()
		stream, exists := streams[dstKey]
		if !exists {
			m.mu.RLock()
			tunnel := m.tunnel
			m.mu.RUnlock()

			if tunnel == nil || !tunnel.IsConnected() {
				streamsMu.Unlock()
				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			stream, err = tunnel.OpenStream(ctx, 0x11, dstHost, dstPort)
			cancel()
			if err != nil {
				streamsMu.Unlock()
				stdlog.Printf("[SOCKS5-UDP] DialStream %s: %v", dstKey, err)
				continue
			}
			streams[dstKey] = stream

			// Goroutine: read responses from tunnel → send back to client.
			go func(stream net.Conn, dstKey, dstHost string, dstPort uint16) {
				defer func() {
					streamsMu.Lock()
					delete(streams, dstKey)
					streamsMu.Unlock()
					stream.Close()
				}()

				// Read length-framed UDP datagrams from the tunnel stream.
				// Each datagram is prefixed with a 2-byte big-endian length.
				hdr := make([]byte, 2)
				respBuf := make([]byte, 65535)
				for {
					if _, err := io.ReadFull(stream, hdr); err != nil {
						return
					}
					sz := int(binary.BigEndian.Uint16(hdr))
					if sz == 0 || sz > len(respBuf) {
						return
					}
					if _, err := io.ReadFull(stream, respBuf[:sz]); err != nil {
						return
					}
					if clientAddr != nil {
						reply := buildUDPReply(dstHost, dstPort, respBuf[:sz])
						udpConn.WriteToUDP(reply, clientAddr)
					}
				}
			}(stream, dstKey, dstHost, dstPort)
		}
		streamsMu.Unlock()

		// Forward payload to tunnel with 2-byte length prefix to preserve
		// UDP datagram boundaries over the TCP-based yamux stream.
		frame := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
		copy(frame[2:], payload)
		if _, err := stream.Write(frame); err != nil {
			streamsMu.Lock()
			delete(streams, dstKey)
			streamsMu.Unlock()
			stream.Close()
		}
	}
}

// ── SOCKS5 UDP header helpers ─────────────────────────────────────────────────

// parseUDPHeader parses the SOCKS5 UDP request header:
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | variable |    2     | variable |
func parseUDPHeader(data []byte) (host string, port uint16, payload []byte, err error) {
	if len(data) < 4 {
		return "", 0, nil, fmt.Errorf("packet too short (%d bytes)", len(data))
	}
	atyp := data[3]
	var offset int
	switch atyp {
	case 0x01: // IPv4
		if len(data) < 10 {
			return "", 0, nil, fmt.Errorf("IPv4 packet too short")
		}
		host = net.IP(data[4:8]).String()
		port = binary.BigEndian.Uint16(data[8:10])
		offset = 10
	case 0x04: // IPv6
		if len(data) < 22 {
			return "", 0, nil, fmt.Errorf("IPv6 packet too short")
		}
		host = net.IP(data[4:20]).String()
		port = binary.BigEndian.Uint16(data[20:22])
		offset = 22
	case 0x03: // Domain
		if len(data) < 5 {
			return "", 0, nil, fmt.Errorf("domain packet too short")
		}
		dl := int(data[4])
		if len(data) < 5+dl+2 {
			return "", 0, nil, fmt.Errorf("domain packet too short")
		}
		host = string(data[5 : 5+dl])
		port = binary.BigEndian.Uint16(data[5+dl : 5+dl+2])
		offset = 5 + dl + 2
	default:
		return "", 0, nil, fmt.Errorf("unsupported ATYP 0x%02x", atyp)
	}
	return host, port, data[offset:], nil
}

// parseUDPDataHeader parses the SealUDPData header prepended by the relay server
// to UDP responses. Format: [addrType(1), IP(4|16), port(2), payload...]
func parseUDPDataHeader(data []byte) (host string, port uint16, payload []byte, err error) {
	if len(data) < 4 {
		return "", 0, nil, fmt.Errorf("udp data header too short")
	}
	atyp := data[0]
	switch atyp {
	case 0x01: // IPv4
		if len(data) < 7 {
			return "", 0, nil, fmt.Errorf("udp IPv4 header too short")
		}
		host = net.IP(data[1:5]).String()
		port = binary.BigEndian.Uint16(data[5:7])
		payload = data[7:]
	case 0x04: // IPv6
		if len(data) < 19 {
			return "", 0, nil, fmt.Errorf("udp IPv6 header too short")
		}
		host = net.IP(data[1:17]).String()
		port = binary.BigEndian.Uint16(data[17:19])
		payload = data[19:]
	case 0x03: // Domain
		if len(data) < 2 {
			return "", 0, nil, fmt.Errorf("udp domain header too short")
		}
		dl := int(data[1])
		if len(data) < 2+dl+2 {
			return "", 0, nil, fmt.Errorf("udp domain header truncated")
		}
		host = string(data[2 : 2+dl])
		port = binary.BigEndian.Uint16(data[2+dl : 2+dl+2])
		payload = data[2+dl+2:]
	default:
		return "", 0, nil, fmt.Errorf("unknown addrtype 0x%02x", atyp)
	}
	return host, port, payload, nil
}

// buildUDPReply wraps payload in a SOCKS5 UDP reply header addressed from
// (host, port) so mihomo can route it back to the game.
func buildUDPReply(host string, port uint16, payload []byte) []byte {
	var hdr []byte
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		hdr = make([]byte, 10)
		hdr[3] = 0x01
		copy(hdr[4:8], ip4)
		binary.BigEndian.PutUint16(hdr[8:10], port)
	} else if ip6 := ip.To16(); ip6 != nil {
		hdr = make([]byte, 22)
		hdr[3] = 0x04
		copy(hdr[4:20], ip6)
		binary.BigEndian.PutUint16(hdr[20:22], port)
	} else {
		// Domain
		hdr = make([]byte, 5+len(host)+2)
		hdr[3] = 0x03
		hdr[4] = byte(len(host))
		copy(hdr[5:], host)
		binary.BigEndian.PutUint16(hdr[5+len(host):], port)
	}
	return append(hdr, payload...)
}
