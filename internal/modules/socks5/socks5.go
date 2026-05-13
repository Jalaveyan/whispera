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

var copyBufPool = sync.Pool{
	New: func() interface{} { b := make([]byte, 32*1024); return &b },
}

type Config struct {
	ListenAddr    string
	Debug         bool
	VPNServerAddr string
	MTU           int

	// BypassFunc — return true to dial the target directly (bypass VPN tunnel).
	// Called with the target hostname/IP and port before tunnel routing.
	BypassFunc func(addr string, port uint16) bool

	// BlockFunc — return true to silently drop the connection.
	BlockFunc func(addr string, port uint16) bool

	// BlockTorrents — drop connections to well-known BitTorrent ports (6881-6889, 6969, 51413).
	BlockTorrents bool
}

type Module struct {
	*base.Module
	config   *Config
	server   *proxy.SOCKS5Server
	listener net.Listener
	tunnel   TunnelManager
	mu       sync.RWMutex
	running  int32
	authUser string
	authPass string
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
	if m.authUser != "" {
		m.server.SetAuthHandler(func(u, p string) bool {
			return u == m.authUser && p == m.authPass
		})
	}
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

func (m *Module) SetAuthHandler(username, password string) {
	m.authUser = username
	m.authPass = password
}

func (m *Module) SetTunnel(tunnel TunnelManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnel = tunnel
	stdlog.Printf("[SOCKS5] Tunnel set")
}


// isTorrentPort returns true for well-known BitTorrent TCP ports.
func isTorrentPort(port uint16) bool {
	switch port {
	case 6969, 51413: // common tracker / client ports
		return true
	}
	return port >= 6881 && port <= 6889
}

func (m *Module) handleConnection(clientConn net.Conn, targetAddr string, targetPort uint16) error {
	defer func() {
		if r := recover(); r != nil {
			stdlog.Printf("[SOCKS5] PANIC in handleConnection: %v", r)
		}
	}()

	// Block before anything else.
	if m.config.BlockTorrents && isTorrentPort(targetPort) {
		stdlog.Printf("[SOCKS5] blocked torrent port %d → %s", targetPort, targetAddr)
		return nil
	}
	if m.config.BlockFunc != nil && m.config.BlockFunc(targetAddr, targetPort) {
		stdlog.Printf("[SOCKS5] blocked by rule: %s:%d", targetAddr, targetPort)
		return nil
	}

	// Bypass: route directly without VPN tunnel.
	if m.config.BypassFunc != nil && m.config.BypassFunc(targetAddr, targetPort) {
		stdlog.Printf("[SOCKS5] direct (bypass) → %s:%d", targetAddr, targetPort)
		return m.directDial(clientConn, targetAddr, targetPort)
	}

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
		tcpConn.SetReadBuffer(4 * 1024 * 1024)
		tcpConn.SetWriteBuffer(4 * 1024 * 1024)
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
		bp := copyBufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(stream, clientConn, *bp)
		copyBufPool.Put(bp)
		errCh <- err
	}()
	go func() {
		bp := copyBufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(clientConn, stream, *bp)
		copyBufPool.Put(bp)
		errCh <- err
	}()
	<-errCh
	return nil
}

// directDial connects to addr:port without the VPN tunnel (used for bypass).
func (m *Module) directDial(clientConn net.Conn, host string, port uint16) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	upstream, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("direct dial %s: %w", addr, err)
	}
	defer upstream.Close()
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 32*1024)
		_, err := io.CopyBuffer(upstream, clientConn, buf)
		errCh <- err
	}()
	go func() {
		buf := make([]byte, 32*1024)
		_, err := io.CopyBuffer(clientConn, upstream, buf)
		errCh <- err
	}()
	<-errCh
	return nil
}


func (m *Module) handleUDPRelay(udpConn *net.UDPConn, tcpConn net.Conn) {
	defer udpConn.Close()

	streams := make(map[string]net.Conn)
	var streamsMu sync.Mutex

	defer func() {
		streamsMu.Lock()
		for _, s := range streams {
			s.Close()
		}
		streamsMu.Unlock()
	}()

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

		if n < 4 || buf[2] != 0 {
			continue
		}

		dstHost, dstPort, payload, err := parseUDPHeader(buf[:n])
		if err != nil {
			stdlog.Printf("[SOCKS5-UDP] bad header: %v", err)
			continue
		}

		dstKey := fmt.Sprintf("%s:%d", dstHost, dstPort)

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

			go func(stream net.Conn, dstKey, dstHost string, dstPort uint16) {
				defer func() {
					streamsMu.Lock()
					delete(streams, dstKey)
					streamsMu.Unlock()
					stream.Close()
				}()

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


func parseUDPHeader(data []byte) (host string, port uint16, payload []byte, err error) {
	if len(data) < 4 {
		return "", 0, nil, fmt.Errorf("packet too short (%d bytes)", len(data))
	}
	atyp := data[3]
	var offset int
	switch atyp {
	case 0x01:
		if len(data) < 10 {
			return "", 0, nil, fmt.Errorf("IPv4 packet too short")
		}
		host = net.IP(data[4:8]).String()
		port = binary.BigEndian.Uint16(data[8:10])
		offset = 10
	case 0x04:
		if len(data) < 22 {
			return "", 0, nil, fmt.Errorf("IPv6 packet too short")
		}
		host = net.IP(data[4:20]).String()
		port = binary.BigEndian.Uint16(data[20:22])
		offset = 22
	case 0x03:
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
		hdr = make([]byte, 5+len(host)+2)
		hdr[3] = 0x03
		hdr[4] = byte(len(host))
		copy(hdr[5:], host)
		binary.BigEndian.PutUint16(hdr[5+len(host):], port)
	}
	return append(hdr, payload...)
}
