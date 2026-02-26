package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/modules/relay"
	"whispera/internal/proxy"
)

func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				stdlog.Printf("[SOCKS5] PANIC in %s: %v\n%s", name, r, debug.Stack())
			}
		}()
		fn()
	}()
}

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

	streams   map[uint16]*ClientStream
	streamsMu sync.RWMutex
	streamID  uint32

	recvChan  chan *relay.Frame
	tunnelCh  chan struct{}

	running int32
}

var streamBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65536+128)
	},
}

type TunnelManager interface {
	IsConnected() bool
	Send(data []byte) error
	Receive(buf []byte) (int, error)
	ReceivePacket() ([]byte, error)
	Recycle(buf []byte)
}

type DataPacket struct {
	Raw     []byte
	Payload []byte
	PoolBuf []byte
}

type ClientStream struct {
	ID         uint16
	TargetAddr string
	TargetPort uint16
	Connected  bool
	Closed     bool

	dataChan     chan DataPacket
	closeChan    chan struct{}
	closeOnce    sync.Once
	connectedCh  chan struct{}
	connectedOnce sync.Once

	mu sync.Mutex
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

	m := &Module{
		Module:   base.NewModule(ModuleName, ModuleVersion, nil),
		config:   cfg,
		streams:  make(map[uint16]*ClientStream),
		recvChan: make(chan *relay.Frame, 32000),
		tunnelCh: make(chan struct{}, 1),
	}

	return m, nil
}

func (m *Module) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	return m.Module.Init(ctx, cfg)
}

func (m *Module) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	m.server = proxy.NewSOCKS5Server(m.config.ListenAddr, m.handleConnection)
	m.server.SetUDPHandler(m.handleUDPConnection)

	go m.receiveFrames()

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
				stdlog.Printf("[SOCKS5] Starting server on %s (relay mode)", m.config.ListenAddr)
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
			} else {
			}
		}
	}()

	m.SetHealthy(true, "SOCKS5 server running (relay mode)")
	return nil
}

func (m *Module) Stop() error {
	atomic.StoreInt32(&m.running, 0)

	m.mu.Lock()
	if m.server != nil {
	}
	if m.listener != nil {
		m.listener.Close()
	}
	m.mu.Unlock()

	m.streamsMu.Lock()
	for _, stream := range m.streams {
		stream.closeOnce.Do(func() {
			close(stream.closeChan)
		})
	}
	m.streams = make(map[uint16]*ClientStream)
	m.streamsMu.Unlock()

	return m.Module.Stop()
}

func (m *Module) SetTunnel(tunnel TunnelManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnel = tunnel
	select {
	case m.tunnelCh <- struct{}{}:
	default:
	}
	stdlog.Printf("[SOCKS5] Tunnel set for encrypted relay routing")
}

func (m *Module) receiveFrames() {
	stdlog.Printf("[SOCKS5] receiveFrames started (Sharded Worker Mode)")

	type packetReq struct {
		pkt    []byte
		tunnel TunnelManager
	}

	const numWorkers = 16
	workerChans := make([]chan packetReq, numWorkers)

	for i := 0; i < numWorkers; i++ {
		workerChans[i] = make(chan packetReq, 8192)
		go func(ch chan packetReq) {
			for req := range ch {
				pkt := req.pkt
				tunnel := req.tunnel

				streamID := binary.BigEndian.Uint16(pkt[0:2])
				fType := pkt[2]
				payloadLen := binary.BigEndian.Uint32(pkt[4:8])

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

		if tunnel == nil {
			select {
			case <-m.tunnelCh:
			case <-time.After(1 * time.Second):
			}
			continue
		}

		pkt, err := tunnel.ReceivePacket()
		if err != nil {
			continue
		}

		if len(pkt) < 8 {
			tunnel.Recycle(pkt)
			continue
		}

		streamID := binary.BigEndian.Uint16(pkt[0:2])
		payloadLen := binary.BigEndian.Uint32(pkt[4:8])

		if int(payloadLen)+8 > len(pkt) {
			tunnel.Recycle(pkt)
			continue
		}

		fType := pkt[2]

		shardID := streamID % uint16(numWorkers)

		if fType == relay.FrameUDPData {
			select {
			case workerChans[shardID] <- packetReq{pkt: pkt, tunnel: tunnel}:
			default:
				tunnel.Recycle(pkt)
			}
		} else {
			workerChans[shardID] <- packetReq{pkt: pkt, tunnel: tunnel}
		}
	}
}

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
		stream.mu.Lock()
		stream.Connected = true
		stream.mu.Unlock()
		stream.connectedOnce.Do(func() { close(stream.connectedCh) })
		tunnel.Recycle(dp.Raw)

	case relay.FrameConnectFail:
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		stream.closeOnce.Do(func() { close(stream.closeChan) })
		tunnel.Recycle(dp.Raw)

	case relay.FrameData, relay.FrameUDPData:

		poolBuf := streamBufferPool.Get().([]byte)
		payloadLen := len(dp.Payload)
		if payloadLen > len(poolBuf) {
			payloadLen = len(poolBuf)
		}
		payloadCopy := poolBuf[:payloadLen]
		copy(payloadCopy, dp.Payload[:payloadLen])
		dp.Payload = payloadCopy
		dp.PoolBuf = poolBuf

		select {
		case stream.dataChan <- dp:
		case <-stream.closeChan:
			streamBufferPool.Put(poolBuf)
			tunnel.Recycle(dp.Raw)
		}

	case relay.FrameClose:
		stream.mu.Lock()
		stream.Closed = true
		stream.mu.Unlock()
		stream.closeOnce.Do(func() { close(stream.closeChan) })
		tunnel.Recycle(dp.Raw)

	default:
		tunnel.Recycle(dp.Raw)
	}
}

func (m *Module) nextStreamID() uint16 {
	for {
		id := atomic.AddUint32(&m.streamID, 1)
		sid := uint16(id % 65535)
		if sid == 0 {
			continue
		}

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

func (m *Module) handleConnection(clientConn net.Conn, targetAddr string, targetPort uint16) error {
	defer func() {
		if r := recover(); r != nil {
			stdlog.Printf("[SOCKS5] PANIC in handleConnection: %v", r)
		}
	}()

	m.mu.RLock()
	tunnel := m.tunnel
	m.mu.RUnlock()

	timeout := time.After(5 * time.Second)
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
			break Loop
		case <-ticker.C:
			continue
		}
	}


	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(2 * 1024 * 1024)
		tcpConn.SetWriteBuffer(2 * 1024 * 1024)
		tcpConn.SetNoDelay(true)
	}

	streamID := m.nextStreamID()
	stream := &ClientStream{
		ID:          streamID,
		TargetAddr:  targetAddr,
		TargetPort:  targetPort,
		dataChan:    make(chan DataPacket, 512),
		closeChan:   make(chan struct{}),
		connectedCh: make(chan struct{}),
	}

	m.streamsMu.Lock()
	m.streams[streamID] = stream
	m.streamsMu.Unlock()

	defer func() {
		m.streamsMu.Lock()
		delete(m.streams, streamID)
		m.streamsMu.Unlock()
	}()


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

	for retries := 0; retries < 3; retries++ {
		if err := tunnel.Send(frameData); err != nil {
			if !tunnel.IsConnected() && retries < 2 {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			stdlog.Printf("[SOCKS5] Handler failed: failed to send CONNECT frame: %v", err)
			return fmt.Errorf("failed to send CONNECT frame: %w", err)
		}
		break
	}



	errChan := make(chan error, 2)

	go func() {
		const safeMTU = 16000
		const headerSize = 8

		select {
		case <-stream.connectedCh:
		case <-stream.closeChan:
			errChan <- fmt.Errorf("connection failed")
			return
		case <-time.After(5 * time.Second):
			errChan <- fmt.Errorf("connect timeout waiting for server ack")
			return
		}

		for {
			bufRaw := streamBufferPool.Get().([]byte)
			buf := bufRaw[:cap(bufRaw)]
			if len(buf) > headerSize+safeMTU {
				buf = buf[:headerSize+safeMTU]
			}

			readBuf := buf[headerSize:]
			n, err := clientConn.Read(readBuf)

			stream.mu.Lock()
			closed := stream.Closed
			stream.mu.Unlock()

			if closed {
				streamBufferPool.Put(bufRaw)
				if err != nil {
					errChan <- nil
					return
				}
				continue
			}

			if err != nil {
				streamBufferPool.Put(bufRaw)
				errChan <- err
				return
			}

			buf[0] = byte(streamID >> 8)
			buf[1] = byte(streamID)
			buf[2] = relay.FrameData
			buf[3] = 0
			payloadLen := uint32(n)
			buf[4] = byte(payloadLen >> 24)
			buf[5] = byte(payloadLen >> 16)
			buf[6] = byte(payloadLen >> 8)
			buf[7] = byte(payloadLen)

			if err := tunnel.Send(buf[:headerSize+n]); err != nil {
				if !tunnel.IsConnected() {
					streamBufferPool.Put(bufRaw)
					continue
				}
				streamBufferPool.Put(bufRaw)
				stdlog.Printf("[SOCKS5] Stream %d: send failed: %v", streamID, err)
				errChan <- err
				return
			}

			streamBufferPool.Put(bufRaw)
		}

	}()

	go func() {
		var pendingWindow uint32
		for {
			select {
			case dp := <-stream.dataChan:
				n, err := clientConn.Write(dp.Payload)

				if dp.PoolBuf != nil {
					streamBufferPool.Put(dp.PoolBuf)
				}
				tunnel.Recycle(dp.Raw)

				if err != nil {
					errChan <- err
					return
				}

				if n > 0 {
					pendingWindow += uint32(n)
					if pendingWindow >= 8192 { 
						wf := relay.NewWindowUpdateFrame(streamID, pendingWindow)
						if data, err := wf.Encode(); err == nil {
							tunnel.Send(data)
						}
						pendingWindow = 0
					}
				}
			case <-stream.closeChan:
				for {
					select {
					case dp := <-stream.dataChan:
						n, err := clientConn.Write(dp.Payload)
						if dp.PoolBuf != nil {
							streamBufferPool.Put(dp.PoolBuf)
						}
						tunnel.Recycle(dp.Raw)
						if err == nil && n > 0 {
							pendingWindow += uint32(n)
							if pendingWindow >= 8192 {
								wf := relay.NewWindowUpdateFrame(streamID, pendingWindow)
								if data, err := wf.Encode(); err == nil {
									tunnel.Send(data)
								}
								pendingWindow = 0
							}
						}
					default:
						goto drained
					}
				}
			drained:
				if tcpConn, ok := clientConn.(*net.TCPConn); ok {
					tcpConn.CloseWrite()
					tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
				}
				errChan <- io.EOF
				return
			}
		}
	}()

	err = <-errChan

	closeFrame := relay.NewCloseFrame(streamID)
	frameData, _ = closeFrame.Encode()
	tunnel.Send(frameData)

	return err
}

func (m *Module) handleUDPConnection(tcpConn net.Conn) error {
	m.mu.RLock()
	tunnel := m.tunnel
	m.mu.RUnlock()

	if tunnel == nil || !tunnel.IsConnected() {
		return fmt.Errorf("tunnel not ready")
	}

	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return fmt.Errorf("failed to create UDP listener: %w", err)
	}
	defer udpListener.Close()

	udpListener.SetReadBuffer(32 * 1024 * 1024)
	udpListener.SetWriteBuffer(32 * 1024 * 1024)

	localAddr := udpListener.LocalAddr().(*net.UDPAddr)

	reply := []byte{0x05, 0x00, 0x00, 0x01}
	reply = append(reply, localAddr.IP.To4()...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(localAddr.Port))
	reply = append(reply, portBuf...)

	if _, err := tcpConn.Write(reply); err != nil {
		return err
	}

	streamID := m.nextStreamID()
	stream := &ClientStream{
		ID:          streamID,
		TargetAddr:  "0.0.0.0",
		TargetPort:  0,
		dataChan:    make(chan DataPacket, 512),
		closeChan:   make(chan struct{}),
		connectedCh: make(chan struct{}),
	}

	m.streamsMu.Lock()
	m.streams[streamID] = stream
	m.streamsMu.Unlock()

	defer func() {
		m.streamsMu.Lock()
		delete(m.streams, streamID)
		m.streamsMu.Unlock()
		stream.closeOnce.Do(func() { close(stream.closeChan) })
	}()

	connectFrame := relay.NewConnectFrame(streamID, relay.ProtoUDP, relay.AddrTypeIPv4, "0.0.0.0", 0)
	encFrame, _ := connectFrame.Encode()
	if err := tunnel.Send(encFrame); err != nil {
		return err
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				stdlog.Printf("[SOCKS5] PANIC in TCP Monitor: %v", r)
			}
		}()
		buf := make([]byte, 1)
		_, err := tcpConn.Read(buf)
		stdlog.Printf("[SOCKS5] TCP Association Monitor exited for %v: %v (Closing UDP)", tcpConn.RemoteAddr(), err)
		udpListener.Close()
	}()

	errChan := make(chan error, 2)

	var clientAddr atomic.Value

	go func() {
		defer func() {
			if r := recover(); r != nil {
				stdlog.Printf("[SOCKS5] PANIC in UDP->Tunnel: %v", r)
			}
		}()

		for {
			bufRaw := streamBufferPool.Get().([]byte)
			buf := bufRaw[:cap(bufRaw)]

			n, addr, err := udpListener.ReadFromUDP(buf[11:])
			if err != nil {
				streamBufferPool.Put(bufRaw)
				errChan <- err
				return
			}

			clientAddr.Store(addr)

			if n < 4 {
				streamBufferPool.Put(bufRaw)
				continue
			}

			// Header (8 bytes): buf[3:11], data: buf[11:11+n]
			plLen := uint32(n)
			buf[3] = byte(streamID >> 8)
			buf[4] = byte(streamID)
			buf[5] = relay.FrameUDPData
			buf[6] = 0
			buf[7] = byte(plLen >> 24)
			buf[8] = byte(plLen >> 16)
			buf[9] = byte(plLen >> 8)
			buf[10] = byte(plLen)

			if err := tunnel.Send(buf[3 : 11+n]); err != nil {
				streamBufferPool.Put(bufRaw)
				continue
			}
			streamBufferPool.Put(bufRaw)
		}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				stdlog.Printf("[SOCKS5] PANIC in Tunnel->UDP: %v", r)
			}
		}()
		for {
			select {
			case dp := <-stream.dataChan:

				if len(dp.Raw) < 8 {
					tunnel.Recycle(dp.Raw)
					continue
				}

				dp.Raw[5] = 0
				dp.Raw[6] = 0
				dp.Raw[7] = 0

				addrVal := clientAddr.Load()
				if addrVal == nil {
					tunnel.Recycle(dp.Raw)
					continue
				}
				addr := addrVal.(*net.UDPAddr)


				_, err := udpListener.WriteToUDP(dp.Raw[5:8+len(dp.Payload)], addr)
				if err != nil {
				}

				if dp.PoolBuf != nil {
					streamBufferPool.Put(dp.PoolBuf)
				}
				tunnel.Recycle(dp.Raw)

			case <-stream.closeChan:
				return
			}
		}
	}()

	return <-errChan
}
