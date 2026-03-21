package relay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
)

var p2pLog = logger.Module("p2p-relay")

const (
	p2pMagic       = 0xDE
	cmdRegister    = 0x01
	cmdConnect     = 0x02
	cmdData        = 0x03
	cmdPing        = 0x04
	cmdPong        = 0x05
	cmdDisconnect  = 0x06

	peerIDLen   = 16
	authTagLen  = 32
	headerLen   = 1 + 1 + peerIDLen + 2
)

type P2PRelayConfig struct {
	ListenAddr   string
	Secret       []byte
	MaxPeers     int
	PeerTimeout  time.Duration
	MaxBandwidth int64
}

func DefaultP2PRelayConfig() *P2PRelayConfig {
	return &P2PRelayConfig{
		MaxPeers:     256,
		PeerTimeout:  5 * time.Minute,
		MaxBandwidth: 100 * 1024 * 1024,
	}
}

type peer struct {
	id           [peerIDLen]byte
	conn         net.Conn
	lastActivity time.Time
	partner      *peer
	mu           sync.Mutex
	bytesUp      uint64
	bytesDown    uint64
}

type P2PRelay struct {
	mu       sync.RWMutex
	config   *P2PRelayConfig
	listener net.Listener
	peers    map[[peerIDLen]byte]*peer
	waiting  map[[peerIDLen]byte]*peer

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	totalPeers   uint64
	totalRelayed uint64
	activePairs  int32
}

func NewP2PRelay(cfg *P2PRelayConfig) *P2PRelay {
	if cfg == nil {
		cfg = DefaultP2PRelayConfig()
	}
	return &P2PRelay{
		config:  cfg,
		peers:   make(map[[peerIDLen]byte]*peer),
		waiting: make(map[[peerIDLen]byte]*peer),
		stopCh:  make(chan struct{}),
	}
}

func (r *P2PRelay) Start() error {
	if r.config.ListenAddr == "" {
		return nil
	}

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", r.config.ListenAddr)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.listener = listener
	r.mu.Unlock()

	r.wg.Add(2)
	go r.acceptLoop()
	go r.cleanupLoop()

	p2pLog.Info("P2P relay started on %s", r.config.ListenAddr)
	return nil
}

func (r *P2PRelay) Stop() {
	r.stopOnce.Do(func() { close(r.stopCh) })
	r.mu.Lock()
	if r.listener != nil {
		r.listener.Close()
		r.listener = nil
	}
	for _, p := range r.peers {
		p.conn.Close()
	}
	r.peers = make(map[[peerIDLen]byte]*peer)
	r.waiting = make(map[[peerIDLen]byte]*peer)
	r.mu.Unlock()
	r.wg.Wait()
}

func (r *P2PRelay) acceptLoop() {
	defer r.wg.Done()
	for {
		r.mu.RLock()
		listener := r.listener
		r.mu.RUnlock()
		if listener == nil {
			return
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-r.stopCh:
				return
			default:
				continue
			}
		}

		r.wg.Add(1)
		go r.handleConn(conn)
	}
}

func (r *P2PRelay) handleConn(conn net.Conn) {
	defer r.wg.Done()
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	header := make([]byte, headerLen+authTagLen)
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
		return
	}

	if header[0] != p2pMagic {
		conn.Close()
		return
	}

	cmd := header[1]
	var peerID [peerIDLen]byte
	copy(peerID[:], header[2:2+peerIDLen])
	payloadLen := binary.BigEndian.Uint16(header[2+peerIDLen : 2+peerIDLen+2])
	authTag := header[headerLen : headerLen+authTagLen]

	if !r.verifyAuth(header[:headerLen], authTag) {
		conn.Close()
		return
	}

	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			conn.Close()
			return
		}
	}

	conn.SetDeadline(time.Time{})

	switch cmd {
	case cmdRegister:
		r.handleRegister(conn, peerID)
	case cmdConnect:
		if len(payload) >= peerIDLen {
			var targetID [peerIDLen]byte
			copy(targetID[:], payload[:peerIDLen])
			r.handleConnect(conn, peerID, targetID)
		} else {
			conn.Close()
		}
	default:
		conn.Close()
	}
}

func (r *P2PRelay) handleRegister(conn net.Conn, peerID [peerIDLen]byte) {
	r.mu.Lock()

	if len(r.peers) >= r.config.MaxPeers {
		r.mu.Unlock()
		r.sendResponse(conn, cmdDisconnect, peerID, []byte("max_peers"))
		conn.Close()
		return
	}

	p := &peer{
		id:           peerID,
		conn:         conn,
		lastActivity: time.Now(),
	}

	r.peers[peerID] = p
	r.waiting[peerID] = p
	r.mu.Unlock()

	atomic.AddUint64(&r.totalPeers, 1)
	p2pLog.Debug("Peer registered: %s", hex.EncodeToString(peerID[:]))

	r.sendResponse(conn, cmdPong, peerID, nil)
	r.keepAliveLoop(p)
}

func (r *P2PRelay) handleConnect(conn net.Conn, fromID, toID [peerIDLen]byte) {
	r.mu.Lock()
	target, exists := r.waiting[toID]
	if !exists {
		r.mu.Unlock()
		r.sendResponse(conn, cmdDisconnect, fromID, []byte("peer_not_found"))
		conn.Close()
		return
	}

	from := &peer{
		id:           fromID,
		conn:         conn,
		lastActivity: time.Now(),
		partner:      target,
	}
	target.mu.Lock()
	target.partner = from
	target.mu.Unlock()

	r.peers[fromID] = from
	delete(r.waiting, toID)
	delete(r.waiting, fromID)
	r.mu.Unlock()

	atomic.AddInt32(&r.activePairs, 1)
	p2pLog.Info("P2P pair established: %s <-> %s",
		hex.EncodeToString(fromID[:]), hex.EncodeToString(toID[:]))

	r.sendResponse(conn, cmdData, fromID, nil)
	r.sendResponse(target.conn, cmdData, toID, nil)

	r.relay(from, target)
}

var relayBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

func (r *P2PRelay) relay(a, b *peer) {
	done := make(chan struct{}, 2)

	pipe := func(src, dst *peer) {
		defer func() { done <- struct{}{} }()
		bp := relayBufPool.Get().(*[]byte)
		buf := *bp
		defer func() { relayBufPool.Put(bp) }()
		for {
			src.conn.SetReadDeadline(time.Now().Add(r.config.PeerTimeout))
			n, err := src.conn.Read(buf)
			if err != nil {
				return
			}
			src.mu.Lock()
			src.lastActivity = time.Now()
			src.mu.Unlock()

			atomic.AddUint64(&src.bytesUp, uint64(n))
			atomic.AddUint64(&dst.bytesDown, uint64(n))
			atomic.AddUint64(&r.totalRelayed, uint64(n))

			dst.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := dst.conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}

	go pipe(a, b)
	go pipe(b, a)

	<-done

	a.conn.Close()
	b.conn.Close()

	<-done

	atomic.AddInt32(&r.activePairs, -1)

	r.mu.Lock()
	delete(r.peers, a.id)
	delete(r.peers, b.id)
	r.mu.Unlock()

	p2pLog.Debug("P2P pair closed: %s <-> %s",
		hex.EncodeToString(a.id[:]), hex.EncodeToString(b.id[:]))
}

func (r *P2PRelay) keepAliveLoop(p *peer) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	buf := make([]byte, 1)
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			partner := p.partner
			p.mu.Unlock()

			if partner != nil {
				return
			}

			p.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _ := p.conn.Read(buf)
			p.conn.SetReadDeadline(time.Time{})

			if n > 0 && buf[0] == cmdPing {
				r.sendResponse(p.conn, cmdPong, p.id, nil)
			}

			p.mu.Lock()
			elapsed := time.Since(p.lastActivity)
			p.mu.Unlock()
			if elapsed > r.config.PeerTimeout {
				r.mu.Lock()
				delete(r.peers, p.id)
				delete(r.waiting, p.id)
				r.mu.Unlock()
				p.conn.Close()
				return
			}
		}
	}
}

func (r *P2PRelay) cleanupLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.cleanupStale()
		}
	}
}

func (r *P2PRelay) cleanupStale() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for id, p := range r.waiting {
		p.mu.Lock()
		elapsed := now.Sub(p.lastActivity)
		p.mu.Unlock()

		if elapsed > r.config.PeerTimeout {
			p.conn.Close()
			delete(r.peers, id)
			delete(r.waiting, id)
		}
	}
}

func (r *P2PRelay) sendResponse(conn net.Conn, cmd byte, peerID [peerIDLen]byte, payload []byte) {
	msg := make([]byte, 0, headerLen+len(payload))
	msg = append(msg, p2pMagic, cmd)
	msg = append(msg, peerID[:]...)

	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(payload)))
	msg = append(msg, lenBytes...)

	if len(payload) > 0 {
		msg = append(msg, payload...)
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.Write(msg)
	conn.SetWriteDeadline(time.Time{})
}

func (r *P2PRelay) verifyAuth(header, tag []byte) bool {
	if len(r.config.Secret) == 0 {
		return true
	}
	mac := hmac.New(sha256.New, r.config.Secret)
	mac.Write(header)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, tag)
}

func (r *P2PRelay) Stats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return map[string]interface{}{
		"total_peers":   atomic.LoadUint64(&r.totalPeers),
		"total_relayed": atomic.LoadUint64(&r.totalRelayed),
		"active_pairs":  atomic.LoadInt32(&r.activePairs),
		"registered":    len(r.peers),
		"waiting":       len(r.waiting),
	}
}

func GeneratePeerID() [peerIDLen]byte {
	var id [peerIDLen]byte
	rand.Read(id[:])
	return id
}

func BuildRegisterMessage(peerID [peerIDLen]byte, secret []byte) []byte {
	msg := make([]byte, 0, headerLen+authTagLen)
	msg = append(msg, p2pMagic, cmdRegister)
	msg = append(msg, peerID[:]...)
	msg = append(msg, 0x00, 0x00)

	tag := computeAuthTag(msg, secret)
	msg = append(msg, tag...)
	return msg
}

func BuildConnectMessage(fromID, toID [peerIDLen]byte, secret []byte) []byte {
	msg := make([]byte, 0, headerLen+authTagLen+peerIDLen)
	msg = append(msg, p2pMagic, cmdConnect)
	msg = append(msg, fromID[:]...)

	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, peerIDLen)
	msg = append(msg, lenBytes...)

	tag := computeAuthTag(msg, secret)
	msg = append(msg, tag...)
	msg = append(msg, toID[:]...)
	return msg
}

func computeAuthTag(header, secret []byte) []byte {
	if len(secret) == 0 {
		return make([]byte, authTagLen)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(header)
	return mac.Sum(nil)
}

type P2PClient struct {
	relayAddr string
	secret    []byte
	peerID    [peerIDLen]byte
	conn      net.Conn
	mu        sync.Mutex
}

func NewP2PClient(relayAddr string, secret []byte) *P2PClient {
	return &P2PClient{
		relayAddr: relayAddr,
		secret:    secret,
		peerID:    GeneratePeerID(),
	}
}

func (c *P2PClient) PeerID() string {
	return hex.EncodeToString(c.peerID[:])
}

func (c *P2PClient) Register(ctx context.Context) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.relayAddr)
	if err != nil {
		return err
	}

	msg := BuildRegisterMessage(c.peerID, c.secret)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		conn.Close()
		return err
	}

	resp := make([]byte, headerLen)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return err
	}
	conn.SetDeadline(time.Time{})

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	return nil
}

func (c *P2PClient) ConnectTo(ctx context.Context, targetPeerID string) (net.Conn, error) {
	targetBytes, err := hex.DecodeString(targetPeerID)
	if err != nil || len(targetBytes) != peerIDLen {
		return nil, io.ErrUnexpectedEOF
	}

	var targetID [peerIDLen]byte
	copy(targetID[:], targetBytes)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.relayAddr)
	if err != nil {
		return nil, err
	}

	msg := BuildConnectMessage(c.peerID, targetID, c.secret)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, headerLen)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] == cmdDisconnect {
		conn.Close()
		return nil, io.ErrClosedPipe
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func (c *P2PClient) WaitForPartner(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return nil, io.ErrClosedPipe
	}

	resp := make([]byte, headerLen)
	conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}

	if resp[1] != cmdData {
		return nil, io.ErrUnexpectedEOF
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func (c *P2PClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}
