package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	asnbypass "whispera/core/asn_bypass"
	"whispera/core/protocol"
	"whispera/core/transport/grpc"
	"whispera/core/transport/yadisk"

	quicgo "github.com/quic-go/quic-go"
	"whispera/common/mux"
)

const altTransportSessionIDLen = 8

func sendAltTransportAuth(conn net.Conn, psk []byte) error {
	if len(psk) != 32 {
		conn.Close()
		return fmt.Errorf("alt transport auth: PSK not available")
	}
	sessionID := make([]byte, altTransportSessionIDLen)
	if _, err := rand.Read(sessionID); err != nil {
		conn.Close()
		return err
	}
	token := protocol.ClientAuthToken(psk, sessionID)
	hdr := make([]byte, 1+altTransportSessionIDLen+2+len(token))
	hdr[0] = byte(altTransportSessionIDLen)
	copy(hdr[1:1+altTransportSessionIDLen], sessionID)
	binary.BigEndian.PutUint16(hdr[1+altTransportSessionIDLen:1+altTransportSessionIDLen+2], uint16(len(token)))
	copy(hdr[1+altTransportSessionIDLen+2:], token)
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return err
	}
	return nil
}

type rtLane struct {
	mu     sync.Mutex
	sess   *mux.Session
	conn   net.Conn
	quicGD *protocol.RTDatagramClient
	refs   int
	idle   *time.Timer
}

type rtLaneManager struct {
	m *Manager

	sessionCache any
	lane         rtLane

	scaleAccBytes uint64
	scaleLastEval time.Time
	scaleMu       sync.Mutex
}

func newRTLaneManager(m *Manager) *rtLaneManager {
	return &rtLaneManager{m: m, sessionCache: protocol.NewSessionCache(128)}
}

func (rl *rtLaneManager) whisperaDial() (func(context.Context) (net.Conn, error), bool) {
	m := rl.m
	if !m.config.EnableWhispera || len(m.config.WhisperaSecret) == 0 {
		return nil, false
	}
	addr := m.config.WhisperaAddr
	if addr == "" {
		addr = m.config.ServerAddr
	}
	sni := m.config.WhisperaSNI
	var sniList []string
	if sni == "" || net.ParseIP(sni) != nil {
		sni = ""
		sniList = asnbypass.WhitelistSNIPool()
	}
	var tcpDialer func(context.Context, string, string) (net.Conn, error)
	if m.asnBypassDialer != nil {
		tcpDialer = m.asnBypassDialer.DialTCP
	}
	cCfg := &protocol.ClientConfig{
		ServerAddr:    addr,
		ServerName:    sni,
		ServerNames:   sniList,
		SharedSecret:  m.config.WhisperaSecret,
		ServerCertPin: m.config.WhisperaCertPin,
		SessionCache:  rl.sessionCache,
		TCPDialer:     tcpDialer,
		EnableQUIC:    m.config.WhisperaQUICAddr != "",
		QUICAddr:      m.config.WhisperaQUICAddr,
		OnQUICConn: func(c *quicgo.Conn) {
			gd := protocol.NewRTDatagramClient(c)
			g := &rl.lane
			g.mu.Lock()
			old := g.quicGD
			g.quicGD = gd
			g.mu.Unlock()
			if old != nil {
				old.Close()
			}
			go func() {
				<-c.Context().Done()
				g.mu.Lock()
				if g.quicGD == gd {
					g.quicGD = nil
				}
				g.mu.Unlock()
				gd.Close()
			}()
		},
	}
	return func(ctx context.Context) (net.Conn, error) {
		return protocol.Client(ctx, cCfg)
	}, true
}

func (rl *rtLaneManager) grpcDial() (func(context.Context) (net.Conn, error), bool) {
	m := rl.m
	if !m.config.EnableGRPC || m.config.GRPCAddr == "" {
		return nil, false
	}
	t, err := grpc.New(&grpc.Config{
		ListenAddr: "127.0.0.1:0",
		ServerName: m.config.GRPCServerName,
		UseTLS:     m.config.GRPCUseTLS,
	})
	if err != nil {
		return nil, false
	}
	addr := m.config.GRPCAddr
	psk := m.config.PSK
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := t.Dial(ctx, addr)
		if err != nil {
			return nil, err
		}
		if err := sendAltTransportAuth(conn, psk); err != nil {
			return nil, err
		}
		return conn, nil
	}, true
}

func (rl *rtLaneManager) yadiskDial() (func(context.Context) (net.Conn, error), bool) {
	m := rl.m
	if !m.config.EnableYaDisk || m.config.YaDiskOAuthToken == "" {
		return nil, false
	}
	t, err := yadisk.New(&yadisk.Config{
		OAuthToken: m.config.YaDiskOAuthToken,
		SessionID:  m.config.YaDiskSessionID,
	})
	if err != nil {
		return nil, false
	}
	if err := t.Start(); err != nil {
		return nil, false
	}
	psk := m.config.PSK
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := t.Dial(ctx, "")
		if err != nil {
			return nil, err
		}
		if err := sendAltTransportAuth(conn, psk); err != nil {
			return nil, err
		}
		return conn, nil
	}, true
}

func (rl *rtLaneManager) dial() func(context.Context) (net.Conn, error) {
	if d, ok := rl.whisperaDial(); ok {
		return d
	}
	if d, ok := rl.grpcDial(); ok {
		return d
	}
	if d, ok := rl.yadiskDial(); ok {
		return d
	}
	return nil
}

func (rl *rtLaneManager) session(ctx context.Context) (*mux.Session, error) {
	m := rl.m
	dial := rl.dial()
	if dial == nil {
		return nil, fmt.Errorf("rt lane: no whispera dial")
	}
	g := &rl.lane
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.idle != nil {
		g.idle.Stop()
		g.idle = nil
	}
	if g.sess != nil && !g.sess.IsClosed() {
		g.refs++
		return g.sess, nil
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	padMax := m.config.PaddingMaxSize
	if padMax <= 0 {
		padMax = 128
	}
	sess, err := mux.Client(mux.NewPaddedConn(conn, padMax), m.getMuxConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}
	g.conn = conn
	g.sess = sess
	g.refs = 1
	return sess, nil
}

func (m *Manager) RTDatagram(ctx context.Context, addr string) (*protocol.RTDatagramClient, func(), bool) {
	if !m.config.EnableWhispera {
		return nil, nil, false
	}
	gd, ok := m.rtLane.AcquireRTDatagram(ctx)
	if !ok {
		return nil, nil, false
	}
	return gd, m.rtLane.ReleaseRTDatagram, true
}

func (rl *rtLaneManager) active() bool {
	g := &rl.lane
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.refs > 0
}

func (rl *rtLaneManager) streamClosed() {
	g := &rl.lane
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refs > 0 {
		g.refs--
	}
	if g.refs == 0 && g.sess != nil && g.idle == nil {
		g.idle = time.AfterFunc(rtIdleTimeout, func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.idle = nil
			if g.refs == 0 && g.sess != nil {
				g.sess.Close()
				if g.conn != nil {
					g.conn.Close()
				}
				g.sess = nil
				g.conn = nil
			}
		})
	}
}

func (rl *rtLaneManager) AcquireRTDatagram(ctx context.Context) (gd *protocol.RTDatagramClient, ok bool) {
	g := &rl.lane
	g.mu.Lock()
	gd = g.quicGD
	g.mu.Unlock()
	return gd, gd != nil
}

func (rl *rtLaneManager) ReleaseRTDatagram() {}

func (rl *rtLaneManager) feedScale(n int) {
	m := rl.m
	if n <= 0 || !m.config.EnableWhispera {
		return
	}
	sum := atomic.AddUint64(&rl.scaleAccBytes, uint64(n))
	if sum >= scaleEvalBytes && atomic.CompareAndSwapUint64(&rl.scaleAccBytes, sum, 0) {
		rl.evalScale()
	}
}

func (rl *rtLaneManager) evalScale() {
	m := rl.m
	rl.scaleMu.Lock()
	now := time.Now()
	last := rl.scaleLastEval
	rl.scaleLastEval = now
	rl.scaleMu.Unlock()
	if last.IsZero() {
		return
	}
	dt := now.Sub(last).Seconds()
	if dt <= 0 {
		return
	}
	rate := float64(scaleEvalBytes) / dt

	m.connMu.RLock()
	poolSize := len(m.activePool)
	m.connMu.RUnlock()
	if poolSize == 0 {
		return
	}
	base := m.config.WhisperaMux
	if base < 1 {
		base = 16
	}

	perConn := rate / float64(poolSize)

	if perConn < chScaleShrinkPerConn && poolSize > base {
		if rl.closeIdlePoolConn(base) {
		}
	}
}

func (rl *rtLaneManager) closeIdlePoolConn(base int) bool {
	m := rl.m
	m.connMu.Lock()
	defer m.connMu.Unlock()
	if len(m.activePool) <= base {
		return false
	}
	inUse := make(map[*managedConn]int, len(m.streamConns))
	for _, c := range m.streamConns {
		inUse[c]++
	}
	for i := len(m.activePool) - 1; i >= 0; i-- {
		c := m.activePool[i]
		if c == m.activeConn || inUse[c] > 0 {
			continue
		}
		m.activePool = append(m.activePool[:i], m.activePool[i+1:]...)
		m.drainingConns = append(m.drainingConns, c)
		go m.monitorDrainingConn(c)
		return true
	}
	return false
}
