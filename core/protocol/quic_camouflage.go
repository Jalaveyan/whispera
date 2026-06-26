package protocol

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	quicCamoTrustWindow  = time.Duration(authWindowTolerance*2+1) * time.Duration(authWindowSeconds) * time.Second
	quicCamoIdleTimeout  = 2 * time.Minute
	quicCamoCleanupEvery = time.Minute
)

type quicDecoySession struct {
	upstream   net.Conn
	lastActive int64
	closeOnce  sync.Once
}

func newQUICDecoySession(listenConn net.PacketConn, clientAddr net.Addr, target string) (*quicDecoySession, error) {
	if target == "" {
		return nil, errors.New("whispera: quic decoy: no target")
	}
	upstream, err := net.Dial("udp", target)
	if err != nil {
		return nil, err
	}
	s := &quicDecoySession{}
	s.upstream = upstream
	atomic.StoreInt64(&s.lastActive, time.Now().UnixNano())
	go s.pump(listenConn, clientAddr)
	return s, nil
}

func (s *quicDecoySession) pump(listenConn net.PacketConn, clientAddr net.Addr) {
	defer s.Close()
	buf := make([]byte, 65535)
	for {
		_ = s.upstream.SetReadDeadline(time.Now().Add(quicCamoIdleTimeout))
		n, err := s.upstream.Read(buf)
		if err != nil {
			return
		}
		atomic.StoreInt64(&s.lastActive, time.Now().UnixNano())
		if _, err := listenConn.WriteTo(buf[:n], clientAddr); err != nil {
			return
		}
	}
}

func (s *quicDecoySession) forward(data []byte) {
	atomic.StoreInt64(&s.lastActive, time.Now().UnixNano())
	_, _ = s.upstream.Write(data)
}

func (s *quicDecoySession) idleSince() time.Duration {
	return time.Since(time.Unix(0, atomic.LoadInt64(&s.lastActive)))
}

func (s *quicDecoySession) Close() {
	s.closeOnce.Do(func() { s.upstream.Close() })
}

type quicCamoConn struct {
	net.PacketConn
	keysFn    func() [][]byte
	decoyAddr func(sni string) string

	mu            sync.Mutex
	realPeers     map[string]time.Time
	decoySessions map[string]*quicDecoySession
	lastClean     time.Time
}

func newQUICCamoConn(inner net.PacketConn, keysFn func() [][]byte, decoyAddr func(string) string) *quicCamoConn {
	return &quicCamoConn{
		PacketConn:    inner,
		keysFn:        keysFn,
		decoyAddr:     decoyAddr,
		realPeers:     make(map[string]time.Time),
		decoySessions: make(map[string]*quicDecoySession),
		lastClean:     time.Now(),
	}
}

func (c *quicCamoConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		key := addr.String()

		c.mu.Lock()
		if exp, ok := c.realPeers[key]; ok {
			if time.Now().Before(exp) {
				c.realPeers[key] = time.Now().Add(quicCamoTrustWindow)
				c.mu.Unlock()
				return n, addr, nil
			}
			delete(c.realPeers, key)
		}
		sess, isDecoy := c.decoySessions[key]
		c.cleanupLocked()
		c.mu.Unlock()

		if isDecoy {
			sess.forward(p[:n])
			continue
		}

		parsed, perr := parseQUICInitialClientHello(p[:n])
		if perr == nil && camoMarkerMatches(c.keysFn(), parsed.random, parsed.keyShare) {
			c.mu.Lock()
			c.realPeers[key] = time.Now().Add(quicCamoTrustWindow)
			c.mu.Unlock()
			traceLog.Infow("quic_camo_authenticated", "remote", key)
			continue
		}

		if !decoyIPRateAllow(key) {
			traceLog.Infow("quic_camo_relay_decoy_throttled", "remote", key)
			continue
		}
		sni := ""
		if parsed != nil {
			sni = parsed.sni
		}
		target := c.decoyAddr(sni)
		newSess, serr := newQUICDecoySession(c.PacketConn, addr, target)
		if serr != nil {
			continue
		}
		traceLog.Infow("quic_camo_relay_decoy", "remote", key, "sni", sni, "target", target)
		c.mu.Lock()
		c.decoySessions[key] = newSess
		c.mu.Unlock()
		newSess.forward(p[:n])
	}
}

func (c *quicCamoConn) cleanupLocked() {
	now := time.Now()
	if now.Sub(c.lastClean) < quicCamoCleanupEvery {
		return
	}
	c.lastClean = now
	for k, exp := range c.realPeers {
		if now.After(exp) {
			delete(c.realPeers, k)
		}
	}
	for k, sess := range c.decoySessions {
		if sess.idleSince() > quicCamoIdleTimeout {
			sess.Close()
			delete(c.decoySessions, k)
		}
	}
}
