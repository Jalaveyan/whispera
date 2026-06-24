package protocol

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	camoWindowSeconds = authWindowSeconds
	camoWindowTol     = authWindowTolerance
	camoPeekTimeout   = 4 * time.Second
	camoMaxHandshake  = 8192
	camoDialTimeout   = 5 * time.Second
)

func deriveCamoKey(psk []byte) []byte {
	if len(psk) != 32 {
		return nil
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("whispera-camo-v1"))
	return mac.Sum(nil)
}

func extractX25519KeyShare(shares []utls.KeyShare) []byte {
	for _, ks := range shares {
		if ks.Group == utls.X25519 {
			return ks.Data
		}
	}
	return nil
}

func camoMarkerForWindow(key []byte, window int64, keyShare []byte) [32]byte {
	var out [32]byte
	mac := hmac.New(sha256.New, key)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(keyShare)
	copy(out[:], mac.Sum(nil))
	return out
}

func buildCamoMarker(key []byte, keyShare []byte) [32]byte {
	w := time.Now().Unix() / camoWindowSeconds
	return camoMarkerForWindow(key, w, keyShare)
}

func camoMarkerMatches(keys [][]byte, random []byte, keyShare []byte) bool {
	if len(random) != 32 || len(keys) == 0 || len(keyShare) == 0 {
		return false
	}
	w := time.Now().Unix() / camoWindowSeconds
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		for cand := w - camoWindowTol; cand <= w+camoWindowTol; cand++ {
			marker := camoMarkerForWindow(key, cand, keyShare)
			if hmac.Equal(marker[:], random) {
				return true
			}
		}
	}
	return false
}

func probeCamoMarkerDrift(keys [][]byte, random []byte, keyShare []byte) (driftWindows int64, found bool) {
	if len(random) != 32 || len(keys) == 0 || len(keyShare) == 0 {
		return 0, false
	}
	w := time.Now().Unix() / camoWindowSeconds
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		for offset := int64(camoWindowTol + 1); offset <= clockDriftProbeWindows; offset++ {
			up := camoMarkerForWindow(key, w+offset, keyShare)
			if hmac.Equal(up[:], random) {
				return offset, true
			}
			down := camoMarkerForWindow(key, w-offset, keyShare)
			if hmac.Equal(down[:], random) {
				return -offset, true
			}
		}
	}
	return 0, false
}

type peekedHello struct {
	raw      []byte
	random   []byte
	sni      string
	keyShare []byte
}

func peekClientHello(conn net.Conn) (*peekedHello, error) {
	_ = conn.SetReadDeadline(time.Now().Add(camoPeekTimeout))
	defer conn.SetReadDeadline(time.Time{})

	var raw []byte
	var hs []byte

	for {
		var hdr [5]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return &peekedHello{raw: raw}, err
		}
		raw = append(raw, hdr[:]...)
		if hdr[0] != 0x16 {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: not a TLS handshake record")
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen <= 0 || recLen > 16384 {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: invalid TLS record length")
		}
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return &peekedHello{raw: raw}, err
		}
		raw = append(raw, payload...)
		hs = append(hs, payload...)

		if len(hs) > camoMaxHandshake {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: ClientHello too large")
		}
		if len(hs) < 4 {
			continue
		}
		if hs[0] != 0x01 {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: not a ClientHello")
		}
		bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		want := 4 + bodyLen
		if len(hs) < want {
			continue
		}
		msg := utls.UnmarshalClientHello(hs[:want])
		if msg == nil {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: failed to parse ClientHello")
		}
		return &peekedHello{
			raw:      raw,
			random:   msg.Random,
			sni:      msg.ServerName,
			keyShare: extractX25519KeyShare(msg.KeyShares),
		}, nil
	}
}

type prefixConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(b, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}

func relayToOrigin(conn net.Conn, raw []byte, addr string) {
	defer conn.Close()
	if addr == "" {
		return
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), camoDialTimeout)
	defer cancel()
	upstream, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return
	}
	defer upstream.Close()

	if len(raw) > 0 {
		if _, err := upstream.Write(raw); err != nil {
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

func camoDecoyAddr(decoyOrigin string) func(sni string) string {
	fallbackHost := ""
	if decoyOrigin != "" {
		if u, err := url.Parse(decoyOrigin); err == nil {
			fallbackHost = u.Hostname()
		} else {
			fallbackHost = decoyOrigin
		}
	}
	return func(sni string) string {
		host := sni
		if !validSNI(host) {
			host = fallbackHost
		}
		if host == "" {
			return ""
		}
		return net.JoinHostPort(host, "443")
	}
}

type camouflageListener struct {
	net.Listener
	ready     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
	keysFn    func() [][]byte
	decoyAddr func(sni string) string
}

func newCamouflageListener(inner net.Listener, keysFn func() [][]byte, decoyAddr func(string) string) *camouflageListener {
	l := &camouflageListener{
		Listener:  inner,
		ready:     make(chan net.Conn),
		closed:    make(chan struct{}),
		keysFn:    keysFn,
		decoyAddr: decoyAddr,
	}
	go l.acceptLoop()
	return l
}

func (l *camouflageListener) acceptLoop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			close(l.ready)
			return
		}
		go l.handle(conn)
	}
}

func (l *camouflageListener) handle(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	ph, err := peekClientHello(conn)
	if err == nil && camoMarkerMatches(l.keysFn(), ph.random, ph.keyShare) {
		traceLog.Infow("camo_authenticated", "remote", remote, "sni", ph.sni)
		pc := &prefixConn{Conn: conn, prefix: ph.raw}
		select {
		case l.ready <- pc:
		case <-l.closed:
			conn.Close()
		}
		return
	}
	if len(ph.raw) == 0 {
		traceLog.Infow("camo_no_hello", "remote", remote, "err", err)
		conn.Close()
		return
	}
	if err == nil {
		if drift, found := probeCamoMarkerDrift(l.keysFn(), ph.random, ph.keyShare); found {
			traceLog.Warnw("camo_marker_drift_suspected", "remote", remote, "sni", ph.sni,
				"drift_windows", drift, "drift_seconds", drift*camoWindowSeconds)
		}
	}
	target := l.decoyAddr(ph.sni)
	traceLog.Infow("camo_relay_decoy", "remote", remote, "sni", ph.sni, "hello_err", err, "target", target)
	relayToOrigin(conn, ph.raw, target)
}

func (l *camouflageListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ready
	if !ok {
		return nil, fmt.Errorf("whispera: camouflage listener closed")
	}
	return conn, nil
}

func (l *camouflageListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

func camoKeysFunc(cfg *ServerConfig) func() [][]byte {
	return func() [][]byte {
		keys := make([][]byte, 0, 4)
		if len(cfg.SharedSecret) == 32 {
			keys = append(keys, deriveCamoKey(cfg.SharedSecret))
		}
		if cfg.GetUsers != nil {
			for _, u := range cfg.GetUsers() {
				if len(u.PSK) == 32 {
					keys = append(keys, deriveCamoKey(u.PSK))
				}
			}
		}
		return keys
	}
}
