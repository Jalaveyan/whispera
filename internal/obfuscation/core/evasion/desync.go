package evasion

import (
	"crypto/rand"
	"net"
	"sync"
	"time"
)

type DesyncStrategy int

const (
	DesyncNone     DesyncStrategy = iota
	DesyncFake
	DesyncRST
	DesyncRSTACK
	DesyncSplit
	DesyncSplit2
	DesyncDisorder
	DesyncDisorder2
)

type DesyncConfig struct {
	Enabled          bool           `yaml:"enabled" json:"enabled"`
	Strategy         DesyncStrategy `yaml:"strategy" json:"strategy"`
	TTL              int            `yaml:"ttl" json:"ttl"`
	SplitPos         int            `yaml:"split_pos" json:"split_pos"`
	FakePayloadSize  int            `yaml:"fake_payload_size" json:"fake_payload_size"`
	AutoDetect       bool           `yaml:"auto_detect" json:"auto_detect"`
}

func DefaultDesyncConfig() *DesyncConfig {
	return &DesyncConfig{
		Enabled:         false,
		Strategy:        DesyncSplit,
		TTL:             1,
		SplitPos:        3,
		FakePayloadSize: 16,
	}
}

type DesyncConn struct {
	inner     net.Conn
	config    *DesyncConfig
	firstDone bool
	mu        sync.Mutex
}

func NewDesyncConn(conn net.Conn, cfg *DesyncConfig) net.Conn {
	if cfg == nil || !cfg.Enabled {
		return conn
	}
	return &DesyncConn{
		inner:  conn,
		config: cfg,
	}
}

func (dc *DesyncConn) Write(p []byte) (int, error) {
	dc.mu.Lock()
	first := !dc.firstDone
	if first {
		dc.firstDone = true
	}
	dc.mu.Unlock()

	if first && isTLSClientHello(p) {
		return dc.desyncWrite(p)
	}
	return dc.inner.Write(p)
}

func (dc *DesyncConn) desyncWrite(p []byte) (int, error) {
	if dc.config.AutoDetect {
		return dc.autoDesync(p)
	}

	switch dc.config.Strategy {
	case DesyncFake:
		return dc.applyFake(p)
	case DesyncRST, DesyncRSTACK:
		return dc.applyRST(p)
	case DesyncSplit:
		return dc.applySplit(p)
	case DesyncSplit2:
		return dc.applySplit2(p)
	case DesyncDisorder:
		return dc.applyDisorder(p)
	case DesyncDisorder2:
		return dc.applyDisorder2(p)
	default:
		return dc.inner.Write(p)
	}
}

func (dc *DesyncConn) autoDesync(p []byte) (int, error) {
	strategies := []func([]byte) (int, error){
		dc.applySplit,
		dc.applyFake,
		dc.applyDisorder,
	}
	for _, fn := range strategies {
		n, err := fn(p)
		if err == nil {
			return n, nil
		}
	}
	return dc.inner.Write(p)
}

func (dc *DesyncConn) applyFake(p []byte) (int, error) {
	tcpConn, ok := dc.inner.(*net.TCPConn)
	if !ok {
		return dc.applySplit(p)
	}

	origTTL := 64
	setTTL(tcpConn, dc.config.TTL)

	fake := make([]byte, dc.config.FakePayloadSize)
	rand.Read(fake)
	if len(fake) >= 3 {
		fake[0] = 0x16
		fake[1] = 0x03
		fake[2] = 0x01
	}
	tcpConn.Write(fake)

	setTTL(tcpConn, origTTL)

	return dc.inner.Write(p)
}

func (dc *DesyncConn) applyRST(p []byte) (int, error) {
	tcpConn, ok := dc.inner.(*net.TCPConn)
	if !ok {
		return dc.applySplit(p)
	}

	origTTL := 64
	setTTL(tcpConn, dc.config.TTL)

	rst := []byte{0x04}
	tcpConn.Write(rst)

	setTTL(tcpConn, origTTL)

	return dc.inner.Write(p)
}

func (dc *DesyncConn) applySplit(p []byte) (int, error) {
	pos := dc.config.SplitPos
	if pos <= 0 || pos >= len(p) {
		pos = 3
	}
	if pos >= len(p) {
		return dc.inner.Write(p)
	}

	n1, err := dc.inner.Write(p[:pos])
	if err != nil {
		return n1, err
	}

	n2, err := dc.inner.Write(p[pos:])
	return n1 + n2, err
}

func (dc *DesyncConn) applySplit2(p []byte) (int, error) {
	pos := dc.config.SplitPos
	if pos <= 0 || pos >= len(p) {
		pos = 3
	}
	if pos >= len(p) {
		return dc.inner.Write(p)
	}

	n1, err := dc.inner.Write(p[:pos])
	if err != nil {
		return n1, err
	}

	pos2 := pos + (len(p)-pos)/2
	if pos2 >= len(p) {
		n2, err := dc.inner.Write(p[pos:])
		return n1 + n2, err
	}

	n2, err := dc.inner.Write(p[pos:pos2])
	if err != nil {
		return n1 + n2, err
	}

	n3, err := dc.inner.Write(p[pos2:])
	return n1 + n2 + n3, err
}

func (dc *DesyncConn) applyDisorder(p []byte) (int, error) {
	pos := dc.config.SplitPos
	if pos <= 0 || pos >= len(p) {
		pos = 3
	}
	if pos >= len(p) {
		return dc.inner.Write(p)
	}

	tcpConn, ok := dc.inner.(*net.TCPConn)
	if !ok {
		return dc.applySplit(p)
	}

	setTTL(tcpConn, dc.config.TTL)
	tcpConn.Write(p[:pos])

	setTTL(tcpConn, 64)

	n2, err := dc.inner.Write(p[pos:])
	if err != nil {
		return n2, err
	}

	_, err = dc.inner.Write(p[:pos])
	return len(p), err
}

func (dc *DesyncConn) applyDisorder2(p []byte) (int, error) {
	pos := dc.config.SplitPos
	if pos <= 0 || pos >= len(p) {
		pos = 3
	}
	if pos >= len(p) {
		return dc.inner.Write(p)
	}

	n1, err := dc.inner.Write(p[pos:])
	if err != nil {
		return n1, err
	}
	n2, err := dc.inner.Write(p[:pos])
	return n1 + n2, err
}

func isTLSClientHello(p []byte) bool {
	return len(p) > 5 && p[0] == 0x16 && p[1] == 0x03 && p[5] == 0x01
}

func randByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

func (dc *DesyncConn) Read(p []byte) (int, error)         { return dc.inner.Read(p) }
func (dc *DesyncConn) Close() error                        { return dc.inner.Close() }
func (dc *DesyncConn) LocalAddr() net.Addr                 { return dc.inner.LocalAddr() }
func (dc *DesyncConn) RemoteAddr() net.Addr                { return dc.inner.RemoteAddr() }
func (dc *DesyncConn) SetDeadline(t time.Time) error       { return dc.inner.SetDeadline(t) }
func (dc *DesyncConn) SetReadDeadline(t time.Time) error   { return dc.inner.SetReadDeadline(t) }
func (dc *DesyncConn) SetWriteDeadline(t time.Time) error  { return dc.inner.SetWriteDeadline(t) }
