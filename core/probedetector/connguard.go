package probedetector

import (
	"net"
	"sync"
	"time"
)

var KnownMagics = [][]byte{
	{0x16, 0x03},
	[]byte("CON"), []byte("GET"), []byte("POS"), []byte("PUT"),
	[]byte("DEL"), []byte("HEA"), []byte("OPT"), []byte("PAT"),
	[]byte("PRI"),
	{0x57},
}

const (
	MaxConnsPerIPPerSec = 20

	MaxPendingPerIP = 16

	FirstBytesDeadline = 300 * time.Millisecond

	MinFirstBytes = 2
)

type ipBucket struct {
	mu      sync.Mutex
	opens   []time.Time
	pending int
}

type ConnGuard struct {
	mu      sync.RWMutex
	buckets map[string]*ipBucket

	CheckMagics bool

	WhitelistCheck func(ip string) bool

	maxConnsPerSec     int
	maxPending         int
	firstBytesDeadline time.Duration

	cleanStop chan struct{}
}

func NewConnGuardWithLimits(checkMagics bool, maxConnsPerSec, maxPending int, firstBytesDeadline time.Duration) *ConnGuard {
	g := &ConnGuard{
		buckets:            make(map[string]*ipBucket),
		CheckMagics:        checkMagics,
		maxConnsPerSec:     maxConnsPerSec,
		maxPending:         maxPending,
		firstBytesDeadline: firstBytesDeadline,
		cleanStop:          make(chan struct{}),
	}
	go g.cleanupLoop()
	return g
}

func (g *ConnGuard) Stop() {
	close(g.cleanStop)
}

func (g *ConnGuard) Allow(addr net.Addr) bool {
	ip := extractIP(addr.String())
	if ip == "" {
		return true
	}

	if g.WhitelistCheck != nil && g.WhitelistCheck(ip) {
		return true
	}

	b := g.bucket(ip)
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Second)

	j := 0
	for _, t := range b.opens {
		if t.After(cutoff) {
			b.opens[j] = t
			j++
		}
	}
	b.opens = b.opens[:j]

	if len(b.opens) >= g.maxConnsPerSec {
		return false
	}
	if b.pending >= g.maxPending {
		return false
	}

	b.opens = append(b.opens, now)
	b.pending++
	return true
}

func (g *ConnGuard) Done(addr net.Addr) {
	ip := extractIP(addr.String())
	if ip == "" {
		return
	}
	b := g.bucket(ip)
	b.mu.Lock()
	if b.pending > 0 {
		b.pending--
	}
	b.mu.Unlock()
}

func (g *ConnGuard) CheckFirstBytes(conn net.Conn) (peeked []byte, err error) {
	if !g.CheckMagics {
		return nil, nil
	}

	conn.SetReadDeadline(time.Now().Add(g.firstBytesDeadline))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, MinFirstBytes)
	n, readErr := readAtLeast(conn, buf, MinFirstBytes)
	peeked = buf[:n]

	if readErr != nil {
		return peeked, readErr
	}

	if !matchesMagic(peeked) {
		return peeked, ErrUnknownProtocol
	}

	return peeked, nil
}

type ErrUnknownProtocolType struct{}

func (ErrUnknownProtocolType) Error() string {
	return "connguard: unknown protocol in first bytes (possible UDP-in-TCP injection)"
}

var ErrUnknownProtocol = ErrUnknownProtocolType{}

func (g *ConnGuard) bucket(ip string) *ipBucket {
	g.mu.RLock()
	b, ok := g.buckets[ip]
	g.mu.RUnlock()
	if ok {
		return b
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if b, ok = g.buckets[ip]; ok {
		return b
	}
	b = &ipBucket{}
	g.buckets[ip] = b
	return b
}

func (g *ConnGuard) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-g.cleanStop:
			return
		case <-ticker.C:
			g.cleanup()
		}
	}
}

func (g *ConnGuard) cleanup() {
	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)
	g.mu.Lock()
	defer g.mu.Unlock()
	for ip, b := range g.buckets {
		b.mu.Lock()
		active := b.pending > 0
		for _, t := range b.opens {
			if t.After(cutoff) {
				active = true
				break
			}
		}
		if !active {
			delete(g.buckets, ip)
		}
		b.mu.Unlock()
	}
}

func matchesMagic(data []byte) bool {
	if len(data) < MinFirstBytes {
		return false
	}
	for _, magic := range KnownMagics {
		if len(magic) > len(data) {
			continue
		}
		match := true
		for i, b := range magic {
			if data[i] != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func readAtLeast(conn net.Conn, buf []byte, n int) (int, error) {
	total := 0
	for total < n {
		nr, err := conn.Read(buf[total:n])
		total += nr
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (g *ConnGuard) Stats() map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return map[string]interface{}{
		"tracked_ips":  len(g.buckets),
		"check_magics": g.CheckMagics,
	}
}
