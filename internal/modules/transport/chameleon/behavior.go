package chameleon

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

type BehaviorParams struct {
	PathSeed     uint64
	BurstSize    int
	ParseDelayMs int
	IdleSec      int
}

const (
	minWindowSec = 15
	maxWindowSec = 90
)

type WindowScheduler struct {
	behaviorKey []byte
	sessionID   []byte
	anchor      time.Time

	mu         sync.Mutex
	boundaries []time.Time
}

func NewWindowScheduler(behaviorKey, sessionID []byte, anchor time.Time) *WindowScheduler {
	ws := &WindowScheduler{
		behaviorKey: behaviorKey,
		sessionID:   sessionID,
		anchor:      anchor,
	}
	ws.boundaries = []time.Time{anchor}
	ws.extendTo(4)
	return ws
}

func (ws *WindowScheduler) windowDuration(i int) time.Duration {
	info := fmt.Sprintf("chameleon-window-dur-v1-%d", i)
	r := hkdf.New(sha256.New, ws.behaviorKey, ws.sessionID, []byte(info))
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		panic("chameleon window dur: " + err.Error())
	}
	secs := minWindowSec + int(binary.BigEndian.Uint32(b[:])%uint32(maxWindowSec-minWindowSec+1))
	return time.Duration(secs) * time.Second
}

func (ws *WindowScheduler) extendTo(n int) {
	for len(ws.boundaries) <= n {
		prev := ws.boundaries[len(ws.boundaries)-1]
		dur := ws.windowDuration(len(ws.boundaries) - 1)
		ws.boundaries = append(ws.boundaries, prev.Add(dur))
	}
}

func (ws *WindowScheduler) CurrentIndex() int {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.currentIndexLocked(time.Now())
}

func (ws *WindowScheduler) NextBoundary() time.Time {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	idx := ws.currentIndexLocked(time.Now())
	ws.extendTo(idx + 2)
	return ws.boundaries[idx+1]
}

func (ws *WindowScheduler) currentIndexLocked(now time.Time) int {
	for {
		last := len(ws.boundaries) - 1
		if now.Before(ws.boundaries[last]) {
			lo, hi := 0, last-1
			for lo < hi {
				mid := (lo + hi + 1) / 2
				if ws.boundaries[mid].After(now) {
					hi = mid - 1
				} else {
					lo = mid
				}
			}
			return lo
		}
		ws.extendTo(last + 2)
	}
}

func DeriveBehaviorParams(behaviorKey []byte, windowIndex int, sessionID []byte) BehaviorParams {
	info := fmt.Sprintf("chameleon-behavior-v1-%d", windowIndex)
	r := hkdf.New(sha256.New, behaviorKey, sessionID, []byte(info))
	var seed [64]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		panic("chameleon behavior derive: " + err.Error())
	}

	u32 := func(off int) uint32 { return binary.BigEndian.Uint32(seed[off:]) }

	return BehaviorParams{
		PathSeed:     binary.BigEndian.Uint64(seed[32:]),
		BurstSize:    2 + int(u32(0)%3),
		ParseDelayMs: 50 + int(u32(4)%101),
		IdleSec:      5 + int(u32(8)%26),
	}
}

type shapedConn struct {
	net.Conn
	sched *WindowScheduler

	ch   chan []byte
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	wErr error
}

func newShapedConn(inner net.Conn, sched *WindowScheduler) *shapedConn {
	sc := &shapedConn{
		Conn:  inner,
		sched: sched,
		ch:    make(chan []byte, 512),
		done:  make(chan struct{}),
	}
	go sc.flusher()
	return sc
}

func (sc *shapedConn) flusher() {
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	var coalesce []byte
	flush := func() {
		if len(coalesce) == 0 {
			return
		}
		if _, err := sc.Conn.Write(coalesce); err != nil {
			sc.mu.Lock()
			sc.wErr = err
			sc.mu.Unlock()
		}
		coalesce = coalesce[:0]
	}
	for {
		select {
		case data := <-sc.ch:
			coalesce = append(coalesce, data...)
		drain:
			for {
				select {
				case more := <-sc.ch:
					coalesce = append(coalesce, more...)
					if len(coalesce) >= 8192 {
						flush()
					}
				default:
					break drain
				}
			}
		case <-ticker.C:
			flush()
		case <-sc.done:
			flush()
			return
		}
	}
}

func (sc *shapedConn) Write(b []byte) (int, error) {
	sc.mu.Lock()
	err := sc.wErr
	sc.mu.Unlock()
	if err != nil {
		return 0, err
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case sc.ch <- cp:
		return len(b), nil
	case <-sc.done:
		return 0, io.ErrClosedPipe
	}
}

func (sc *shapedConn) Close() error {
	sc.once.Do(func() { close(sc.done) })
	return sc.Conn.Close()
}
