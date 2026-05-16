package chameleon

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// BehaviorParams controls traffic shaping for one window interval.
// Derived deterministically from shared key + window index + session ID.
type BehaviorParams struct {
	SizeMu    float64
	SizeSigma float64

	InterPacketMean time.Duration

	BurstMin, BurstMax int
	BurstPause         time.Duration

	PaddingMin, PaddingMax int

	PathSeed uint64
}

// WindowScheduler derives a random sequence of window durations from the shared key.
// Both client and server compute the same sequence independently — no negotiation.
//
// Window durations are drawn from [minWindowSec, maxWindowSec] via HKDF, so the
// switching interval is unpredictable to an observer without the key.
const (
	minWindowSec = 15
	maxWindowSec = 90
)

type WindowScheduler struct {
	behaviorKey []byte
	sessionID   []byte
	anchor      time.Time // connection start — embedded in session header

	mu         sync.Mutex
	boundaries []time.Time // pre-computed window boundary times
}

func NewWindowScheduler(behaviorKey, sessionID []byte, anchor time.Time) *WindowScheduler {
	ws := &WindowScheduler{
		behaviorKey: behaviorKey,
		sessionID:   sessionID,
		anchor:      anchor,
	}
	// pre-compute first few boundaries
	ws.boundaries = []time.Time{anchor}
	ws.extendTo(4)
	return ws
}

// windowDuration returns the duration of window i, derived deterministically.
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

// extendTo ensures boundaries slice has at least n+1 entries (covers window n).
func (ws *WindowScheduler) extendTo(n int) {
	for len(ws.boundaries) <= n {
		prev := ws.boundaries[len(ws.boundaries)-1]
		dur := ws.windowDuration(len(ws.boundaries) - 1)
		ws.boundaries = append(ws.boundaries, prev.Add(dur))
	}
}

// CurrentIndex returns the window index for now.
func (ws *WindowScheduler) CurrentIndex() int {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	now := time.Now()
	for {
		last := len(ws.boundaries) - 1
		if now.Before(ws.boundaries[last]) {
			// find index by binary search
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
		// extend and retry
		ws.extendTo(last + 2)
	}
}

// NextBoundary returns when the current window ends.
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

// DeriveBehaviorParams produces unique params per (key, windowIndex, sessionID) triple.
func DeriveBehaviorParams(behaviorKey []byte, windowIndex int, sessionID []byte) BehaviorParams {
	info := fmt.Sprintf("chameleon-behavior-v1-%d", windowIndex)
	r := hkdf.New(sha256.New, behaviorKey, sessionID, []byte(info))
	var seed [64]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		panic("chameleon behavior derive: " + err.Error())
	}

	f32 := func(off int) float64 {
		return float64(binary.BigEndian.Uint32(seed[off:])) / math.MaxUint32
	}

	return BehaviorParams{
		SizeMu:          512 + f32(0)*3584,
		SizeSigma:       64 + f32(4)*256,
		InterPacketMean: time.Duration((1+f32(8)*19)*float64(time.Millisecond)),
		BurstMin:        1 + int(f32(12)*4),
		BurstMax:        3 + int(f32(16)*8),
		BurstPause:      time.Duration((10+f32(20)*90)*float64(time.Millisecond)),
		PaddingMin:      int(f32(24) * 32),
		PaddingMax:      32 + int(f32(28)*96),
		PathSeed:        binary.BigEndian.Uint64(seed[32:]),
	}
}

// shapedConn wraps net.Conn with GRU-based traffic shaping.
// It tracks window switches via WindowScheduler and rotates the GRU when the
// window changes, so the traffic fingerprint shifts at random intervals.
//
// Design notes:
//   - Chunk size and inter-frame delay come from the GRU (session-unique weights).
//   - Session-level burst/idle is handled by connection rotation in tunnel.go
//     (each H2 POST lives 45-120s), not by artificial pauses here. Per-write
//     burst pauses were removed: they triggered every 32-256 KB, causing
//     7-60 stalls per HLS segment and making Twitch unwatchable.
//   - Writes < 512 B (yamux SYN/ACK/SETTINGS/WINDOW_UPDATE) bypass all delays
//     so yamux control frames never stall the send goroutine.
//   - If no write for >5 s, the next write skips the inter-frame delay
//     so resumption latency is minimal (user just started a new activity).
type shapedConn struct {
	net.Conn
	sched     *WindowScheduler
	gru       *trafficGRU
	lastIndex int

	lastWrite time.Time
}

func newShapedConn(inner net.Conn, sched *WindowScheduler) *shapedConn {
	idx := sched.CurrentIndex()
	gru := newTrafficGRU(sched.behaviorKey, int64(idx), sched.sessionID)
	return &shapedConn{
		Conn:      inner,
		sched:     sched,
		gru:       gru,
		lastIndex: idx,
	}
}

func (s *shapedConn) refreshGRU() {
	idx := s.sched.CurrentIndex()
	if idx != s.lastIndex {
		s.gru = newTrafficGRU(s.sched.behaviorKey, int64(idx), s.sched.sessionID)
		s.lastIndex = idx
	}
}

func (s *shapedConn) Write(p []byte) (int, error) {
	s.refreshGRU()

	returningFromIdle := !s.lastWrite.IsZero() && time.Since(s.lastWrite) > 5*time.Second
	_, delayMs := s.gru.Next()

	written := 0
	for len(p) > 0 {
		chunkSize, _ := s.gru.Next()
		if chunkSize > len(p) {
			chunkSize = len(p)
		}
		if chunkSize < 1 {
			chunkSize = 1
		}
		if _, err := s.Conn.Write(p[:chunkSize]); err != nil {
			return written, err
		}
		written += chunkSize
		p = p[chunkSize:]
	}

	s.lastWrite = time.Now()

	// Bypass delay for yamux control frames (SYN=12B, SETTINGS=12B, WINDOW_UPDATE=16B)
	// and for idle resumption. Only data writes (≥512B) get an inter-frame delay.
	if written >= 512 && !returningFromIdle && delayMs > 0.5 {
		time.Sleep(time.Duration(delayMs * float64(time.Millisecond)))
	}

	return written, nil
}
