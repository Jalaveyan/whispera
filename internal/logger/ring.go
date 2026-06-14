package logger

import (
	"sync"
	"time"
)

const defaultRingSize = 5000

type RingEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Module  string    `json:"module,omitempty"`
	Message string    `json:"msg"`
}

type ringBuffer struct {
	mu    sync.RWMutex
	buf   []RingEntry
	size  int
	head  int
	count int
}

func newRingBuffer(size int) *ringBuffer {
	if size <= 0 {
		size = defaultRingSize
	}
	return &ringBuffer{buf: make([]RingEntry, size), size: size}
}

func (r *ringBuffer) push(e RingEntry) {
	r.mu.Lock()
	r.buf[r.head] = e
	r.head = (r.head + 1) % r.size
	if r.count < r.size {
		r.count++
	}
	r.mu.Unlock()
}

func (r *ringBuffer) snapshot(limit int, minLevel Level) []RingEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 || limit > r.count {
		limit = r.count
	}

	out := make([]RingEntry, 0, limit)
	start := (r.head - r.count + r.size) % r.size
	for i := 0; i < r.count; i++ {
		idx := (start + i) % r.size
		e := r.buf[idx]
		if minLevel > LevelDebug && levelFromString(e.Level) < minLevel {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func levelFromString(s string) Level {
	switch s {
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARN":
		return LevelWarn
	case "ERROR":
		return LevelError
	case "FATAL":
		return LevelFatal
	}
	return LevelInfo
}

var (
	globalRing     *ringBuffer
	globalRingOnce sync.Once
)

func ring() *ringBuffer {
	globalRingOnce.Do(func() {
		globalRing = newRingBuffer(defaultRingSize)
	})
	return globalRing
}

func Snapshot(limit int, minLevel Level) []RingEntry {
	return ring().snapshot(limit, minLevel)
}
