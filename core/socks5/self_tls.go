package socks5

import (
	"io"
	"sync/atomic"
	"time"
)

var HarvestHook func([]byte)

var lastHarvest atomic.Int64

type harvestPeekReader struct {
	io.Reader
	done bool
}

func (h *harvestPeekReader) Read(p []byte) (int, error) {
	n, err := h.Reader.Read(p)
	if !h.done && n > 0 {
		h.done = true
		maybeHarvest(p[:n])
	}
	return n, err
}

func maybeHarvest(b []byte) {
	if HarvestHook == nil || len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
		return
	}
	recLen := int(b[3])<<8 | int(b[4])
	if recLen <= 0 || 5+recLen > len(b) {
		return
	}
	now := time.Now().UnixNano()
	last := lastHarvest.Load()
	if now-last < int64(30*time.Second) {
		return
	}
	if !lastHarvest.CompareAndSwap(last, now) {
		return
	}
	rec := make([]byte, 5+recLen)
	copy(rec, b[:5+recLen])
	HarvestHook(rec)
}
