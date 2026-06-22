package base

import (
	"sync/atomic"
	"time"
)

type GoroutineLimiter struct {
	sem     chan struct{}
	active  int64
	dropped int64
	limit   int
}

func NewGoroutineLimiter(limit int) *GoroutineLimiter {
	return &GoroutineLimiter{
		sem:   make(chan struct{}, limit),
		limit: limit,
	}
}

func (gl *GoroutineLimiter) Go(fn func()) bool {
	select {
	case gl.sem <- struct{}{}:
		atomic.AddInt64(&gl.active, 1)
		go func() {
			defer func() {
				<-gl.sem
				atomic.AddInt64(&gl.active, -1)
			}()
			fn()
		}()
		return true
	default:
		atomic.AddInt64(&gl.dropped, 1)
		return false
	}
}

func (gl *GoroutineLimiter) GoWithTimeout(fn func(), timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case gl.sem <- struct{}{}:
		atomic.AddInt64(&gl.active, 1)
		go func() {
			defer func() {
				<-gl.sem
				atomic.AddInt64(&gl.active, -1)
			}()
			fn()
		}()
		return true
	case <-t.C:
		atomic.AddInt64(&gl.dropped, 1)
		return false
	}
}

func (gl *GoroutineLimiter) Active() int64  { return atomic.LoadInt64(&gl.active) }
func (gl *GoroutineLimiter) Dropped() int64 { return atomic.LoadInt64(&gl.dropped) }
func (gl *GoroutineLimiter) Limit() int     { return gl.limit }
