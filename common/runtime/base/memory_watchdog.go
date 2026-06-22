package base

import (
	"context"
	"log"
	"runtime"
	"time"
)

type MemoryWatchdog struct {
	softLimit   uint64
	hardLimit   uint64
	checkPeriod time.Duration
	onPressure  func(allocMB uint64)
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewMemoryWatchdog(softLimitMB, hardLimitMB uint64, period time.Duration) *MemoryWatchdog {
	ctx, cancel := context.WithCancel(context.Background())
	return &MemoryWatchdog{
		softLimit:   softLimitMB * 1024 * 1024,
		hardLimit:   hardLimitMB * 1024 * 1024,
		checkPeriod: period,
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (mw *MemoryWatchdog) Start() {
	go func() {
		ticker := time.NewTicker(mw.checkPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-mw.ctx.Done():
				return
			case <-ticker.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				if ms.Alloc > mw.hardLimit {
					log.Printf("[MemoryWatchdog] HARD limit exceeded: %dMB (limit %dMB), forcing GC",
						ms.Alloc/1024/1024, mw.hardLimit/1024/1024)
					runtime.GC()
					runtime.ReadMemStats(&ms)
					if ms.Alloc > mw.hardLimit {
						log.Printf("[MemoryWatchdog] still above hard limit after GC: %dMB", ms.Alloc/1024/1024)
					}
				} else if ms.Alloc > mw.softLimit {
					log.Printf("[MemoryWatchdog] soft limit exceeded: %dMB (limit %dMB)",
						ms.Alloc/1024/1024, mw.softLimit/1024/1024)
					if mw.onPressure != nil {
						mw.onPressure(ms.Alloc / 1024 / 1024)
					}
				}
			}
		}
	}()
}

func (mw *MemoryWatchdog) Stop() {
	mw.cancel()
}
