package util

import (
	"sync/atomic"
	"time"

	"whispera/internal/logger"
)

// SafeClose safely closes a resource and logs any error
func SafeClose(name string, closer func() error) {
	if err := closer(); err != nil {
		logger.Warn("Failed to close %s: %v", name, err)
	}
}

// TimeCache provides cached time for performance using atomics instead of RWMutex
type TimeCache struct {
	// УЛУЧШЕНИЕ: Используем atomic.Value вместо RWMutex для избежания задержек
	current atomic.Value // содержит time.Time
}

var globalTimeCache = &TimeCache{}

func init() {
	globalTimeCache.current.Store(time.Now())
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		for t := range ticker.C {
			// УЛУЧШЕНИЕ: Без лока - просто атомарное сохранение
			globalTimeCache.current.Store(t)
		}
	}()
}

// GetGlobalTimeCache returns the global time cache
func GetGlobalTimeCache() *TimeCache {
	return globalTimeCache
}

// Now returns the cached current time without locking
func (tc *TimeCache) Now() time.Time {
	// УЛУЧШЕНИЕ: Без RLock - прямое atomics чтение O(1) без контенции
	return tc.current.Load().(time.Time)
}

// NowNano returns the cached current time as nanoseconds without locking
func (tc *TimeCache) NowNano() int64 {
	// УЛУЧШЕНИЕ: Без RLock - прямое atomics чтение
	return tc.current.Load().(time.Time).UnixNano()
}
