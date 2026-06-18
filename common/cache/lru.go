package cache

import (
	"context"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const defaultLRUCapacity = 10000

type lruEntry[V any] struct {
	value     V
	counter   int64
	expiresAt time.Time
}

type LRUCache[V any] struct {
	c  *lru.Cache[string, *lruEntry[V]]
	mu sync.Mutex
}

func NewLRUCache[V any](capacity int) *LRUCache[V] {
	if capacity <= 0 {
		capacity = defaultLRUCapacity
	}
	c, _ := lru.New[string, *lruEntry[V]](capacity)
	return &LRUCache[V]{c: c}
}

func (m *LRUCache[V]) Get(_ context.Context, key string) (V, error) {
	e, ok := m.c.Get(key)
	if !ok {
		var zero V
		return zero, nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		m.c.Remove(key)
		var zero V
		return zero, nil
	}
	return e.value, nil
}

func (m *LRUCache[V]) Set(_ context.Context, key string, value V, ttl time.Duration) error {
	e := &lruEntry[V]{value: value}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
	}
	m.c.Add(key, e)
	return nil
}

func (m *LRUCache[V]) Delete(_ context.Context, key string) error {
	m.c.Remove(key)
	return nil
}

func (m *LRUCache[V]) Exists(_ context.Context, key string) bool {
	e, ok := m.c.Get(key)
	if !ok {
		return false
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		m.c.Remove(key)
		return false
	}
	return true
}

func (m *LRUCache[V]) Incr(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.c.Get(key)
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		e = &lruEntry[V]{}
		m.c.Add(key, e)
	}
	e.counter++
	return e.counter, nil
}

func (m *LRUCache[V]) IncrWithTTL(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.c.Get(key)
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		e = &lruEntry[V]{}
		if ttl > 0 {
			e.expiresAt = time.Now().Add(ttl)
		}
		m.c.Add(key, e)
	}
	e.counter++
	return e.counter, nil
}

func (m *LRUCache[V]) Close() error { return nil }

func (m *LRUCache[V]) Ping(_ context.Context) error { return nil }

func (m *LRUCache[V]) Type() string { return "lru" }

func (m *LRUCache[V]) Clear() {
	m.c.Purge()
}

func (m *LRUCache[V]) Len() int {
	return m.c.Len()
}
