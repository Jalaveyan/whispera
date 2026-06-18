package cache

import (
	"context"
	"testing"
	"time"
)

func TestLRUCacheGetSetGeneric(t *testing.T) {
	c := NewLRUCache[string](2)
	ctx := context.Background()

	if err := c.Set(ctx, "a", "1", 0); err != nil {
		t.Fatalf("set: %v", err)
	}
	v, err := c.Get(ctx, "a")
	if err != nil || v != "1" {
		t.Fatalf("expected v=1, got %q err=%v", v, err)
	}

	v, err = c.Get(ctx, "missing")
	if err != nil || v != "" {
		t.Fatalf("expected zero value for missing key, got %q err=%v", v, err)
	}
}

func TestLRUCacheEviction(t *testing.T) {
	c := NewLRUCache[int](2)
	ctx := context.Background()

	_ = c.Set(ctx, "a", 1, 0)
	_ = c.Set(ctx, "b", 2, 0)
	_ = c.Set(ctx, "c", 3, 0)

	if c.Len() != 2 {
		t.Fatalf("expected len 2, got %d", c.Len())
	}
	if v, _ := c.Get(ctx, "a"); v != 0 {
		t.Fatalf("expected 'a' evicted, got %d", v)
	}
	if v, _ := c.Get(ctx, "c"); v != 3 {
		t.Fatalf("expected 'c' present, got %d", v)
	}
}

func TestLRUCacheTTLExpiry(t *testing.T) {
	c := NewLRUCache[string](10)
	ctx := context.Background()

	_ = c.Set(ctx, "a", "1", 10*time.Millisecond)
	if !c.Exists(ctx, "a") {
		t.Fatalf("expected key to exist before TTL")
	}
	time.Sleep(30 * time.Millisecond)
	if c.Exists(ctx, "a") {
		t.Fatalf("expected key to expire after TTL")
	}
}

func TestLRUCachePointerValue(t *testing.T) {
	type dest struct{ name string }
	c := NewLRUCache[*dest](10)
	ctx := context.Background()

	_ = c.Set(ctx, "x", &dest{name: "direct"}, 0)
	v, err := c.Get(ctx, "x")
	if err != nil || v == nil || v.name != "direct" {
		t.Fatalf("expected pointer round-trip, got %+v err=%v", v, err)
	}

	v, err = c.Get(ctx, "missing")
	if err != nil || v != nil {
		t.Fatalf("expected nil for missing pointer key, got %+v err=%v", v, err)
	}
}

func TestLRUCacheClear(t *testing.T) {
	c := NewLRUCache[int](10)
	ctx := context.Background()
	_ = c.Set(ctx, "a", 1, 0)
	_ = c.Set(ctx, "b", 2, 0)
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("expected len 0 after clear, got %d", c.Len())
	}
}

func TestLRUCacheIncr(t *testing.T) {
	c := NewLRUCache[string](10)
	ctx := context.Background()

	n, err := c.Incr(ctx, "k")
	if err != nil || n != 1 {
		t.Fatalf("expected 1, got %d err=%v", n, err)
	}
	n, err = c.Incr(ctx, "k")
	if err != nil || n != 2 {
		t.Fatalf("expected 2, got %d err=%v", n, err)
	}
}
