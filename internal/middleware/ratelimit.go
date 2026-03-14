package middleware

import (
	"context"
	"fmt"
	"sync"
	"time"

	"whispera/core/router"
)

type RateLimiter interface {
	Allow(key string) bool
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

type SimpleRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	rate     float64
	burst    int
	lastClean time.Time
}

func NewSimpleRateLimiter(rate float64, burst int) *SimpleRateLimiter {
	if rate <= 0 {
		rate = 100
	}
	if burst <= 0 {
		burst = 200
	}
	return &SimpleRateLimiter{
		buckets:   make(map[string]*tokenBucket),
		rate:      rate,
		burst:     burst,
		lastClean: time.Now(),
	}
}

func (l *SimpleRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	if now.Sub(l.lastClean) > 5*time.Minute {
		cutoff := now.Add(-10 * time.Minute)
		for k, b := range l.buckets {
			if b.lastTime.Before(cutoff) {
				delete(l.buckets, k)
			}
		}
		l.lastClean = now
	}

	b, exists := l.buckets[key]
	if !exists {
		b = &tokenBucket{
			tokens:   float64(l.burst),
			lastTime: now,
		}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.lastTime).Seconds()
	b.lastTime = now
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (l *SimpleRateLimiter) SetRate(rate float64, burst int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = rate
	l.burst = burst
}

type EndpointRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	rate     float64
	burst    int
	lastClean time.Time
}

func NewEndpointRateLimiter(rate float64, burst int) *EndpointRateLimiter {
	if rate <= 0 {
		rate = 30
	}
	if burst <= 0 {
		burst = 60
	}
	return &EndpointRateLimiter{
		buckets:   make(map[string]*tokenBucket),
		rate:      rate,
		burst:     burst,
		lastClean: time.Now(),
	}
}

func (l *EndpointRateLimiter) Allow(ip, endpoint string) bool {
	key := ip + "|" + endpoint
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	if now.Sub(l.lastClean) > 5*time.Minute {
		cutoff := now.Add(-10 * time.Minute)
		for k, b := range l.buckets {
			if b.lastTime.Before(cutoff) {
				delete(l.buckets, k)
			}
		}
		l.lastClean = now
	}

	b, exists := l.buckets[key]
	if !exists {
		b = &tokenBucket{
			tokens:   float64(l.burst),
			lastTime: now,
		}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.lastTime).Seconds()
	b.lastTime = now
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

type RateLimitMiddleware struct {
	global   *SimpleRateLimiter
	endpoint *EndpointRateLimiter
}

func NewRateLimitMiddleware(limiter RateLimiter) *RateLimitMiddleware {
	global := NewSimpleRateLimiter(100, 200)
	endpoint := NewEndpointRateLimiter(30, 60)
	if sl, ok := limiter.(*SimpleRateLimiter); ok {
		global = sl
	}
	return &RateLimitMiddleware{
		global:   global,
		endpoint: endpoint,
	}
}

func (m *RateLimitMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	key := req.RemoteAddr.String()

	if !m.global.Allow(key) {
		return &router.Response{
			StatusCode: 429,
			Error:      fmt.Errorf("too many requests"),
		}, nil
	}

	return next.Handle(ctx, req)
}

func (m *RateLimitMiddleware) Name() string {
	return "ratelimit"
}
func (m *RateLimitMiddleware) Priority() int {
	return 15
}
