package cache

import (
	"context"
	"time"
)

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)

	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	Delete(ctx context.Context, key string) error

	Exists(ctx context.Context, key string) bool

	Incr(ctx context.Context, key string) (int64, error)

	IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error)

	Close() error

	Ping(ctx context.Context) error

	Type() string
}
