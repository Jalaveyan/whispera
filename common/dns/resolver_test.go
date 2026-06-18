package dns

import (
	"context"
	"net"
	"testing"
)

func TestPositiveCacheServedWithoutQuery(t *testing.T) {
	r := NewResolver(DefaultConfig())
	want := net.IPv4(203, 0, 113, 7)
	_ = r.cache.Set(context.Background(), "host.example", []net.IP{want}, 0)

	ips, err := r.Resolve(context.Background(), "host.example")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("got %v want %v", ips, want)
	}
}

func TestResolveIPLiteral(t *testing.T) {
	r := NewResolver(DefaultConfig())
	ips, err := r.Resolve(context.Background(), "198.51.100.9")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(198, 51, 100, 9)) {
		t.Fatalf("got ips=%v err=%v", ips, err)
	}
}
