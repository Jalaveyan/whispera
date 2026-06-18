package router

import (
	"context"
	"net"
	"testing"

	"whispera/common/runtime/interfaces"
)

func TestRouteCachesDestinationAcrossCalls(t *testing.T) {
	e, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := e.AddRule(interfaces.RoutingRule{
		ID:       "block-1.2.3.4",
		Priority: 10,
		Conditions: []interfaces.RuleCondition{
			{Field: "dst_ip", Operator: "eq", Value: "1.2.3.4"},
		},
		Destination: interfaces.Destination{Type: interfaces.DestinationBlock},
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	packet := &interfaces.Packet{
		DstAddr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443},
	}

	ctx := context.Background()
	dest, err := e.Route(ctx, packet)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dest.Type != interfaces.DestinationBlock {
		t.Fatalf("expected block on first route, got %v", dest.Type)
	}

	stats := e.GetStats()
	if stats.CacheMisses == 0 {
		t.Fatalf("expected at least one cache miss on first call")
	}

	dest2, err := e.Route(ctx, packet)
	if err != nil {
		t.Fatalf("Route (cached): %v", err)
	}
	if dest2.Type != interfaces.DestinationBlock {
		t.Fatalf("expected block on cached route, got %v", dest2.Type)
	}

	stats2 := e.GetStats()
	if stats2.CacheHits == 0 {
		t.Fatalf("expected at least one cache hit on second call, stats=%+v", stats2)
	}
}
