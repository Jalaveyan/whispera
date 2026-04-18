package tunnel

import (
	"context"
	"net"
	"testing"
)

func dummy(_ context.Context) (net.Conn, error) { return nil, nil }

func TestApplyTransportPolicy_Whitelist(t *testing.T) {
	m := &Manager{config: &Config{TransportWhitelist: []string{"tcp", "quic"}}}
	out := m.applyTransportPolicy([]dialCandidate{
		{name: "tcp", fn: dummy},
		{name: "websocket", fn: dummy},
		{name: "quic", fn: dummy},
		{name: "russian:gosuslugi", fn: dummy},
	})
	if len(out) != 2 {
		t.Fatalf("want 2 entries (tcp+quic), got %d: %v", len(out), names(out))
	}
}

func TestApplyTransportPolicy_Blacklist(t *testing.T) {
	m := &Manager{config: &Config{TransportBlacklist: []string{"snowflake", "russian"}}}
	out := m.applyTransportPolicy([]dialCandidate{
		{name: "tcp", fn: dummy},
		{name: "snowflake", fn: dummy},
		{name: "russian:antizapret", fn: dummy},
	})
	if len(out) != 1 || out[0].name != "tcp" {
		t.Fatalf("want only tcp, got %v", names(out))
	}
}

func TestApplyTransportPolicy_None(t *testing.T) {
	m := &Manager{config: &Config{}}
	in := []dialCandidate{{name: "tcp", fn: dummy}, {name: "ws", fn: dummy}}
	if out := m.applyTransportPolicy(in); len(out) != 2 {
		t.Fatalf("policy with empty lists must be no-op, got %v", names(out))
	}
}

func names(cc []dialCandidate) []string {
	n := make([]string, len(cc))
	for i, c := range cc {
		n[i] = c.name
	}
	return n
}
