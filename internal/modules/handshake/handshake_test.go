package handshake

import (
	"context"
	"testing"
	"time"
)

type hsTestAddr struct{}

func (hsTestAddr) Network() string { return "udp" }
func (hsTestAddr) String() string  { return "203.0.113.7:443" }

func permissiveHandler(t *testing.T) *Handler {
	t.Helper()
	h, err := New(&Config{
		RateLimit:        1e12,
		RateBurst:        1 << 30,
		Timeout:          time.Second,
		MaxPending:       1000,
		EnableAntiReplay: false,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func TestHandleHandshake_RejectsBadSize(t *testing.T) {
	h := permissiveHandler(t)
	ctx := context.Background()
	if _, err := h.HandleHandshake(ctx, make([]byte, HandshakeMinSize-1), hsTestAddr{}); err == nil {
		t.Fatalf("expected error on too-short handshake")
	}
	if _, err := h.HandleHandshake(ctx, make([]byte, HandshakeMaxSize+1), hsTestAddr{}); err == nil {
		t.Fatalf("expected error on too-long handshake")
	}
}

func TestHandleHandshake_NoDepsReturnsError(t *testing.T) {
	h := permissiveHandler(t)
	for _, typ := range []HandshakeType{HandshakeTypeInit, HandshakeTypeRekey} {
		data := make([]byte, HandshakeMinSize)
		data[0] = byte(typ)
		sess, err := h.HandleHandshake(context.Background(), data, hsTestAddr{})
		if err == nil {
			t.Fatalf("type %d: expected error without dependencies, got session %v", typ, sess)
		}
		if sess != nil {
			t.Fatalf("type %d: session must be nil on error", typ)
		}
	}
}

func FuzzHandleHandshake(f *testing.F) {
	f.Add(make([]byte, HandshakeMinSize))
	initPkt := make([]byte, HandshakeMinSize)
	initPkt[0] = byte(HandshakeTypeInit)
	f.Add(initPkt)
	rekeyPkt := make([]byte, HandshakeMinSize)
	rekeyPkt[0] = byte(HandshakeTypeRekey)
	f.Add(rekeyPkt)
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := permissiveHandler(t)
		sess, err := h.HandleHandshake(context.Background(), data, hsTestAddr{})
		if err == nil && sess == nil {
			t.Fatalf("nil error with nil session — contract violation")
		}
	})
}
