package bond

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandshakeCodec(t *testing.T) {
	ca, cb := net.Pipe()
	var id bondID
	for i := range id {
		id[i] = byte(i + 1)
	}
	go func() { writeHandshake(ca, id) }()
	gotID, err := readHandshake(cb)
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if gotID != id {
		t.Fatalf("id mismatch: %v want %v", gotID, id)
	}
}

func TestHandshakeBadMagic(t *testing.T) {
	ca, cb := net.Pipe()
	go func() { ca.Write(bytes.Repeat([]byte{0xFF}, handshakeSize)) }()
	if _, err := readHandshake(cb); err != ErrBadHandshake {
		t.Fatalf("want ErrBadHandshake, got %v", err)
	}
}

func TestPairingDynamicGrowth(t *testing.T) {
	const n = 4
	cas := make([]net.Conn, n)
	cbs := make([]net.Conn, n)
	for i := 0; i < n; i++ {
		cas[i], cbs[i] = net.Pipe()
	}
	var di int32
	dialOne := func(ctx context.Context) (net.Conn, error) {
		i := atomic.AddInt32(&di, 1) - 1
		return cas[i], nil
	}

	co := NewCoordinator()
	serverBondCh := make(chan *Conn, 1)
	go func() {
		b, legacy, err := co.Offer(cbs[0])
		if err != nil || b == nil || legacy != nil {
			t.Errorf("offer0: b=%v legacy=%v err=%v", b, legacy, err)
			return
		}
		serverBondCh <- b
		for i := 1; i < n; i++ {
			b, legacy, err := co.Offer(cbs[i])
			if err != nil || b != nil || legacy != nil {
				t.Errorf("offer%d should attach: b=%v legacy=%v err=%v", i, b, legacy, err)
			}
		}
	}()

	clientBond, err := Dial(context.Background(), dialOne)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientBond.Close()

	var serverBond *Conn
	select {
	case serverBond = <-serverBondCh:
	case <-time.After(3 * time.Second):
		t.Fatal("server bond not created")
	}
	defer serverBond.Close()

	for i := 1; i < n; i++ {
		if err := clientBond.Grow(context.Background(), dialOne); err != nil {
			t.Fatalf("grow %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for serverBond.Width() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if clientBond.Width() != n || serverBond.Width() != n {
		t.Fatalf("width client=%d server=%d want %d", clientBond.Width(), serverBond.Width(), n)
	}

	msg := bytes.Repeat([]byte("striped-after-growth-"), 8000)
	go func() {
		clientBond.Write(msg)
		clientBond.Close()
	}()
	got, err := io.ReadAll(serverBond)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("payload mismatch across grown bond")
	}
}

func TestOfferLegacyFallback(t *testing.T) {
	ca, cb := net.Pipe()
	co := NewCoordinator()

	legacyMsg := []byte("not-a-bond-handshake-just-mux-bytes-following-here")
	go func() {
		ca.Write(legacyMsg)
		ca.Close()
	}()

	b, legacy, err := co.Offer(cb)
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	if b != nil || legacy == nil {
		t.Fatalf("expected legacy passthrough, got b=%v legacy=%v", b, legacy)
	}
	got, err := io.ReadAll(legacy)
	if err != nil {
		t.Fatalf("read legacy: %v", err)
	}
	if !bytes.Equal(got, legacyMsg) {
		t.Fatalf("legacy bytes corrupted: got %q want %q", got, legacyMsg)
	}
}

func TestPairingRegistryCleanup(t *testing.T) {
	ca, cb := net.Pipe()
	co := NewCoordinator()
	dialOne := func(ctx context.Context) (net.Conn, error) { return ca, nil }

	go func() {
		b, _, err := co.Offer(cb)
		if err != nil || b == nil {
			t.Errorf("offer: b=%v err=%v", b, err)
			return
		}
		b.Close()
	}()

	clientBond, err := Dial(context.Background(), dialOne)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	clientBond.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		co.mu.Lock()
		nLive := len(co.live)
		co.mu.Unlock()
		if nLive == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("live bond not cleaned up after close")
}
