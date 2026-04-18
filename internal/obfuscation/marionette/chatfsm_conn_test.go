package marionette

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"whispera/internal/obfuscation/behavioral"
)

// loopbackPair returns two connected TCP loopback conns. Used instead of
// net.Pipe because pipe is fully synchronous, which deadlocks against the
// bidirectional cover loops both peers run.
func loopbackPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return a, r.c
}

// TestChatFSMConn_RoundTrip wires two ChatFSMConn instances back-to-back over
// loopback TCP and verifies that:
//   - app payload bytes round-trip exactly,
//   - cover frames emitted by the peer are silently dropped on read,
//   - large payloads (>1 frame) are reassembled across multiple Read calls.
func TestChatFSMConn_RoundTrip(t *testing.T) {
	a, b := loopbackPair(t)
	defer a.Close()
	defer b.Close()

	clientSide := NewChatFSMConn(a, 0xCAFEBABE, 50*time.Millisecond)
	serverSide := NewChatFSMConn(b, 0xDEADBEEF, 50*time.Millisecond)
	defer clientSide.Close()
	defer serverSide.Close()

	payloads := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, maxFramePayload+1234), // forces split across frames
		[]byte("trailing"),
	}

	// Drain reverse direction so serverSide cover frames don't accumulate
	// in the kernel send buffer. We don't care about results — just consume.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		buf := make([]byte, 4096)
		for {
			if _, err := clientSide.Read(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		for _, p := range payloads {
			if _, err := clientSide.Write(p); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i, want := range payloads {
		got := make([]byte, 0, len(want))
		buf := make([]byte, 32*1024)
		for len(got) < len(want) {
			n, err := serverSide.Read(buf)
			if err != nil {
				t.Fatalf("payload %d: read: %v", i, err)
			}
			got = append(got, buf[:n]...)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("payload %d: mismatch (len got=%d want=%d)", i, len(got), len(want))
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("write goroutine: %v", err)
	}
}

func TestChatFSMConn_ClosePropagates(t *testing.T) {
	a, b := loopbackPair(t)
	c1 := NewChatFSMConn(a, 1, 0)
	c2 := NewChatFSMConn(b, 2, 0)
	defer c2.Close()

	if err := c1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	buf := make([]byte, 16)
	_, err := c2.Read(buf)
	if err != io.EOF && err != io.ErrClosedPipe {
		// On TCP the peer-close manifests as a generic read error
		// (connection reset / EOF). Accept any non-nil error.
		if err == nil {
			t.Fatalf("expected error after peer close, got nil")
		}
	}
}

// TestChatFSMConn_LiveProfileSwap verifies the live-reconfig contract:
// after SetProfile() on an open connection, the new profile takes effect
// without losing data in flight or breaking the framing layer. Mirrors how
// the panel/ML profiler will switch a tunnel from VK-messenger to Spotify
// mid-session to dodge a classifier.
func TestChatFSMConn_LiveProfileSwap(t *testing.T) {
	a, b := loopbackPair(t)
	defer a.Close()
	defer b.Close()

	clientSide := NewChatFSMConn(a, 0xCAFEBABE, 30*time.Millisecond)
	serverSide := NewChatFSMConn(b, 0xDEADBEEF, 30*time.Millisecond)
	defer clientSide.Close()
	defer serverSide.Close()

	// Verify both are in the live registry.
	if got := LiveCount(); got < 2 {
		t.Fatalf("LiveCount: want >=2, got %d", got)
	}
	if LiveConnByID(clientSide.ID()) != clientSide {
		t.Fatal("LiveConnByID lookup failed for clientSide")
	}

	// Reverse-direction drainer.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		buf := make([]byte, 4096)
		for {
			if _, err := clientSide.Read(buf); err != nil {
				return
			}
		}
	}()

	// Phase 1: write payload under VK profile (default).
	want1 := bytes.Repeat([]byte{0x11}, 8192)
	writeErr := make(chan error, 1)
	go func() {
		_, err := clientSide.Write(want1)
		writeErr <- err
	}()

	got := make([]byte, 0, len(want1))
	buf := make([]byte, 4096)
	for len(got) < len(want1) {
		n, err := serverSide.Read(buf)
		if err != nil {
			t.Fatalf("phase1 read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want1) {
		t.Fatal("phase1: payload mismatch")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("phase1 write: %v", err)
	}

	// Live swap: switch to Spotify (streaming) profile mid-connection.
	clientSide.SetProfile(behavioral.SpotifyProfile())
	serverSide.SetProfile(behavioral.SpotifyProfile())

	// Phase 2: write another payload — must still round-trip exactly.
	want2 := bytes.Repeat([]byte{0x22}, 4096)
	go func() {
		_, err := clientSide.Write(want2)
		writeErr <- err
	}()

	got = got[:0]
	for len(got) < len(want2) {
		n, err := serverSide.Read(buf)
		if err != nil {
			t.Fatalf("phase2 read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want2) {
		t.Fatal("phase2: payload mismatch after profile swap")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("phase2 write: %v", err)
	}
}

// TestChatFSMConn_LiveCoverToggle verifies SetCoverEnabled works on a
// running connection — toggling cover off then back on should not affect
// data round-trip.
func TestChatFSMConn_LiveCoverToggle(t *testing.T) {
	a, b := loopbackPair(t)
	defer a.Close()
	defer b.Close()

	c1 := NewChatFSMConn(a, 1, 30*time.Millisecond)
	c2 := NewChatFSMConn(b, 2, 30*time.Millisecond)
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := c1.Read(buf); err != nil {
				return
			}
		}
	}()

	// Disable cover, write data, ensure round-trip.
	c1.SetCoverEnabled(false)
	c2.SetCoverEnabled(false)
	time.Sleep(50 * time.Millisecond) // let loops settle

	want := []byte("cover-off-payload")
	go c1.Write(want)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c2, got); err != nil {
		t.Fatalf("read with cover off: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("data mismatch with cover off")
	}

	// Re-enable cover, write again, ensure still works.
	c1.SetCoverEnabled(true)
	c2.SetCoverEnabled(true)
	time.Sleep(50 * time.Millisecond)

	want2 := []byte("cover-back-on")
	go c1.Write(want2)
	got2 := make([]byte, len(want2))
	if _, err := io.ReadFull(c2, got2); err != nil {
		t.Fatalf("read with cover on: %v", err)
	}
	if !bytes.Equal(got2, want2) {
		t.Fatal("data mismatch with cover re-enabled")
	}
}

// TestBroadcastSetProfile verifies that BroadcastSetProfile reaches every
// registered live connection in one call.
func TestBroadcastSetProfile(t *testing.T) {
	a, b := loopbackPair(t)
	defer a.Close()
	defer b.Close()

	c1 := NewChatFSMConn(a, 1, 0) // cover off — we only test profile swap
	c2 := NewChatFSMConn(b, 2, 0)
	defer c1.Close()
	defer c2.Close()

	tg := behavioral.TelegramProfile()
	updated := BroadcastSetProfile(tg)
	if updated < 2 {
		t.Fatalf("BroadcastSetProfile: want updates >=2, got %d", updated)
	}

	if c1.profile().Name != tg.Name {
		t.Fatalf("c1 profile not swapped: got %q, want %q", c1.profile().Name, tg.Name)
	}
	if c2.profile().Name != tg.Name {
		t.Fatalf("c2 profile not swapped: got %q, want %q", c2.profile().Name, tg.Name)
	}
}
