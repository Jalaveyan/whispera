package buf

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayCopiesAndCloses(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	relayDone := make(chan struct{})
	go func() { Relay(a2, b2, nil, nil); close(relayDone) }()

	go func() {
		a1.Write([]byte("hello"))
		a1.Close()
	}()

	b1.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, _ := io.ReadAll(b1)
	if string(got) != "hello" {
		t.Fatalf("relay a->b: got %q", got)
	}

	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not terminate after peer close")
	}
}
