package bond

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type delayConn struct {
	net.Conn
	delay time.Duration
}

func (d *delayConn) Write(p []byte) (int, error) {
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	return d.Conn.Write(p)
}

func newBondPair(n int, delays []time.Duration) (*Conn, *Conn) {
	var id bondID
	id[0] = 0x7E
	var a, b *Conn
	for i := 0; i < n; i++ {
		ca, cb := net.Pipe()
		var am net.Conn = ca
		if delays != nil && delays[i] > 0 {
			am = &delayConn{Conn: ca, delay: delays[i]}
		}
		if i == 0 {
			a = newConn(id, am)
			b = newConn(id, cb)
		} else {
			a.AddMember(am)
			b.AddMember(cb)
		}
	}
	return a, b
}

func TestBondRoundTrip(t *testing.T) {
	a, b := newBondPair(4, nil)
	defer a.Close()
	defer b.Close()

	msg := bytes.Repeat([]byte("hello bonded world spanning several chunks "), 4096)
	go func() {
		if _, err := a.Write(msg); err != nil {
			t.Errorf("write: %v", err)
		}
	}()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("payload mismatch")
	}
}

func TestBondSingleMember(t *testing.T) {
	a, b := newBondPair(1, nil)
	defer a.Close()
	defer b.Close()
	if a.Width() != 1 {
		t.Fatalf("width=%d", a.Width())
	}
	msg := bytes.Repeat([]byte("single-member-bond "), 1000)
	go a.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("mismatch")
	}
}

func TestBondLargeReorder(t *testing.T) {
	a, b := newBondPair(3, []time.Duration{0, 5 * time.Millisecond, 15 * time.Millisecond})
	defer a.Close()
	defer b.Close()

	src := make([]byte, 512*1024)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := a.Write(src)
		done <- err
	}()

	got := make([]byte, len(src))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, src) {
		t.Fatal("payload mismatch under reordering")
	}
}

func TestBondBidirectional(t *testing.T) {
	a, b := newBondPair(4, []time.Duration{0, 3 * time.Millisecond, 0, 7 * time.Millisecond})
	defer a.Close()
	defer b.Close()

	msgA := bytes.Repeat([]byte("AAAA"), 200000)
	msgB := bytes.Repeat([]byte("BBBB"), 200000)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.Write(msgA) }()
	go func() { defer wg.Done(); b.Write(msgB) }()

	gotB := make([]byte, len(msgA))
	gotA := make([]byte, len(msgB))
	var rg sync.WaitGroup
	rg.Add(2)
	go func() { defer rg.Done(); io.ReadFull(b, gotB) }()
	go func() { defer rg.Done(); io.ReadFull(a, gotA) }()
	rg.Wait()
	wg.Wait()

	if !bytes.Equal(gotB, msgA) {
		t.Fatal("A->B mismatch")
	}
	if !bytes.Equal(gotA, msgB) {
		t.Fatal("B->A mismatch")
	}
}

func TestBondPartialReads(t *testing.T) {
	a, b := newBondPair(2, nil)
	defer a.Close()
	defer b.Close()

	msg := []byte("0123456789abcdefghij")
	go func() { a.Write(msg) }()

	var out []byte
	tmp := make([]byte, 3)
	for len(out) < len(msg) {
		n, err := b.Read(tmp)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		out = append(out, tmp[:n]...)
	}
	if !bytes.Equal(out, msg) {
		t.Fatalf("got %q want %q", out, msg)
	}
}

func TestBondCloseEOF(t *testing.T) {
	a, b := newBondPair(2, nil)

	msg := []byte("final bytes")
	go func() {
		a.Write(msg)
		a.Close()
	}()

	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q want %q", got, msg)
	}
	b.Close()
}

func TestReordererGapsAndDups(t *testing.T) {
	r := newReorderer(1 << 20)
	r.push(2, []byte("c"))
	r.push(0, []byte("a"))
	r.push(1, []byte("b"))
	r.push(1, []byte("X"))
	r.push(2, []byte("Y"))
	r.setClosed(nil)

	var out []byte
	buf := make([]byte, 1)
	for {
		n, err := r.read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if string(out) != "abc" {
		t.Fatalf("got %q want abc", out)
	}
}
