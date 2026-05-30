package chameleon

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testConn struct {
	mu          sync.Mutex
	mode        string
	maxPerWrite int
	writeErr    error
	writes      []byte
	writeCount  int32
}

func (c *testConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	atomic.AddInt32(&c.writeCount, 1)
	switch c.mode {
	case "error":
		return 0, c.writeErr
	case "zero":
		return 0, nil
	case "partial":
		n := len(p)
		if c.maxPerWrite > 0 && n > c.maxPerWrite {
			n = c.maxPerWrite
		}
		c.writes = append(c.writes, p[:n]...)
		return n, nil
	default:
		c.writes = append(c.writes, p...)
		return len(p), nil
	}
}

func (c *testConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *testConn) Close() error                       { return nil }
func (c *testConn) LocalAddr() net.Addr                { return nil }
func (c *testConn) RemoteAddr() net.Addr               { return nil }
func (c *testConn) SetDeadline(t time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *testConn) bytesWritten() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

func (c *testConn) syscalls() int32 {
	return atomic.LoadInt32(&c.writeCount)
}

func TestFrameConn_NormalWrite(t *testing.T) {
	tc := &testConn{mode: "normal"}
	fc := NewFrameConn(tc)
	defer fc.Close()

	payload := []byte("hello")
	n, err := fc.Write(payload)
	if err != nil {
		t.Fatalf("Write err: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want %d", n, len(payload))
	}

	want := []byte{0, 0, 0, 6, frameTypeData, 'h', 'e', 'l', 'l', 'o'}
	got := tc.bytesWritten()
	if string(got) != string(want) {
		t.Fatalf("written bytes mismatch:\ngot:  %x\nwant: %x", got, want)
	}
}

func TestFrameConn_PartialWriteRetries(t *testing.T) {
	tc := &testConn{mode: "partial", maxPerWrite: 3}
	fc := NewFrameConn(tc)
	defer fc.Close()

	payload := []byte("hello world!!!")
	n, err := fc.Write(payload)
	if err != nil {
		t.Fatalf("Write err: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want %d", n, len(payload))
	}

	got := tc.bytesWritten()
	if len(got) != 19 {
		t.Fatalf("written %d bytes, want 19; payload truncated despite no err — short-write bug",
			len(got))
	}
	if tc.syscalls() < 2 {
		t.Fatalf("expected >=2 syscalls under partial mode, got %d", tc.syscalls())
	}
}

func TestFrameConn_ZeroWriteReturnsShortWrite(t *testing.T) {
	tc := &testConn{mode: "zero"}
	fc := NewFrameConn(tc)
	defer fc.Close()

	_, err := fc.Write([]byte("hi"))
	if err == nil {
		t.Fatalf("Write returned nil err on zero-write conn — would loop forever")
	}
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected ErrShortWrite, got %v", err)
	}
}

func TestFrameConn_ErrorPropagates(t *testing.T) {
	myErr := errors.New("boom")
	tc := &testConn{mode: "error", writeErr: myErr}
	fc := NewFrameConn(tc)
	defer fc.Close()

	_, err := fc.Write([]byte("hi"))
	if err == nil || err.Error() != "boom" {
		t.Fatalf("expected err 'boom', got %v", err)
	}
}

func TestFrameConn_ConcurrentWritesCoalesce(t *testing.T) {
	tc := &testConn{mode: "normal"}
	fc := NewFrameConn(tc)
	defer fc.Close()

	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			payload := []byte{byte(i)}
			if _, err := fc.Write(payload); err != nil {
				t.Errorf("Write err: %v", err)
			}
		}()
	}
	wg.Wait()

	got := tc.bytesWritten()
	if len(got) != N*6 {
		t.Fatalf("written %d bytes, want %d", len(got), N*6)
	}
	if tc.syscalls() >= N {
		t.Fatalf("no batching: %d syscalls for %d writes (expected <%d)",
			tc.syscalls(), N, N)
	}
	t.Logf("batched %d writes into %d syscalls", N, tc.syscalls())
}

func TestFrameConn_CloseUnblocksPendingSubmit(t *testing.T) {
	blocked := make(chan struct{})
	bc := &blockingConn{block: blocked}

	fc := NewFrameConn(bc)

	errCh := make(chan error, 1)
	go func() {
		_, err := fc.Write([]byte("hi"))
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	fc.Close()
	close(blocked)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected non-nil error after Close, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Write did not unblock after Close")
	}
}

type blockingConn struct {
	block chan struct{}
}

func (c *blockingConn) Write(p []byte) (int, error) {
	<-c.block
	return 0, io.ErrClosedPipe
}
func (c *blockingConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *blockingConn) Close() error                       { return nil }
func (c *blockingConn) LocalAddr() net.Addr                { return nil }
func (c *blockingConn) RemoteAddr() net.Addr               { return nil }
func (c *blockingConn) SetDeadline(t time.Time) error      { return nil }
func (c *blockingConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *blockingConn) SetWriteDeadline(t time.Time) error { return nil }

func TestFrameConn_WriteMultiBufferPartialRetries(t *testing.T) {
	tc := &testConn{mode: "partial", maxPerWrite: 5}
	fc := NewFrameConn(tc)
	defer fc.Close()

	mb := []byte("AAAAAAAAAA")
	if _, err := fc.Write(mb); err != nil {
		t.Fatalf("Write err: %v", err)
	}

	got := tc.bytesWritten()
	if len(got) != 4+1+10 {
		t.Fatalf("written %d bytes, want %d (frame truncated under partial-write)",
			len(got), 4+1+10)
	}
}
