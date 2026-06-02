package chameleon

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

type loopConn struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (c *loopConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.Read(p)
}
func (c *loopConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.Write(p)
}
func (c *loopConn) Close() error                       { return nil }
func (c *loopConn) LocalAddr() net.Addr                { return nil }
func (c *loopConn) RemoteAddr() net.Addr               { return nil }
func (c *loopConn) SetDeadline(t time.Time) error      { return nil }
func (c *loopConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *loopConn) SetWriteDeadline(t time.Time) error { return nil }

type readOnlyConn struct {
	r *bytes.Reader
}

func (c *readOnlyConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *readOnlyConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *readOnlyConn) Close() error                       { return nil }
func (c *readOnlyConn) LocalAddr() net.Addr                { return nil }
func (c *readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (c *readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (c *readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

func FuzzFrameConnRead(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x06, frameTypeData, 'h', 'e', 'l', 'l', 'o'})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00, 0x3F, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		fc := NewFrameConn(&readOnlyConn{r: bytes.NewReader(data)})
		defer fc.Close()
		tmp := make([]byte, 4096)
		for i := 0; i < 1<<16; i++ {
			n, err := fc.Read(tmp)
			if n < 0 || n > len(tmp) {
				t.Fatalf("Read n=%d out of range", n)
			}
			if err != nil {
				return
			}
		}
	})
}

func FuzzFrameConnRoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte{0xCD}, 70000))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > maxFrameSize-8 {
			return
		}
		fc := NewFrameConn(&loopConn{})
		defer fc.Close()
		if _, err := fc.Write(data); err != nil {
			t.Fatalf("Write: %v", err)
		}
		got := make([]byte, 0, len(data))
		tmp := make([]byte, 8192)
		for len(got) < len(data) {
			n, err := fc.Read(tmp)
			if n > 0 {
				got = append(got, tmp[:n]...)
			}
			if err != nil {
				t.Fatalf("Read err after %d/%d: %v", len(got), len(data), err)
			}
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("round-trip mismatch len got=%d want=%d", len(got), len(data))
		}
	})
}
