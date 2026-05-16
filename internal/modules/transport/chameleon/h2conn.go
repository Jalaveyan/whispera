package chameleon

import (
	"io"
	"net"
	"sync"
	"time"
)

// h2ServerConn adapts an HTTP/2 handler's request body + response writer
// into a net.Conn so the rest of the stack (FrameConn, shapedConn) can sit on top.
//
// Read  ← request body  (client → server)
// Write → response body (server → client), flushed after every write
type h2ServerConn struct {
	r       io.ReadCloser
	w       io.Writer
	flush   func()
	done    chan struct{}
	once    sync.Once
	onClose func()

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newH2ServerConn(body io.ReadCloser, w io.Writer, flush func(), local, remote net.Addr, onClose func()) *h2ServerConn {
	return &h2ServerConn{
		r:          body,
		w:          w,
		flush:      flush,
		done:       make(chan struct{}),
		onClose:    onClose,
		localAddr:  local,
		remoteAddr: remote,
	}
}

func (c *h2ServerConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *h2ServerConn) Write(b []byte) (n int, err error) {
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, io.ErrClosedPipe
		}
	}()
	n, err = c.w.Write(b)
	if err == nil && n > 0 {
		c.flush()
	}
	return n, err
}

func (c *h2ServerConn) Close() error {
	c.once.Do(func() {
		c.r.Close()
		close(c.done)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *h2ServerConn) Done() <-chan struct{} { return c.done }

func (c *h2ServerConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *h2ServerConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *h2ServerConn) SetDeadline(t time.Time) error      { return nil }
func (c *h2ServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *h2ServerConn) SetWriteDeadline(t time.Time) error { return nil }

// h2ClientConn adapts a bidirectional HTTP/2 stream into a net.Conn.
//
// Write → request body pipe (client → server)
// Read  ← response body   (server → client)
type h2ClientConn struct {
	pr     *io.PipeReader
	pw     *io.PipeWriter
	resp   io.ReadCloser
	cancel func()
	once   sync.Once

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newH2ClientConn(pr *io.PipeReader, pw *io.PipeWriter, resp io.ReadCloser, cancel func(), local, remote net.Addr) *h2ClientConn {
	return &h2ClientConn{
		pr:         pr,
		pw:         pw,
		resp:       resp,
		cancel:     cancel,
		localAddr:  local,
		remoteAddr: remote,
	}
}

func (c *h2ClientConn) Read(b []byte) (int, error) { return c.resp.Read(b) }
func (c *h2ClientConn) Write(b []byte) (int, error) {
	t0 := time.Now()
	n, err := c.pw.Write(b)
	if d := time.Since(t0); d > 100*time.Millisecond {
		log.Printf("chameleon: h2 pipe write %d bytes blocked %v", len(b), d)
	}
	return n, err
}

func (c *h2ClientConn) Close() error {
	c.once.Do(func() {
		c.pw.Close()
		c.resp.Close()
		if c.cancel != nil {
			c.cancel()
		}
	})
	return nil
}

func (c *h2ClientConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *h2ClientConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *h2ClientConn) SetDeadline(t time.Time) error      { return nil }
func (c *h2ClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *h2ClientConn) SetWriteDeadline(t time.Time) error { return nil }

// staticAddr is a minimal net.Addr for wrapping host:port strings.
type staticAddr struct{ network, addr string }

func (a staticAddr) Network() string { return a.network }
func (a staticAddr) String() string  { return a.addr }
