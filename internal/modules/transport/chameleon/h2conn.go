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

// bufferedPipeWriter wraps an io.PipeWriter with an async buffer so that
// Write returns immediately even before the pipe reader goroutine starts.
// On Android the HTTP/2 request-body goroutine can take 30-44s to schedule;
// without buffering yamux blocks on the very first SYN frame.
type bufferedPipeWriter struct {
	pw   *io.PipeWriter
	ch   chan []byte
	done chan struct{}
	once sync.Once
}

func newBufferedPipeWriter(pw *io.PipeWriter) *bufferedPipeWriter {
	b := &bufferedPipeWriter{
		pw:   pw,
		ch:   make(chan []byte, 1024),
		done: make(chan struct{}),
	}
	go b.drain()
	return b
}

func (b *bufferedPipeWriter) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case b.ch <- cp:
		return len(p), nil
	case <-b.done:
		return 0, io.ErrClosedPipe
	}
}

func (b *bufferedPipeWriter) Close() {
	b.once.Do(func() { close(b.done) })
}

func (b *bufferedPipeWriter) drain() {
	defer b.pw.Close()
	var coalesce []byte
	for {
		select {
		case data := <-b.ch:
			coalesce = append(coalesce, data...)
		drain:
			for {
				select {
				case more := <-b.ch:
					coalesce = append(coalesce, more...)
				default:
					break drain
				}
			}
			if _, err := b.pw.Write(coalesce); err != nil {
				return
			}
			coalesce = coalesce[:0]
		case <-b.done:
			return
		}
	}
}

// pipelinedConn is the client-side H2 tunnel conn.
// Write path (bpw → POST body) is live immediately; Read path blocks until
// deliver() is called with the HTTP response body — allowing yamux SETTINGS
// to be sent before the server's 200 OK arrives, saving one RTT.
type pipelinedConn struct {
	bpw    *bufferedPipeWriter
	pr     *io.PipeReader
	cancel func()
	once   sync.Once
	sig    sync.Once

	bodyCh chan io.ReadCloser
	body   io.ReadCloser
	buf    []byte

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newPipelinedConn(pr *io.PipeReader, bpw *bufferedPipeWriter, cancel func(), local, remote net.Addr) *pipelinedConn {
	return &pipelinedConn{
		pr:         pr,
		bpw:        bpw,
		cancel:     cancel,
		bodyCh:     make(chan io.ReadCloser, 1),
		localAddr:  local,
		remoteAddr: remote,
	}
}

// deliver hands resp.Body to the Read path. Returns false if Close already ran first.
func (c *pipelinedConn) deliver(body io.ReadCloser) bool {
	ran := false
	c.sig.Do(func() { c.bodyCh <- body; ran = true })
	return ran
}

func (c *pipelinedConn) Write(b []byte) (int, error) { return c.bpw.Write(b) }

func (c *pipelinedConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	if c.body == nil {
		body := <-c.bodyCh
		if body == nil {
			return 0, io.ErrClosedPipe
		}
		c.body = body
	}
	return c.body.Read(b)
}

func (c *pipelinedConn) Close() error {
	c.once.Do(func() {
		c.bpw.Close()
		c.pr.Close()
		c.sig.Do(func() { c.bodyCh <- nil })
		if c.body != nil {
			c.body.Close()
		}
		c.cancel()
	})
	return nil
}

func (c *pipelinedConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *pipelinedConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *pipelinedConn) SetDeadline(t time.Time) error      { return nil }
func (c *pipelinedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pipelinedConn) SetWriteDeadline(t time.Time) error { return nil }

// staticAddr is a minimal net.Addr for wrapping host:port strings.
type staticAddr struct{ network, addr string }

func (a staticAddr) Network() string { return a.network }
func (a staticAddr) String() string  { return a.addr }
