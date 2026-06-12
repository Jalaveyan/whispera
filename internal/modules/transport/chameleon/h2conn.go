package chameleon

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/buf"
)

type bufferedPipeWriter struct {
	pw   *io.PipeWriter
	ch   chan *buf.Buffer
	done chan struct{}
	once sync.Once
}

func newBufferedPipeWriter(pw *io.PipeWriter) *bufferedPipeWriter {
	b := &bufferedPipeWriter{
		pw:   pw,
		ch:   make(chan *buf.Buffer, 1024),
		done: make(chan struct{}),
	}
	go b.drain()
	return b
}

func (bw *bufferedPipeWriter) Write(p []byte) (int, error) {
	b := buf.NewSize(len(p))
	b.Write(p)
	select {
	case bw.ch <- b:
		return len(p), nil
	case <-bw.done:
		b.Release()
		return 0, io.ErrClosedPipe
	}
}

func (bw *bufferedPipeWriter) Close() {
	bw.once.Do(func() { close(bw.done) })
}

func (bw *bufferedPipeWriter) drain() {
	defer bw.pw.Close()
	var pending buf.MultiBuffer
	for {
		select {
		case b := <-bw.ch:
			pending = append(pending, b)
		drainLoop:
			for {
				select {
				case more := <-bw.ch:
					pending = append(pending, more)
				default:
					break drainLoop
				}
			}
			for _, b := range pending {
				if _, err := bw.pw.Write(b.Bytes()); err != nil {
					buf.ReleaseMulti(pending)
					return
				}
			}
			pending = buf.ReleaseMulti(pending)
		case <-bw.done:
			buf.ReleaseMulti(pending)
			return
		}
	}
}

type pipelinedConn struct {
	bpw    *bufferedPipeWriter
	pr     *io.PipeReader
	cancel func()
	once   sync.Once
	sig    sync.Once

	bodyReady chan struct{}
	body      io.ReadCloser

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newPipelinedConn(pr *io.PipeReader, bpw *bufferedPipeWriter, cancel func(), local, remote net.Addr) *pipelinedConn {
	return &pipelinedConn{
		pr:         pr,
		bpw:        bpw,
		cancel:     cancel,
		bodyReady:  make(chan struct{}),
		localAddr:  local,
		remoteAddr: remote,
	}
}

func (c *pipelinedConn) deliver(body io.ReadCloser) bool {
	ran := false
	c.sig.Do(func() {
		ran = true
		c.body = body
		close(c.bodyReady)
	})
	return ran
}

func (c *pipelinedConn) Write(b []byte) (int, error) { return c.bpw.Write(b) }

func (c *pipelinedConn) Read(b []byte) (int, error) {
	<-c.bodyReady
	if c.body == nil {
		return 0, io.EOF
	}
	return c.body.Read(b)
}

func (c *pipelinedConn) Close() error {
	c.once.Do(func() {
		c.bpw.Close()
		c.pr.Close()
		c.cancel()
		c.sig.Do(func() { close(c.bodyReady) })
		if c.body != nil {
			c.body.Close()
		}
	})
	return nil
}

func (c *pipelinedConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *pipelinedConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *pipelinedConn) SetDeadline(t time.Time) error      { return nil }
func (c *pipelinedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pipelinedConn) SetWriteDeadline(t time.Time) error { return nil }

type staticAddr struct{ network, addr string }

func (a staticAddr) Network() string { return a.network }
func (a staticAddr) String() string  { return a.addr }

type httpStreamConn struct {
	r      io.Reader
	w      http.ResponseWriter
	flush  func()
	local  net.Addr
	remote net.Addr
	done   chan struct{}
	once   sync.Once

	upBytes   int64
	downBytes int64
}

func newHTTPStreamConn(r io.Reader, w http.ResponseWriter, flush func(), local, remote net.Addr, _ GANDecideFunc) *httpStreamConn {
	return &httpStreamConn{r: r, w: w, flush: flush, local: local, remote: remote, done: make(chan struct{})}
}

func (c *httpStreamConn) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.upBytes, int64(n))
	}
	if err != nil {
		up := atomic.LoadInt64(&c.upBytes)
		if err != io.EOF || up < 64 {
			traceLog.Warnw("server_post_body_read_err",
				"remote", c.remote.String(),
				"up_bytes", up,
				"err", err.Error(),
				"err_type", fmt.Sprintf("%T", err),
			)
		}
	}
	return n, err
}

func (c *httpStreamConn) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	if n > 0 {
		atomic.AddInt64(&c.downBytes, int64(n))
	}
	if err == nil {
		c.flush()
	}
	return n, err
}
func (c *httpStreamConn) FlushWrite() {
	c.flush()
}
func (c *httpStreamConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}
func (c *httpStreamConn) LocalAddr() net.Addr                { return c.local }
func (c *httpStreamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *httpStreamConn) SetDeadline(t time.Time) error      { return nil }
func (c *httpStreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *httpStreamConn) SetWriteDeadline(t time.Time) error { return nil }
