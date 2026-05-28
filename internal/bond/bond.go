package bond

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	hdrSize         = 12
	maxChunk        = 32 * 1024
	defaultBudget   = 16 * 1024 * 1024
	writeQueueDepth = 64
	flushTimeout    = 2 * time.Second
	maxBondMembers  = 32
)

var ErrClosed = errors.New("bond: closed")

var framePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, hdrSize+maxChunk)
		return &b
	},
}

func frameGet() *[]byte {
	bp := framePool.Get().(*[]byte)
	*bp = (*bp)[:cap(*bp)]
	return bp
}

func framePut(bp *[]byte) {
	if bp == nil {
		return
	}
	framePool.Put(bp)
}

type Conn struct {
	id bondID

	mu      sync.Mutex
	members [maxBondMembers]net.Conn
	wq      [maxBondMembers]chan *[]byte
	n       int32

	writeMu sync.Mutex
	nextSeq uint64

	ro *reorderer

	closeOnce sync.Once
	closed    chan struct{}
	err       atomic.Value
	writerWg  sync.WaitGroup
}

func newConn(id bondID, first net.Conn) *Conn {
	c := &Conn{
		id:     id,
		closed: make(chan struct{}),
		ro:     newReorderer(defaultBudget),
	}
	c.AddMember(first)
	return c
}

func (c *Conn) AddMember(m net.Conn) bool {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		m.Close()
		return false
	default:
	}
	i := int(c.n)
	if i >= maxBondMembers {
		c.mu.Unlock()
		m.Close()
		return false
	}
	c.members[i] = m
	c.wq[i] = make(chan *[]byte, writeQueueDepth)
	c.writerWg.Add(1)
	atomic.StoreInt32(&c.n, int32(i+1))
	c.mu.Unlock()
	go c.writeLoop(i)
	go c.readLoop(i)
	return true
}

func (c *Conn) Width() int { return int(atomic.LoadInt32(&c.n)) }

func (c *Conn) Done() <-chan struct{} { return c.closed }

func (c *Conn) ID() bondID { return c.id }

func (c *Conn) loadErr() error {
	if e, ok := c.err.Load().(error); ok && e != nil {
		return e
	}
	return ErrClosed
}

func (c *Conn) setErr(err error) { _ = c.shutdown(err, false) }

func (c *Conn) Close() error { return c.shutdown(nil, true) }

func (c *Conn) shutdown(err error, graceful bool) error {
	first := false
	c.closeOnce.Do(func() {
		first = true
		if err != nil {
			c.err.Store(err)
		}
		close(c.closed)
	})
	if !first {
		return nil
	}
	if graceful {
		done := make(chan struct{})
		go func() { c.writerWg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(flushTimeout):
		}
	}
	c.ro.setClosed(c.loadErr())
	c.mu.Lock()
	n := int(c.n)
	c.mu.Unlock()
	for i := 0; i < n; i++ {
		if c.members[i] != nil {
			c.members[i].Close()
		}
	}
	return nil
}

func (c *Conn) writeLoop(i int) {
	defer c.writerWg.Done()
	m := c.members[i]
	q := c.wq[i]
	write := func(bp *[]byte) bool {
		_, err := m.Write(*bp)
		framePut(bp)
		if err != nil {
			c.setErr(err)
			return false
		}
		return true
	}
	for {
		select {
		case bp := <-q:
			if !write(bp) {
				return
			}
		case <-c.closed:
			for {
				select {
				case bp := <-q:
					if !write(bp) {
						return
					}
				default:
					return
				}
			}
		}
	}
}

func (c *Conn) readLoop(i int) {
	m := c.members[i]
	var hdr [hdrSize]byte
	for {
		if _, err := io.ReadFull(m, hdr[:]); err != nil {
			c.setErr(err)
			return
		}
		seq := binary.BigEndian.Uint64(hdr[0:8])
		ln := binary.BigEndian.Uint32(hdr[8:12])
		bp := frameGet()
		data := (*bp)[:ln]
		if ln > 0 {
			if _, err := io.ReadFull(m, data); err != nil {
				framePut(bp)
				c.setErr(err)
				return
			}
		}
		if !c.ro.push(seq, data, bp) {
			framePut(bp)
			return
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.closed:
		return 0, c.loadErr()
	default:
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		seq := c.nextSeq
		c.nextSeq++
		bp := frameGet()
		frame := (*bp)[:hdrSize+n]
		binary.BigEndian.PutUint64(frame[0:8], seq)
		binary.BigEndian.PutUint32(frame[8:12], uint32(n))
		copy(frame[hdrSize:], p[:n])
		*bp = frame
		width := int(atomic.LoadInt32(&c.n))
		if width < 1 {
			framePut(bp)
			return total, c.loadErr()
		}
		start := int(seq % uint64(width))
		placed := false
		for off := 0; off < width; off++ {
			select {
			case c.wq[(start+off)%width] <- bp:
				placed = true
			default:
			}
			if placed {
				break
			}
		}
		if !placed {
			select {
			case c.wq[start] <- bp:
			case <-c.closed:
				framePut(bp)
				return total, c.loadErr()
			}
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	return c.ro.read(p)
}

func (c *Conn) LocalAddr() net.Addr {
	if m := c.member0(); m != nil {
		return m.LocalAddr()
	}
	return nil
}

func (c *Conn) RemoteAddr() net.Addr {
	if m := c.member0(); m != nil {
		return m.RemoteAddr()
	}
	return nil
}

func (c *Conn) member0() net.Conn {
	if atomic.LoadInt32(&c.n) == 0 {
		return nil
	}
	return c.members[0]
}

func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

type rchunk struct {
	data []byte
	buf  *[]byte
}

type reorderer struct {
	mu          sync.Mutex
	cond        *sync.Cond
	next        uint64
	pending     map[uint64]rchunk
	ready       []rchunk
	leftover    []byte
	leftoverBuf *[]byte
	budget      int
	bufBytes    int
	closed      bool
	err         error
}

func newReorderer(budget int) *reorderer {
	r := &reorderer{pending: make(map[uint64]rchunk), budget: budget}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *reorderer) push(seq uint64, data []byte, buf *[]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for !r.closed && seq != r.next && r.bufBytes >= r.budget {
		r.cond.Wait()
	}
	if r.closed {
		return false
	}
	if seq < r.next {
		framePut(buf)
		return true
	}
	if seq == r.next {
		r.ready = append(r.ready, rchunk{data: data, buf: buf})
		r.next++
		for {
			c, ok := r.pending[r.next]
			if !ok {
				break
			}
			delete(r.pending, r.next)
			r.bufBytes -= len(c.data)
			r.ready = append(r.ready, c)
			r.next++
		}
		r.cond.Broadcast()
		return true
	}
	if _, exists := r.pending[seq]; !exists {
		r.pending[seq] = rchunk{data: data, buf: buf}
		r.bufBytes += len(data)
	} else {
		framePut(buf)
	}
	return true
}

func (r *reorderer) read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.leftover) == 0 && len(r.ready) == 0 {
		if r.closed {
			return 0, r.errOrEOF()
		}
		r.cond.Wait()
	}
	if len(r.leftover) == 0 {
		c := r.ready[0]
		r.ready[0] = rchunk{}
		r.ready = r.ready[1:]
		r.leftover = c.data
		r.leftoverBuf = c.buf
	}
	n := copy(p, r.leftover)
	r.leftover = r.leftover[n:]
	if len(r.leftover) == 0 {
		framePut(r.leftoverBuf)
		r.leftoverBuf = nil
	}
	r.cond.Broadcast()
	return n, nil
}

func (r *reorderer) setClosed(err error) {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		r.err = err
	}
	r.cond.Broadcast()
	r.mu.Unlock()
}

func (r *reorderer) errOrEOF() error {
	if r.err != nil && r.err != ErrClosed {
		return r.err
	}
	return io.EOF
}
