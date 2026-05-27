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

type Conn struct {
	id bondID

	mu      sync.Mutex
	members []net.Conn
	wq      []chan []byte
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
		id:      id,
		members: make([]net.Conn, 0, maxBondMembers),
		wq:      make([]chan []byte, 0, maxBondMembers),
		closed:  make(chan struct{}),
		ro:      newReorderer(defaultBudget),
	}
	c.AddMember(first)
	return c
}

func (c *Conn) AddMember(m net.Conn) bool {
	select {
	case <-c.closed:
		m.Close()
		return false
	default:
	}
	c.mu.Lock()
	if len(c.members) >= maxBondMembers {
		c.mu.Unlock()
		m.Close()
		return false
	}
	i := len(c.members)
	c.members = append(c.members, m)
	c.wq = append(c.wq, make(chan []byte, writeQueueDepth))
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

func (c *Conn) setErr(err error) { c.shutdown(err, false) }

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
	members := append([]net.Conn(nil), c.members...)
	c.mu.Unlock()
	for _, m := range members {
		m.Close()
	}
	return nil
}

func (c *Conn) queue(i int) chan []byte {
	c.mu.Lock()
	ch := c.wq[i]
	c.mu.Unlock()
	return ch
}

func (c *Conn) member(i int) net.Conn {
	c.mu.Lock()
	m := c.members[i]
	c.mu.Unlock()
	return m
}

func (c *Conn) writeLoop(i int) {
	defer c.writerWg.Done()
	m := c.member(i)
	q := c.queue(i)
	write := func(frame []byte) bool {
		if _, err := m.Write(frame); err != nil {
			c.setErr(err)
			return false
		}
		return true
	}
	for {
		select {
		case frame := <-q:
			if !write(frame) {
				return
			}
		case <-c.closed:
			for {
				select {
				case frame := <-q:
					if !write(frame) {
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
	m := c.member(i)
	hdr := make([]byte, hdrSize)
	for {
		if _, err := io.ReadFull(m, hdr); err != nil {
			c.setErr(err)
			return
		}
		seq := binary.BigEndian.Uint64(hdr[0:8])
		ln := binary.BigEndian.Uint32(hdr[8:12])
		data := make([]byte, ln)
		if ln > 0 {
			if _, err := io.ReadFull(m, data); err != nil {
				c.setErr(err)
				return
			}
		}
		if !c.ro.push(seq, data) {
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
		frame := make([]byte, hdrSize+n)
		binary.BigEndian.PutUint64(frame[0:8], seq)
		binary.BigEndian.PutUint32(frame[8:12], uint32(n))
		copy(frame[hdrSize:], p[:n])
		width := atomic.LoadInt32(&c.n)
		if width < 1 {
			return total, c.loadErr()
		}
		idx := int(seq % uint64(width))
		select {
		case c.queue(idx) <- frame:
		case <-c.closed:
			return total, c.loadErr()
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.members) > 0 {
		return c.members[0]
	}
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

type reorderer struct {
	mu       sync.Mutex
	cond     *sync.Cond
	next     uint64
	pending  map[uint64][]byte
	ready    [][]byte
	leftover []byte
	budget   int
	bufBytes int
	closed   bool
	err      error
}

func newReorderer(budget int) *reorderer {
	r := &reorderer{pending: make(map[uint64][]byte), budget: budget}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *reorderer) push(seq uint64, data []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for !r.closed && seq != r.next && r.bufBytes >= r.budget {
		r.cond.Wait()
	}
	if r.closed {
		return false
	}
	if seq < r.next {
		return true
	}
	if seq == r.next {
		r.ready = append(r.ready, data)
		r.next++
		for {
			d, ok := r.pending[r.next]
			if !ok {
				break
			}
			delete(r.pending, r.next)
			r.bufBytes -= len(d)
			r.ready = append(r.ready, d)
			r.next++
		}
		r.cond.Broadcast()
		return true
	}
	if _, exists := r.pending[seq]; !exists {
		r.pending[seq] = data
		r.bufBytes += len(data)
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
		r.leftover = r.ready[0]
		r.ready[0] = nil
		r.ready = r.ready[1:]
	}
	n := copy(p, r.leftover)
	r.leftover = r.leftover[n:]
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
