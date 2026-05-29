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
	defaultBudget   = 64 * 1024 * 1024
	writeQueueDepth = 256
	flushTimeout    = 2 * time.Second
	maxBondMembers  = 1024
	gapStallTimeout = 8 * time.Second
)

var ErrClosed = errors.New("bond: closed")

var ErrGapStalled = errors.New("bond: reorder gap stalled")

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
	members atomic.Pointer[[]net.Conn]
	wq      atomic.Pointer[[]chan *[]byte]

	writeMu sync.Mutex
	nextSeq uint64

	ro *reorderer

	fallbackHits atomic.Uint64

	closeOnce sync.Once
	closed    chan struct{}
	err       atomic.Value
	writerWg  sync.WaitGroup
	readerWg  sync.WaitGroup
}

func newConn(id bondID, first net.Conn) *Conn {
	c := &Conn{
		id:     id,
		closed: make(chan struct{}),
		ro:     newReorderer(defaultBudget),
	}
	c.ro.onStall = func() { c.setErr(ErrGapStalled) }
	c.AddMember(first)
	return c
}

func (c *Conn) loadMembers() []net.Conn {
	if p := c.members.Load(); p != nil {
		return *p
	}
	return nil
}

func (c *Conn) loadWQ() []chan *[]byte {
	if p := c.wq.Load(); p != nil {
		return *p
	}
	return nil
}

func (c *Conn) AddMember(m net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		m.Close()
		return false
	default:
	}
	cur := c.loadMembers()
	curQ := c.loadWQ()
	i := len(cur)
	if i >= maxBondMembers {
		m.Close()
		return false
	}
	newMembers := make([]net.Conn, i+1)
	copy(newMembers, cur)
	newMembers[i] = m
	newWQ := make([]chan *[]byte, i+1)
	copy(newWQ, curQ)
	q := make(chan *[]byte, writeQueueDepth)
	newWQ[i] = q
	c.members.Store(&newMembers)
	c.wq.Store(&newWQ)
	c.writerWg.Add(1)
	c.readerWg.Add(1)
	go c.writeLoop(i, m, q)
	go c.readLoop(i, m)
	return true
}

func (c *Conn) Width() int { return len(c.loadMembers()) }

func (c *Conn) QueuePressure() (avgPct, maxPct, minPct int, fallbackHits uint64) {
	wq := c.loadWQ()
	if len(wq) == 0 {
		return 0, 0, 0, c.fallbackHits.Load()
	}
	capPer := cap(wq[0])
	if capPer <= 0 {
		return 0, 0, 0, c.fallbackHits.Load()
	}
	var sum, peak int
	low := capPer
	for _, q := range wq {
		l := len(q)
		sum += l
		if l > peak {
			peak = l
		}
		if l < low {
			low = l
		}
	}
	n := len(wq)
	return sum * 100 / (n * capPer), peak * 100 / capPer, low * 100 / capPer, c.fallbackHits.Load()
}

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
	go func() {
		if graceful {
			done := make(chan struct{})
			go func() { c.writerWg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(flushTimeout):
			}
		}
		for _, m := range c.loadMembers() {
			if m != nil {
				m.Close()
			}
		}
		readDone := make(chan struct{})
		go func() { c.readerWg.Wait(); close(readDone) }()
		select {
		case <-readDone:
		case <-time.After(flushTimeout):
		}
		c.ro.setClosed(c.loadErr())
	}()
	return nil
}

func (c *Conn) writeLoop(i int, m net.Conn, q chan *[]byte) {
	defer c.writerWg.Done()
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

func (c *Conn) readLoop(i int, m net.Conn) {
	defer c.readerWg.Done()
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
		wq := c.loadWQ()
		width := len(wq)
		if width < 1 {
			framePut(bp)
			return total, c.loadErr()
		}
		start := 0
		minLen := len(wq[0])
		for j := 1; j < width; j++ {
			if l := len(wq[j]); l < minLen {
				minLen = l
				start = j
			}
		}
		placed := false
		for off := 0; off < width; off++ {
			select {
			case wq[(start+off)%width] <- bp:
				placed = true
			default:
			}
			if placed {
				break
			}
		}
		if !placed {
			c.fallbackHits.Add(1)
			select {
			case wq[start] <- bp:
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
	if ms := c.loadMembers(); len(ms) > 0 {
		return ms[0]
	}
	return nil
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

	onStall      func()
	stallTimer   *time.Timer
	stallTimeout time.Duration
}

func (r *reorderer) fireStall() {
	r.mu.Lock()
	stuck := !r.closed && r.bufBytes > 0
	r.mu.Unlock()
	if stuck && r.onStall != nil {
		r.onStall()
	}
}

func (r *reorderer) syncGapTimer(advanced bool) {
	if advanced && r.stallTimer != nil {
		r.stallTimer.Stop()
		r.stallTimer = nil
	}
	if r.bufBytes > 0 {
		if r.stallTimer == nil && !r.closed {
			r.stallTimer = time.AfterFunc(r.stallTimeout, r.fireStall)
		}
	} else if r.stallTimer != nil {
		r.stallTimer.Stop()
		r.stallTimer = nil
	}
}

func newReorderer(budget int) *reorderer {
	r := &reorderer{pending: make(map[uint64]rchunk), budget: budget, stallTimeout: gapStallTimeout}
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
		r.syncGapTimer(true)
		r.cond.Broadcast()
		return true
	}
	if _, exists := r.pending[seq]; !exists {
		r.pending[seq] = rchunk{data: data, buf: buf}
		r.bufBytes += len(data)
	} else {
		framePut(buf)
	}
	r.syncGapTimer(false)
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
	if r.stallTimer != nil {
		r.stallTimer.Stop()
		r.stallTimer = nil
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
