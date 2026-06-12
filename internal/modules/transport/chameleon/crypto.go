package chameleon

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/crypto/hkdf"

	"whispera/internal/buf"
)

var frameBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 5+65536); return &b },
}

var frameReqPool = sync.Pool{
	New: func() any { return &frameReq{done: make(chan error, 1)} },
}

func acquireFrameReq() *frameReq {
	r := frameReqPool.Get().(*frameReq)
	select {
	case <-r.done:
	default:
	}
	return r
}

func releaseFrameReq(r *frameReq) {
	r.data = nil
	r.bufp = nil
	r.addBytes = 0
	frameReqPool.Put(r)
}

const (
	maxFrameSize  = 4 * 1024 * 1024
	frameTypeData = byte(0x01)
	framePadding  = byte(0x00)
)

type Keys struct {
	Auth     []byte
	Behavior []byte
}

var deriveKeysCache = func() *lru.Cache[[32]byte, *Keys] {
	c, _ := lru.New[[32]byte, *Keys](1024)
	return c
}()

func DeriveKeys(sharedSecret []byte) *Keys {
	cacheKey := sha256.Sum256(sharedSecret)
	if v, ok := deriveKeysCache.Get(cacheKey); ok {
		return v
	}

	derive := func(info string) []byte {
		r := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))
		k := make([]byte, 32)
		if _, err := io.ReadFull(r, k); err != nil {
			panic("chameleon hkdf: " + err.Error())
		}
		return k
	}

	keys := &Keys{
		Auth:     derive("chameleon-auth-v1"),
		Behavior: derive("chameleon-behavior-v1"),
	}
	deriveKeysCache.Add(cacheKey, keys)
	return keys
}

type frameReq struct {
	data     []byte
	bufp     *[]byte
	addBytes uint64
	done     chan error
}

type FrameConn struct {
	net.Conn
	writeCh   chan *frameReq
	closed    chan struct{}
	closeOnce sync.Once
	buf       []byte
	recvBuf   []byte

	bytesRecent uint64
}

func connRemote(c net.Conn) string {
	if c == nil {
		return ""
	}
	if a := c.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}

func NewFrameConn(conn net.Conn) *FrameConn {
	fc := &FrameConn{
		Conn:    conn,
		writeCh: make(chan *frameReq, 128),
		closed:  make(chan struct{}),
	}
	go fc.writer()
	return fc
}

func (fc *FrameConn) Close() error {
	fc.closeOnce.Do(func() { close(fc.closed) })
	return fc.Conn.Close()
}

func (fc *FrameConn) writer() {
	var scratch []byte
	var batch []*frameReq
	for {
		batch = batch[:0]
		select {
		case req := <-fc.writeCh:
			batch = append(batch, req)
		case <-fc.closed:
			return
		}
	drain:
		for len(batch) < 64 {
			select {
			case req := <-fc.writeCh:
				batch = append(batch, req)
			default:
				break drain
			}
		}

		total := 0
		for _, r := range batch {
			total += len(r.data)
		}
		if cap(scratch) < total {
			scratch = make([]byte, total)
		} else {
			scratch = scratch[:total]
		}
		off := 0
		var addBytes uint64
		for _, r := range batch {
			copy(scratch[off:], r.data)
			off += len(r.data)
			addBytes += r.addBytes
			if r.bufp != nil {
				frameBufPool.Put(r.bufp)
			}
		}

		var err error
		written := 0
		for written < off {
			n, werr := fc.Conn.Write(scratch[written:off])
			if werr != nil {
				err = werr
				break
			}
			if n == 0 {
				err = io.ErrShortWrite
				break
			}
			written += n
		}

		if err == nil && addBytes > 0 {
			atomic.AddUint64(&fc.bytesRecent, addBytes)
		}
		if err == nil && len(fc.writeCh) == 0 {
			if f, ok := fc.Conn.(interface{ FlushWrite() }); ok {
				f.FlushWrite()
			}
		}
		for _, r := range batch {
			select {
			case r.done <- err:
			default:
			}
		}
	}
}

func (fc *FrameConn) submit(req *frameReq) error {
	select {
	case fc.writeCh <- req:
	case <-fc.closed:
		if req.bufp != nil {
			frameBufPool.Put(req.bufp)
		}
		releaseFrameReq(req)
		return io.ErrClosedPipe
	}
	select {
	case err := <-req.done:
		releaseFrameReq(req)
		return err
	case <-fc.closed:
		return io.ErrClosedPipe
	}
}

func (fc *FrameConn) buildFrame(typ byte, p []byte) (*[]byte, []byte) {
	total := 4 + 1 + len(p)
	bufp := frameBufPool.Get().(*[]byte)
	buf := *bufp
	if cap(buf) < total {
		buf = make([]byte, total)
	} else {
		buf = buf[:total]
	}
	binary.BigEndian.PutUint32(buf[:4], uint32(1+len(p)))
	buf[4] = typ
	copy(buf[5:], p)
	*bufp = buf
	return bufp, buf[:total]
}

func (fc *FrameConn) Write(p []byte) (int, error) {
	bufp, framed := fc.buildFrame(frameTypeData, p)
	req := acquireFrameReq()
	req.data = framed
	req.bufp = bufp
	req.addBytes = uint64(len(p))
	if err := fc.submit(req); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (fc *FrameConn) SampleAndResetBytes() uint64 {
	return atomic.SwapUint64(&fc.bytesRecent, 0)
}

func (fc *FrameConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		if len(fc.buf) > 0 {
			b := buf.NewSize(len(fc.buf))
			b.Write(fc.buf)
			fc.buf = fc.buf[:0]
			return buf.MultiBuffer{b}, nil
		}

		var hdr [4]byte
		if _, err := io.ReadFull(fc.Conn, hdr[:]); err != nil {
			return nil, err
		}
		frameLen := binary.BigEndian.Uint32(hdr[:])
		if frameLen == 0 || frameLen > uint32(maxFrameSize) {
			return nil, fmt.Errorf("chameleon: bad frame len %d", frameLen)
		}

		var typ [1]byte
		if _, err := io.ReadFull(fc.Conn, typ[:]); err != nil {
			return nil, err
		}
		bodyLen := int(frameLen) - 1

		if typ[0] == framePadding {
			if _, err := io.CopyN(io.Discard, fc.Conn, int64(bodyLen)); err != nil {
				return nil, err
			}
			continue
		}
		if bodyLen <= 0 {
			continue
		}

		var mb buf.MultiBuffer
		remaining := bodyLen
		for remaining > 0 {
			b := buf.New()
			chunk := remaining
			if chunk > b.Cap() {
				chunk = b.Cap()
			}
			slice := b.Extend(chunk)
			if _, err := io.ReadFull(fc.Conn, slice); err != nil {
				b.Release()
				buf.ReleaseMulti(mb)
				return nil, err
			}
			mb = append(mb, b)
			remaining -= chunk
		}
		atomic.AddUint64(&fc.bytesRecent, uint64(bodyLen))
		return mb, nil
	}
}

func (fc *FrameConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if len(mb) == 0 {
		return nil
	}

	totalSize := 0
	for _, b := range mb {
		if b != nil && !b.IsEmpty() {
			totalSize += 5 + b.Len()
		}
	}
	if totalSize == 0 {
		return nil
	}

	bufp := frameBufPool.Get().(*[]byte)
	combined := *bufp
	if cap(combined) < totalSize {
		combined = make([]byte, totalSize)
	} else {
		combined = combined[:totalSize]
	}

	off := 0
	var payloadBytes uint64
	for _, b := range mb {
		if b == nil || b.IsEmpty() {
			continue
		}
		data := b.Bytes()
		binary.BigEndian.PutUint32(combined[off:off+4], uint32(1+len(data)))
		combined[off+4] = frameTypeData
		copy(combined[off+5:], data)
		off += 5 + len(data)
		payloadBytes += uint64(len(data))
	}
	*bufp = combined

	req := acquireFrameReq()
	req.data = combined[:off]
	req.bufp = bufp
	req.addBytes = payloadBytes
	return fc.submit(req)
}

func (fc *FrameConn) WritePad(n int) error {
	if n <= 0 {
		return nil
	}
	b := buf.NewSize(n)
	defer b.Release()
	pad := b.Extend(n)
	crand.Read(pad)
	bufp, framed := fc.buildFrame(framePadding, pad)
	req := acquireFrameReq()
	req.data = framed
	req.bufp = bufp
	return fc.submit(req)
}

func (fc *FrameConn) Read(b []byte) (int, error) {
	for {
		if len(fc.buf) > 0 {
			n := copy(b, fc.buf)
			fc.buf = fc.buf[n:]
			return n, nil
		}

		var hdr [4]byte
		if n, err := io.ReadFull(fc.Conn, hdr[:]); err != nil {
			traceLog.Warnw("frameconn_read_err",
				"phase", "len_header",
				"got", n,
				"want", 4,
				"remote", connRemote(fc.Conn),
				"err", err.Error(),
				"err_type", fmt.Sprintf("%T", err),
			)
			return 0, err
		}
		frameLen := binary.BigEndian.Uint32(hdr[:])
		if frameLen == 0 || frameLen > uint32(maxFrameSize) {
			traceLog.Warnw("frameconn_bad_len",
				"frame_len", frameLen,
				"header", fmt.Sprintf("%x", hdr),
				"remote", connRemote(fc.Conn),
			)
			return 0, fmt.Errorf("chameleon: bad frame len %d", frameLen)
		}

		if uint32(cap(fc.recvBuf)) < frameLen {
			fc.recvBuf = make([]byte, frameLen)
		} else {
			fc.recvBuf = fc.recvBuf[:frameLen]
		}
		if n, err := io.ReadFull(fc.Conn, fc.recvBuf); err != nil {
			traceLog.Warnw("frameconn_read_err",
				"phase", "body",
				"got", n,
				"want", frameLen,
				"remote", connRemote(fc.Conn),
				"err", err.Error(),
				"err_type", fmt.Sprintf("%T", err),
			)
			return 0, err
		}

		pt := fc.recvBuf[:frameLen]
		if pt[0] == framePadding {
			continue
		}

		pt = pt[1:]
		if len(pt) == 0 {
			continue
		}
		n := copy(b, pt)
		if n < len(pt) {
			leftover := pt[n:]
			if cap(fc.buf) < len(leftover) {
				fc.buf = make([]byte, len(leftover))
			} else {
				fc.buf = fc.buf[:len(leftover)]
			}
			copy(fc.buf, leftover)
		}
		atomic.AddUint64(&fc.bytesRecent, uint64(len(pt)))
		return n, nil
	}
}
