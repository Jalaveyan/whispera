package buf

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

const Size = 66048

var ErrShort = errors.New("buf: short write")

type Buffer struct {
	v        []byte
	start    int
	end      int
	released atomic.Bool
}

var pool = sync.Pool{
	New: func() any {
		return &Buffer{v: make([]byte, Size)}
	},
}

func New() *Buffer {
	b := pool.Get().(*Buffer)
	b.start = 0
	b.end = 0
	b.released.Store(false)
	return b
}

func NewSize(n int) *Buffer {
	if n <= Size {
		return New()
	}
	return &Buffer{v: make([]byte, n)}
}

func (b *Buffer) Release() {
	if b == nil {
		return
	}
	if !b.released.CompareAndSwap(false, true) {
		return
	}
	if cap(b.v) == Size {
		pool.Put(b)
	}
}

func (b *Buffer) Bytes() []byte { return b.v[b.start:b.end] }
func (b *Buffer) Len() int      { return b.end - b.start }
func (b *Buffer) Cap() int      { return cap(b.v) - b.end }
func (b *Buffer) IsEmpty() bool { return b.end-b.start == 0 }
func (b *Buffer) IsFull() bool  { return b.end == cap(b.v) }

func (b *Buffer) Reset()        { b.start = 0; b.end = 0 }
func (b *Buffer) Advance(n int) { b.start += n }
func (b *Buffer) Extend(n int) []byte {
	if b.end+n > cap(b.v) {
		n = cap(b.v) - b.end
	}
	out := b.v[b.end : b.end+n]
	b.end += n
	return out
}

func (b *Buffer) Write(p []byte) (int, error) {
	free := cap(b.v) - b.end
	if free == 0 {
		return 0, io.ErrShortBuffer
	}
	n := copy(b.v[b.end:], p)
	b.end += n
	if n < len(p) {
		return n, io.ErrShortBuffer
	}
	return n, nil
}

func (b *Buffer) ReadFrom(r io.Reader) (int64, error) {
	n, err := r.Read(b.v[b.end:cap(b.v)])
	if n > 0 {
		b.end += n
	}
	return int64(n), err
}

func (b *Buffer) Read(p []byte) (int, error) {
	if b.IsEmpty() {
		return 0, io.EOF
	}
	n := copy(p, b.v[b.start:b.end])
	b.start += n
	return n, nil
}

func (b *Buffer) WriteByte(c byte) error {
	if b.IsFull() {
		return io.ErrShortBuffer
	}
	b.v[b.end] = c
	b.end++
	return nil
}

func (b *Buffer) WriteString(s string) (int, error) {
	free := cap(b.v) - b.end
	if free == 0 {
		return 0, io.ErrShortBuffer
	}
	n := copy(b.v[b.end:], s)
	b.end += n
	if n < len(s) {
		return n, io.ErrShortBuffer
	}
	return n, nil
}

func (b *Buffer) Byte(i int) byte    { return b.v[b.start+i] }
func (b *Buffer) SetByte(i int, c byte) { b.v[b.start+i] = c }

type MultiBuffer []*Buffer

func MergeMulti(dst, src MultiBuffer) (MultiBuffer, MultiBuffer) {
	dst = append(dst, src...)
	for i := range src {
		src[i] = nil
	}
	return dst, src[:0]
}

func ReleaseMulti(mb MultiBuffer) MultiBuffer {
	for i, b := range mb {
		b.Release()
		mb[i] = nil
	}
	return mb[:0]
}

func (mb MultiBuffer) Len() int64 {
	var n int64
	for _, b := range mb {
		n += int64(b.Len())
	}
	return n
}

func (mb MultiBuffer) IsEmpty() bool {
	for _, b := range mb {
		if !b.IsEmpty() {
			return false
		}
	}
	return true
}

func SplitBytes(mb MultiBuffer, dst []byte) (MultiBuffer, int) {
	totalBytes := 0
	endIndex := -1
	for i, b := range mb {
		if b == nil || b.IsEmpty() {
			continue
		}
		n, _ := b.Read(dst[totalBytes:])
		totalBytes += n
		if b.IsEmpty() {
			b.Release()
			mb[i] = nil
		}
		if totalBytes == len(dst) {
			endIndex = i + 1
			break
		}
	}
	if endIndex == -1 {
		endIndex = len(mb)
	}
	compact := mb[:0]
	for _, b := range mb[:endIndex] {
		if b != nil {
			compact = append(compact, b)
		}
	}
	compact = append(compact, mb[endIndex:]...)
	return compact, totalBytes
}

func MergeBytes(dst MultiBuffer, src []byte) MultiBuffer {
	for len(src) > 0 {
		var last *Buffer
		if len(dst) > 0 {
			last = dst[len(dst)-1]
		}
		if last == nil || last.IsFull() {
			last = New()
			dst = append(dst, last)
		}
		n, _ := last.Write(src)
		src = src[n:]
	}
	return dst
}

type Reader interface {
	ReadMultiBuffer() (MultiBuffer, error)
}

type Writer interface {
	WriteMultiBuffer(MultiBuffer) error
}

type ReaderFunc func() (MultiBuffer, error)

func (f ReaderFunc) ReadMultiBuffer() (MultiBuffer, error) { return f() }

func NewReader(r io.Reader) Reader {
	if br, ok := r.(Reader); ok {
		return br
	}
	return &singleReader{r: r}
}

type singleReader struct{ r io.Reader }

func (sr *singleReader) ReadMultiBuffer() (MultiBuffer, error) {
	b := New()
	if _, err := b.ReadFrom(sr.r); err != nil {
		b.Release()
		return nil, err
	}
	if b.IsEmpty() {
		b.Release()
		return nil, nil
	}
	return MultiBuffer{b}, nil
}

func NewWriter(w io.Writer) Writer {
	if bw, ok := w.(Writer); ok {
		return bw
	}
	return &singleWriter{w: w}
}

type singleWriter struct{ w io.Writer }

func (sw *singleWriter) WriteMultiBuffer(mb MultiBuffer) error {
	defer ReleaseMulti(mb)
	if len(mb) == 0 {
		return nil
	}
	if len(mb) == 1 {
		b := mb[0]
		for !b.IsEmpty() {
			n, err := sw.w.Write(b.Bytes())
			if err != nil {
				return err
			}
			b.Advance(n)
		}
		return nil
	}
	if _, ok := sw.w.(*net.TCPConn); ok {
		bufs := make(net.Buffers, 0, len(mb))
		for _, b := range mb {
			if !b.IsEmpty() {
				bufs = append(bufs, b.Bytes())
			}
		}
		if _, err := bufs.WriteTo(sw.w); err != nil {
			return err
		}
		for _, b := range mb {
			b.start = b.end
		}
		return nil
	}
	for _, b := range mb {
		for !b.IsEmpty() {
			n, err := sw.w.Write(b.Bytes())
			if err != nil {
				return err
			}
			b.Advance(n)
		}
	}
	return nil
}

func Copy(reader Reader, writer Writer) (int64, error) {
	var total int64
	for {
		mb, err := reader.ReadMultiBuffer()
		if !mb.IsEmpty() {
			total += mb.Len()
			if werr := writer.WriteMultiBuffer(mb); werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}
