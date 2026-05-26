package chameleon

import (
	"bufio"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/hkdf"
)

var frameBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 5+4*1024*1024); return &b },
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

func DeriveKeys(sharedSecret []byte) *Keys {
	derive := func(info string) []byte {
		r := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))
		k := make([]byte, 32)
		if _, err := io.ReadFull(r, k); err != nil {
			panic("chameleon hkdf: " + err.Error())
		}
		return k
	}

	return &Keys{
		Auth:     derive("chameleon-auth-v1"),
		Behavior: derive("chameleon-behavior-v1"),
	}
}

type FrameConn struct {
	net.Conn
	sendMu  sync.Mutex
	buf     []byte
	recvBuf []byte

	bufRead *bufio.Reader

	bytesRecent uint64
}

func NewFrameConn(conn net.Conn) *FrameConn {
	return &FrameConn{
		Conn:    conn,
		bufRead: bufio.NewReaderSize(conn, 128*1024),
	}
}

func (fc *FrameConn) writeFrame(typ byte, p []byte) error {
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
	_, err := fc.Conn.Write(buf[:total])

	*bufp = buf
	frameBufPool.Put(bufp)
	return err
}

func (fc *FrameConn) Write(p []byte) (int, error) {
	fc.sendMu.Lock()
	defer fc.sendMu.Unlock()
	if err := fc.writeFrame(frameTypeData, p); err != nil {
		return 0, err
	}
	atomic.AddUint64(&fc.bytesRecent, uint64(len(p)))
	return len(p), nil
}

func (fc *FrameConn) SampleAndResetBytes() uint64 {
	return atomic.SwapUint64(&fc.bytesRecent, 0)
}

func (fc *FrameConn) WritePad(n int) error {
	if n <= 0 {
		return nil
	}
	pad := make([]byte, n)
	crand.Read(pad)
	fc.sendMu.Lock()
	defer fc.sendMu.Unlock()
	return fc.writeFrame(framePadding, pad)
}

func (fc *FrameConn) Read(b []byte) (int, error) {
	for {
		if len(fc.buf) > 0 {
			n := copy(b, fc.buf)
			fc.buf = fc.buf[n:]
			return n, nil
		}

		var hdr [4]byte
		if _, err := io.ReadFull(fc.bufRead, hdr[:]); err != nil {
			return 0, err
		}
		frameLen := binary.BigEndian.Uint32(hdr[:])
		if frameLen == 0 || frameLen > uint32(maxFrameSize) {
			return 0, fmt.Errorf("chameleon: bad frame len %d", frameLen)
		}

		if uint32(cap(fc.recvBuf)) < frameLen {
			fc.recvBuf = make([]byte, frameLen)
		} else {
			fc.recvBuf = fc.recvBuf[:frameLen]
		}
		if _, err := io.ReadFull(fc.bufRead, fc.recvBuf); err != nil {
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
			fc.buf = make([]byte, len(pt)-n)
			copy(fc.buf, pt[n:])
		}
		atomic.AddUint64(&fc.bytesRecent, uint64(len(pt)))
		return n, nil
	}
}
