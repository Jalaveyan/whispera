package chameleon

import (
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var frameBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 4+1+65536+16); return &b },
}

const (
	maxFrameSize    = 4 * 1024 * 1024
	frameTypeData   = byte(0x01)
	framePadding    = byte(0x00)
)

type Keys struct {
	Auth     []byte
	DataSend []byte
	DataRecv []byte
	Behavior []byte
}

func DeriveKeys(sharedSecret []byte, isClient bool) *Keys {
	derive := func(info string) []byte {
		r := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))
		k := make([]byte, 32)
		if _, err := io.ReadFull(r, k); err != nil {
			panic("chameleon hkdf: " + err.Error())
		}
		return k
	}

	c2s := derive("chameleon-c2s-v1")
	s2c := derive("chameleon-s2c-v1")

	var send, recv []byte
	if isClient {
		send, recv = c2s, s2c
	} else {
		send, recv = s2c, c2s
	}

	return &Keys{
		Auth:     derive("chameleon-auth-v1"),
		DataSend: send,
		DataRecv: recv,
		Behavior: derive("chameleon-behavior-v1"),
	}
}

type FrameConn struct {
	net.Conn
	sendMu   sync.Mutex
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	sendSeq  uint64
	recvSeq  uint64
	buf      []byte
	recvBuf  []byte
}

func NewFrameConn(conn net.Conn, sendKey, recvKey []byte) (*FrameConn, error) {
	sa, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	ra, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}
	return &FrameConn{Conn: conn, sendAEAD: sa, recvAEAD: ra}, nil
}

func counterNonce(seq uint64) [12]byte {
	var n [12]byte
	binary.LittleEndian.PutUint64(n[:], seq)
	return n
}

// writeFrame encrypts and sends [typ][payload] as one frame.
func (fc *FrameConn) writeFrame(typ byte, p []byte) error {
	overhead := fc.sendAEAD.Overhead()
	plainLen := 1 + len(p)
	total := 4 + plainLen + overhead

	bufp := frameBufPool.Get().(*[]byte)
	buf := *bufp
	if cap(buf) < total {
		buf = make([]byte, total)
	} else {
		buf = buf[:total]
	}

	binary.BigEndian.PutUint32(buf[:4], uint32(plainLen+overhead))
	buf[4] = typ
	copy(buf[5:], p)
	nonce := counterNonce(fc.sendSeq)
	fc.sendAEAD.Seal(buf[4:4], nonce[:], buf[4:4+plainLen], nil)
	fc.sendSeq++
	_, err := fc.Conn.Write(buf[:total])

	*bufp = buf
	frameBufPool.Put(bufp)
	return err
}

// Write sends p as a data frame (type=0x01).
func (fc *FrameConn) Write(p []byte) (int, error) {
	fc.sendMu.Lock()
	defer fc.sendMu.Unlock()
	if err := fc.writeFrame(frameTypeData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WritePad sends n random bytes as a padding frame (type=0x00).
// The receiver discards padding frames silently.
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

// Read decrypts the next data frame, silently skipping padding frames.
func (fc *FrameConn) Read(b []byte) (int, error) {
	for {
		if len(fc.buf) > 0 {
			n := copy(b, fc.buf)
			fc.buf = fc.buf[n:]
			return n, nil
		}

		var hdr [4]byte
		if _, err := io.ReadFull(fc.Conn, hdr[:]); err != nil {
			return 0, err
		}
		ctLen := binary.BigEndian.Uint32(hdr[:])
		if ctLen == 0 || ctLen > uint32(maxFrameSize+fc.recvAEAD.Overhead()) {
			return 0, fmt.Errorf("chameleon: bad frame len %d", ctLen)
		}

		if uint32(cap(fc.recvBuf)) < ctLen {
			fc.recvBuf = make([]byte, ctLen)
		} else {
			fc.recvBuf = fc.recvBuf[:ctLen]
		}
		if _, err := io.ReadFull(fc.Conn, fc.recvBuf); err != nil {
			return 0, err
		}

		recvNonce := counterNonce(fc.recvSeq)
		pt, err := fc.recvAEAD.Open(fc.recvBuf[:0], recvNonce[:], fc.recvBuf[:ctLen], nil)
		if err != nil {
			return 0, fmt.Errorf("chameleon: decrypt: %w", err)
		}
		fc.recvSeq++

		if len(pt) == 0 {
			return 0, fmt.Errorf("chameleon: empty frame")
		}

		// Skip padding frames; loop to read the next one.
		if pt[0] == framePadding {
			continue
		}

		// Strip type byte and return payload.
		pt = pt[1:]
		if len(pt) == 0 {
			continue
		}
		n := copy(b, pt)
		if n < len(pt) {
			fc.buf = make([]byte, len(pt)-n)
			copy(fc.buf, pt[n:])
		}
		return n, nil
	}
}
