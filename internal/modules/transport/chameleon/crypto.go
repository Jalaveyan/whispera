package chameleon

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const maxFrameSize = 4 * 1024 * 1024

// Frame type bytes (first byte of plaintext inside every encrypted frame).
const (
	frameTypeData = byte(0x01) // normal data — pass to caller
	frameTypePad  = byte(0x00) // download padding — discard silently
)

// Keys holds all subkeys derived from the shared secret.
type Keys struct {
	Auth     []byte // HMAC key for HTTP auth token
	DataSend []byte // ChaCha20-Poly1305 key — outbound frames
	DataRecv []byte // ChaCha20-Poly1305 key — inbound frames
	Behavior []byte // base key for BehaviorParams derivation
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

// FrameConn wraps net.Conn with ChaCha20-Poly1305 authenticated encryption.
//
// Wire format per frame: [4B ciphertext_len][ciphertext+tag]
// Plaintext layout:      [1B frame_type][data]
//   frameTypeData (0x01) — normal payload, passed to caller with type byte stripped.
//   frameTypePad  (0x00) — download padding, decrypted and silently discarded.
//
// Nonce = little-endian counter — not transmitted, both sides track independently.
// wmu serialises writes so the download-padding goroutine and the data path don't race.
type FrameConn struct {
	net.Conn
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	sendSeq  uint64
	recvSeq  uint64
	buf      []byte
	wmu      sync.Mutex
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

func counterNonce(seq uint64) []byte {
	n := make([]byte, 12)
	binary.LittleEndian.PutUint64(n, seq)
	return n
}

func (fc *FrameConn) writeFrame(plain []byte) error {
	ct := fc.sendAEAD.Seal(nil, counterNonce(fc.sendSeq), plain, nil)
	fc.sendSeq++
	frame := make([]byte, 4+len(ct))
	binary.BigEndian.PutUint32(frame, uint32(len(ct)))
	copy(frame[4:], ct)
	_, err := fc.Conn.Write(frame)
	return err
}

func (fc *FrameConn) Write(p []byte) (int, error) {
	fc.wmu.Lock()
	defer fc.wmu.Unlock()

	plain := make([]byte, 1+len(p))
	plain[0] = frameTypeData
	copy(plain[1:], p)

	if err := fc.writeFrame(plain); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WritePadding sends a padding frame of the given size that the peer discards.
// The content is zeroed — it's encrypted so the wire value is indistinguishable from data.
func (fc *FrameConn) WritePadding(size int) error {
	fc.wmu.Lock()
	defer fc.wmu.Unlock()

	plain := make([]byte, 1+size) // plain[0] = frameTypePad (zero value), rest = zeros
	return fc.writeFrame(plain)
}

func (fc *FrameConn) Read(b []byte) (int, error) {
	if len(fc.buf) > 0 {
		n := copy(b, fc.buf)
		fc.buf = fc.buf[n:]
		return n, nil
	}

	for {
		var hdr [4]byte
		if _, err := io.ReadFull(fc.Conn, hdr[:]); err != nil {
			return 0, err
		}
		ctLen := binary.BigEndian.Uint32(hdr[:])
		if ctLen == 0 || ctLen > uint32(maxFrameSize+fc.recvAEAD.Overhead()) {
			return 0, fmt.Errorf("chameleon: bad frame len %d", ctLen)
		}

		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(fc.Conn, ct); err != nil {
			return 0, err
		}

		pt, err := fc.recvAEAD.Open(nil, counterNonce(fc.recvSeq), ct, nil)
		if err != nil {
			return 0, fmt.Errorf("chameleon: decrypt: %w", err)
		}
		fc.recvSeq++

		if len(pt) == 0 {
			return 0, fmt.Errorf("chameleon: empty frame")
		}
		if pt[0] == frameTypePad {
			continue // discard padding, read next frame
		}

		// Data frame: strip type byte.
		data := pt[1:]
		n := copy(b, data)
		if n < len(data) {
			fc.buf = make([]byte, len(data)-n)
			copy(fc.buf, data[n:])
		}
		return n, nil
	}
}
