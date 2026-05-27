package bond

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const (
	handshakeMagic = 0x424E4432
	handshakeSize  = 4 + 16
)

var ErrBadHandshake = errors.New("bond: bad handshake")

type bondID [16]byte

func writeHandshake(c net.Conn, id bondID) error {
	var b [handshakeSize]byte
	binary.BigEndian.PutUint32(b[0:4], handshakeMagic)
	copy(b[4:20], id[:])
	_, err := c.Write(b[:])
	return err
}

func readHandshake(c net.Conn) (id bondID, err error) {
	var b [handshakeSize]byte
	if _, err = io.ReadFull(c, b[:]); err != nil {
		return
	}
	if binary.BigEndian.Uint32(b[0:4]) != handshakeMagic {
		err = ErrBadHandshake
		return
	}
	copy(id[:], b[4:20])
	return
}

type DialFunc func(context.Context) (net.Conn, error)

func Dial(ctx context.Context, dial DialFunc) (*Conn, error) {
	var id bondID
	if _, err := crand.Read(id[:]); err != nil {
		return nil, err
	}
	c, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeHandshake(c, id); err != nil {
		c.Close()
		return nil, err
	}
	return newConn(id, c), nil
}

func (c *Conn) Grow(ctx context.Context, dial DialFunc) error {
	select {
	case <-c.closed:
		return ErrClosed
	default:
	}
	if c.Width() >= maxBondMembers {
		return nil
	}
	m, err := dial(ctx)
	if err != nil {
		return err
	}
	if err := writeHandshake(m, c.id); err != nil {
		m.Close()
		return err
	}
	if !c.AddMember(m) {
		return ErrClosed
	}
	return nil
}

type Coordinator struct {
	mu   sync.Mutex
	live map[bondID]*Conn
}

func NewCoordinator() *Coordinator {
	return &Coordinator{live: make(map[bondID]*Conn)}
}

func (co *Coordinator) Offer(conn net.Conn) (*Conn, net.Conn, error) {
	var b [handshakeSize]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		return nil, nil, err
	}
	if binary.BigEndian.Uint32(b[0:4]) != handshakeMagic {
		return nil, &prefixConn{Conn: conn, prefix: append([]byte(nil), b[:]...)}, nil
	}
	var id bondID
	copy(id[:], b[4:20])

	co.mu.Lock()
	if live, ok := co.live[id]; ok {
		co.mu.Unlock()
		if live.AddMember(conn) {
			return nil, nil, nil
		}
		return co.create(id, conn), nil, nil
	}
	co.mu.Unlock()
	return co.create(id, conn), nil, nil
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (co *Coordinator) create(id bondID, conn net.Conn) *Conn {
	b := newConn(id, conn)
	co.mu.Lock()
	co.live[id] = b
	co.mu.Unlock()
	go func() {
		<-b.Done()
		co.mu.Lock()
		if co.live[id] == b {
			delete(co.live, id)
		}
		co.mu.Unlock()
	}()
	return b
}
