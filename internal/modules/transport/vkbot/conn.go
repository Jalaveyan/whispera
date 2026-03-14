package vkbot

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type botConn struct {
	transport *Transport
	peerID    int64

	recvMu   sync.Mutex
	recvBuf  []byte
	recvCond *sync.Cond

	asmMu  sync.Mutex
	frames map[uint32]*frameAsm

	sendSeq   atomic.Uint32
	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}

	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

type frameAsm struct {
	total  int
	chunks map[int][]byte
}

func newBotConn(t *Transport, peerID int64) *botConn {
	c := &botConn{
		transport: t,
		peerID:    peerID,
		frames:    make(map[uint32]*frameAsm),
		done:      make(chan struct{}),
	}
	c.recvCond = sync.NewCond(&c.recvMu)
	return c
}


func (c *botConn) Write(data []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	total := len(data)
	seq := c.sendSeq.Add(1)

	var chunks [][]byte
	for len(data) > 0 {
		n := maxChunk
		if n > len(data) {
			n = len(data)
		}
		chunks = append(chunks, data[:n])
		data = data[n:]
	}
	if len(chunks) == 0 {
		chunks = [][]byte{{}}
	}
	if len(chunks) > 255 {
		return 0, fmt.Errorf("vkbot: write too large (%d bytes, max %d)", total, 255*maxChunk)
	}

	if dl, ok := c.writeDeadline.Load().(time.Time); ok && !dl.IsZero() && time.Now().After(dl) {
		return 0, &net.OpError{Op: "write", Net: "vkbot", Err: fmt.Errorf("i/o timeout")}
	}

	for i, chunk := range chunks {
		msg := encodeMsg(seq, len(chunks), i, chunk)
		if err := c.transport.sendMessage(c.peerID, msg); err != nil {
			return 0, err
		}
	}
	return total, nil
}

func (c *botConn) Read(buf []byte) (int, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for len(c.recvBuf) == 0 {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
			remaining := time.Until(dl)
			if remaining <= 0 {
				return 0, &net.OpError{Op: "read", Net: "vkbot", Err: fmt.Errorf("i/o timeout")}
			}
			go func() {
				time.Sleep(remaining)
				c.recvCond.Broadcast()
			}()
		}
		c.recvCond.Wait()
		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() && time.Now().After(dl) {
			return 0, &net.OpError{Op: "read", Net: "vkbot", Err: fmt.Errorf("i/o timeout")}
		}
	}
	n := copy(buf, c.recvBuf)
	c.recvBuf = c.recvBuf[n:]
	return n, nil
}

func (c *botConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.recvCond.Broadcast()
		close(c.done)
	})
	return nil
}

func (c *botConn) LocalAddr() net.Addr {
	return &vkAddr{id: "local"}
}
func (c *botConn) RemoteAddr() net.Addr {
	return &vkAddr{id: fmt.Sprintf("vk:%d", c.peerID)}
}

func (c *botConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	c.recvCond.Broadcast()
	return nil
}
func (c *botConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.recvCond.Broadcast()
	return nil
}
func (c *botConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}


func (c *botConn) deliver(text string) {
	seq, total, chunkIdx, payload, err := decodeMsg(text)
	if err != nil {
		log.Warn("[vkbot] decode: %v", err)
		return
	}

	c.asmMu.Lock()
	asm, exists := c.frames[seq]
	if !exists {
		asm = &frameAsm{total: total, chunks: make(map[int][]byte)}
		c.frames[seq] = asm
	}
	asm.chunks[chunkIdx] = payload

	if len(asm.chunks) < asm.total {
		c.asmMu.Unlock()
		return
	}

	var frame []byte
	for i := 0; i < asm.total; i++ {
		frame = append(frame, asm.chunks[i]...)
	}
	delete(c.frames, seq)
	c.asmMu.Unlock()

	c.recvMu.Lock()
	c.recvBuf = append(c.recvBuf, frame...)
	c.recvCond.Signal()
	c.recvMu.Unlock()
}


func (c *botConn) userPollLoop(ctx context.Context, cancel context.CancelFunc) {
	defer func() {
		cancel()
		c.Close()
	}()

	server, key, ts, err := c.transport.fetchUserLPServer()
	if err != nil {
		log.Error("[vkbot] userPollLoop: failed to get LP server: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-c.transport.stopChan:
			return
		default:
		}

		msgs, newTS, err := c.transport.pollUser(server, key, ts)
		if err != nil {
			log.Warn("[vkbot] user LP error: %v — refetching", err)
			time.Sleep(2 * time.Second)
			server, key, ts, err = c.transport.fetchUserLPServer()
			if err != nil {
				log.Warn("[vkbot] re-fetch user LP server: %v", err)
				time.Sleep(5 * time.Second)
			}
			continue
		}
		ts = newTS

		for _, text := range msgs {
			c.deliver(text)
		}
	}
}


type vkAddr struct{ id string }

func (a *vkAddr) Network() string { return "vkbot" }
func (a *vkAddr) String() string  { return a.id }
