package relay

import (
	"io"
	"net"
	"runtime/debug"
	"sync"
	"time"
	"whispera/common/log"
)

type PooledConn struct {
	conn      net.Conn
	createdAt time.Time
	usedAt    time.Time
	key       string
}

type ConnectionPool struct {
	mu         sync.RWMutex
	conns      map[string][]*PooledConn
	ttl        time.Duration
	maxPerHost int
	quit       chan struct{}
	closeOnce  sync.Once
}

func NewConnectionPool(ttl time.Duration, maxPerHost int) *ConnectionPool {
	pool := &ConnectionPool{
		conns:      make(map[string][]*PooledConn),
		ttl:        ttl,
		maxPerHost: maxPerHost,
		quit:       make(chan struct{}),
	}

	go pool.cleanupLoop()

	return pool
}

func (cp *ConnectionPool) Get(key string) net.Conn {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	conns := cp.conns[key]
	if len(conns) == 0 {
		return nil
	}

	pc := conns[len(conns)-1]
	cp.conns[key] = conns[:len(conns)-1]

	if time.Since(pc.createdAt) > cp.ttl {
		pc.conn.Close()
		return nil
	}

	if tcpConn, ok := pc.conn.(*net.TCPConn); ok {
		tcpConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		buf := make([]byte, 1)
		_, err := tcpConn.Read(buf)
		tcpConn.SetReadDeadline(time.Time{})

		if err != nil && err != io.EOF {
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				pc.conn.Close()
				return nil
			}
		} else if err == io.EOF {
			pc.conn.Close()
			return nil
		}
	}

	pc.usedAt = time.Now()
	return pc.conn
}

func (cp *ConnectionPool) Put(key string, conn net.Conn) {
	if conn == nil {
		return
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	conns := cp.conns[key]
	if len(conns) >= cp.maxPerHost {
		conn.Close()
		return
	}

	pc := &PooledConn{
		conn:      conn,
		createdAt: time.Now(),
		usedAt:    time.Now(),
		key:       key,
	}

	if len(conns) < cap(conns) {
		conns = conns[:len(conns)+1]
		conns[len(conns)-1] = pc
	} else {
		conns = append(conns, pc)
	}
	cp.conns[key] = conns
}
func (cp *ConnectionPool) Discard(conn net.Conn) {
	if conn != nil {
		conn.Close()
	}
}

var connPoolLog = logger.Module("relay_pool")

func (cp *ConnectionPool) cleanupLoop() {
	ticker := time.NewTicker(cp.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-cp.quit:
			return
		case <-ticker.C:
			cp.cleanupSafe()
		}
	}
}

func (cp *ConnectionPool) cleanupSafe() {
	defer func() {
		if r := recover(); r != nil {
			connPoolLog.Error("PANIC in connection pool cleanup: %v\n%s", r, debug.Stack())
		}
	}()
	cp.cleanup()
}

func (cp *ConnectionPool) cleanup() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	now := time.Now()
	for key, conns := range cp.conns {
		writeIdx := 0
		for readIdx := 0; readIdx < len(conns); readIdx++ {
			pc := conns[readIdx]
			if now.Sub(pc.createdAt) <= cp.ttl && now.Sub(pc.usedAt) <= cp.ttl/2 {
				conns[writeIdx] = pc
				writeIdx++
			} else {
				pc.conn.Close()
			}
		}

		if writeIdx == 0 {
			delete(cp.conns, key)
		} else {
			cp.conns[key] = conns[:writeIdx]
		}
	}
}

func (cp *ConnectionPool) Close() {
	cp.closeOnce.Do(func() {
		close(cp.quit)
	})

	cp.mu.Lock()
	defer cp.mu.Unlock()

	for _, conns := range cp.conns {
		for _, pc := range conns {
			pc.conn.Close()
		}
	}
	cp.conns = make(map[string][]*PooledConn)
}

func (cp *ConnectionPool) Stats() map[string]int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	stats := make(map[string]int)
	for key, conns := range cp.conns {
		stats[key] = len(conns)
	}
	return stats
}
