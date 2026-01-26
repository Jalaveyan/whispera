// Package relay provides stream management for multiplexed connections
package relay

import (
	"net"
	"sync"
	"time"
)

// PooledConn wraps a net.Conn with metadata for pooling
type PooledConn struct {
	conn      net.Conn
	createdAt time.Time
	usedAt    time.Time
	key       string // target address key
}

// ConnectionPool управляет переиспользованием TCP соединений
// ОПТИМИЗАЦИЯ: Избегает handshake overhead на повторные подключения к тому же адресу
type ConnectionPool struct {
	mu       sync.RWMutex
	conns    map[string][]*PooledConn // key: "host:port"
	ttl      time.Duration             // Max age for a pooled connection
	maxPerHost int                      // Max connections to keep per host
}

// NewConnectionPool создает новый пул соединений
func NewConnectionPool(ttl time.Duration, maxPerHost int) *ConnectionPool {
	pool := &ConnectionPool{
		conns:      make(map[string][]*PooledConn),
		ttl:        ttl,
		maxPerHost: maxPerHost,
	}
	
	// Фоновый goroutine для очистки старых соединений
	go pool.cleanupLoop()
	
	return pool
}

// Get возвращает переиспользуемое соединение или nil
func (cp *ConnectionPool) Get(key string) net.Conn {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	conns := cp.conns[key]
	if len(conns) == 0 {
		return nil
	}
	
	// Получаем последнее соединение из пула (LIFO для лучшей cache locality)
	pc := conns[len(conns)-1]
	cp.conns[key] = conns[:len(conns)-1]
	
	// Проверяем, не истекло ли время жизни
	if time.Since(pc.createdAt) > cp.ttl {
		pc.conn.Close()
		return nil
	}
	
	pc.usedAt = time.Now()
	return pc.conn
}

// Put возвращает соединение в пул для переиспользования
func (cp *ConnectionPool) Put(key string, conn net.Conn) {
	if conn == nil {
		return
	}
	
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	// Проверяем количество соединений для этого хоста
	conns := cp.conns[key]
	if len(conns) >= cp.maxPerHost {
		// Пул переполнен, закрываем соединение
		conn.Close()
		return
	}
	
	pc := &PooledConn{
		conn:      conn,
		createdAt: time.Now(),
		usedAt:    time.Now(),
		key:       key,
	}
	
	// ОПТИМИЗАЦИЯ: Избегаем append если возможно - переиспользуем capacity
	if len(conns) < cap(conns) {
		// Есть место в pre-allocated slice - используем его без allocations
		conns = conns[:len(conns)+1]
		conns[len(conns)-1] = pc
	} else {
		// Нужно расширить - только тогда используем append
		conns = append(conns, pc)
	}
	cp.conns[key] = conns
}


// Discard закрывает соединение и не добавляет его в пул
func (cp *ConnectionPool) Discard(conn net.Conn) {
	if conn != nil {
		conn.Close()
	}
}

// cleanupLoop периодически очищает старые соединения
func (cp *ConnectionPool) cleanupLoop() {
	ticker := time.NewTicker(cp.ttl / 2) // Чистим в 2 раза чаще, чем TTL
	defer ticker.Stop()
	
	for range ticker.C {
		cp.cleanup()
	}
}

// cleanup удаляет истекшие соединения
func (cp *ConnectionPool) cleanup() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	now := time.Now()
	for key, conns := range cp.conns {
		// ОПТИМИЗАЦИЯ: Избегаем append - используем индекс для перезаписи живых соединений
		writeIdx := 0
		for readIdx := 0; readIdx < len(conns); readIdx++ {
			pc := conns[readIdx]
			if now.Sub(pc.createdAt) <= cp.ttl && now.Sub(pc.usedAt) <= cp.ttl/2 {
				// Живое соединение - переместить на writeIdx
				conns[writeIdx] = pc
				writeIdx++
			} else {
				// Мёртвое соединение - закрыть и пропустить
				pc.conn.Close()
			}
		}
		
		// Обновляем slice на живые соединения
		if writeIdx == 0 {
			delete(cp.conns, key)
		} else {
			cp.conns[key] = conns[:writeIdx]
		}
	}
}

// Close закрывает все соединения в пуле
func (cp *ConnectionPool) Close() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	for _, conns := range cp.conns {
		for _, pc := range conns {
			pc.conn.Close()
		}
	}
	cp.conns = make(map[string][]*PooledConn)
}

// Stats возвращает статистику пула
func (cp *ConnectionPool) Stats() map[string]int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	
	stats := make(map[string]int)
	for key, conns := range cp.conns {
		stats[key] = len(conns)
	}
	return stats
}
