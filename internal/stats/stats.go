package stats

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
)

type TrafficStats struct {
	mu sync.RWMutex

	totalBytesRx   atomic.Int64
	totalBytesTx   atomic.Int64
	totalPacketsRx atomic.Int64
	totalPacketsTx atomic.Int64

	userStats map[string]*UserStats

	historySize int
	history     []TrafficSnapshot

	startTime time.Time

	log *logger.Logger
}

type UserStats struct {
	UserID       string    `json:"user_id"`
	BytesRx      int64     `json:"bytes_rx"`
	BytesTx      int64     `json:"bytes_tx"`
	PacketsRx    int64     `json:"packets_rx"`
	PacketsTx    int64     `json:"packets_tx"`
	LastActivity time.Time `json:"last_activity"`
	SessionCount int       `json:"session_count"`
	AssignedIP   string    `json:"assigned_ip,omitempty"`
}

type TrafficSnapshot struct {
	Timestamp time.Time `json:"timestamp"`
	BytesRx   int64     `json:"bytes_rx"`
	BytesTx   int64     `json:"bytes_tx"`
	PacketsRx int64     `json:"packets_rx"`
	PacketsTx int64     `json:"packets_tx"`
	UserCount int       `json:"user_count"`
}

type GlobalStats struct {
	TotalBytesRx   int64             `json:"total_bytes_rx"`
	TotalBytesTx   int64             `json:"total_bytes_tx"`
	TotalPacketsRx int64             `json:"total_packets_rx"`
	TotalPacketsTx int64             `json:"total_packets_tx"`
	ActiveUsers    int               `json:"active_users"`
	Uptime         string            `json:"uptime"`
	UptimeSeconds  int64             `json:"uptime_seconds"`
	History        []TrafficSnapshot `json:"history,omitempty"`
}

func New() *TrafficStats {
	return &TrafficStats{
		userStats:   make(map[string]*UserStats),
		historySize: 168,
		history:     make([]TrafficSnapshot, 0, 168),
		startTime:   time.Now(),
		log:         logger.Module("stats"),
	}
}

func (s *TrafficStats) AddRx(userID string, bytes int64) {
	s.totalBytesRx.Add(bytes)
	s.totalPacketsRx.Add(1)

	if userID != "" {
		s.mu.Lock()
		user := s.getOrCreateUser(userID)
		s.mu.Unlock()

		user.BytesRx += bytes
		user.PacketsRx++
		user.LastActivity = time.Now()
	}

	s.log.Debug("RX: user=%s bytes=%d", userID, bytes)
}

func (s *TrafficStats) AddTx(userID string, bytes int64) {
	s.totalBytesTx.Add(bytes)
	s.totalPacketsTx.Add(1)

	if userID != "" {
		s.mu.Lock()
		user := s.getOrCreateUser(userID)
		s.mu.Unlock()

		user.BytesTx += bytes
		user.PacketsTx++
		user.LastActivity = time.Now()
	}

	s.log.Debug("TX: user=%s bytes=%d", userID, bytes)
}

func (s *TrafficStats) AddTraffic(userID string, bytesRx, bytesTx int64) {
	if bytesRx > 0 {
		s.totalBytesRx.Add(bytesRx)
		s.totalPacketsRx.Add(1)
	}
	if bytesTx > 0 {
		s.totalBytesTx.Add(bytesTx)
		s.totalPacketsTx.Add(1)
	}

	if userID != "" {
		s.mu.Lock()
		user := s.getOrCreateUser(userID)
		s.mu.Unlock()

		user.BytesRx += bytesRx
		user.BytesTx += bytesTx
		if bytesRx > 0 {
			user.PacketsRx++
		}
		if bytesTx > 0 {
			user.PacketsTx++
		}
		user.LastActivity = time.Now()
	}
}

func (s *TrafficStats) SetUserIP(userID, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user := s.getOrCreateUser(userID)
	user.AssignedIP = ip

	s.log.Info("User %s assigned IP %s", userID, ip)
}

func (s *TrafficStats) IncrementSessionCount(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user := s.getOrCreateUser(userID)
	user.SessionCount++
}

func (s *TrafficStats) DecrementSessionCount(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user, ok := s.userStats[userID]; ok {
		user.SessionCount--
		if user.SessionCount < 0 {
			user.SessionCount = 0
		}
	}
}

func (s *TrafficStats) getOrCreateUser(userID string) *UserStats {
	if user, ok := s.userStats[userID]; ok {
		return user
	}

	user := &UserStats{
		UserID:       userID,
		LastActivity: time.Now(),
	}
	s.userStats[userID] = user
	return user
}

func (s *TrafficStats) GetGlobalStats() *GlobalStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uptime := time.Since(s.startTime)

	return &GlobalStats{
		TotalBytesRx:   s.totalBytesRx.Load(),
		TotalBytesTx:   s.totalBytesTx.Load(),
		TotalPacketsRx: s.totalPacketsRx.Load(),
		TotalPacketsTx: s.totalPacketsTx.Load(),
		ActiveUsers:    s.countActiveUsers(),
		Uptime:         formatDuration(uptime),
		UptimeSeconds:  int64(uptime.Seconds()),
		History:        s.history,
	}
}

func (s *TrafficStats) GetUserStats(userID string) *UserStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if user, ok := s.userStats[userID]; ok {
		copy := *user
		return &copy
	}
	return nil
}

func (s *TrafficStats) GetAllUserStats() []*UserStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*UserStats, 0, len(s.userStats))
	for _, user := range s.userStats {
		copy := *user
		result = append(result, &copy)
	}
	return result
}

func (s *TrafficStats) TakeSnapshot() {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := TrafficSnapshot{
		Timestamp: time.Now(),
		BytesRx:   s.totalBytesRx.Load(),
		BytesTx:   s.totalBytesTx.Load(),
		PacketsRx: s.totalPacketsRx.Load(),
		PacketsTx: s.totalPacketsTx.Load(),
		UserCount: len(s.userStats),
	}

	s.history = append(s.history, snapshot)

	if len(s.history) > s.historySize {
		s.history = s.history[len(s.history)-s.historySize:]
	}

	s.log.Debug("Snapshot taken: rx=%d tx=%d users=%d",
		s.totalBytesRx.Load(), s.totalBytesTx.Load(), len(s.userStats))
}

func (s *TrafficStats) ResetUserStats(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user, ok := s.userStats[userID]; ok {
		user.BytesRx = 0
		user.BytesTx = 0
		user.PacketsRx = 0
		user.PacketsTx = 0
		s.log.Info("Reset stats for user %s", userID)
	}
}

func (s *TrafficStats) countActiveUsers() int {
	count := 0
	cutoff := time.Now().Add(-5 * time.Minute)

	for _, user := range s.userStats {
		if user.LastActivity.After(cutoff) || user.SessionCount > 0 {
			count++
		}
	}
	return count
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

var (
	globalStats     *TrafficStats
	globalStatsOnce sync.Once
)

func Global() *TrafficStats {
	globalStatsOnce.Do(func() {
		globalStats = New()
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				globalStats.TakeSnapshot()
			}
		}()
	})
	return globalStats
}


func AddRx(userID string, bytes int64) {
	Global().AddRx(userID, bytes)
}

func AddTx(userID string, bytes int64) {
	Global().AddTx(userID, bytes)
}

func AddTraffic(userID string, bytesRx, bytesTx int64) {
	Global().AddTraffic(userID, bytesRx, bytesTx)
}

func GetGlobalStats() *GlobalStats {
	return Global().GetGlobalStats()
}

func GetUserStats(userID string) *UserStats {
	return Global().GetUserStats(userID)
}

func GetAllUserStats() []*UserStats {
	return Global().GetAllUserStats()
}

type TrafficConn struct {
	net.Conn
	UserID    string
	closeOnce sync.Once
}

func (c *TrafficConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		AddRx(c.UserID, int64(n))
	}
	return
}

func (c *TrafficConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		AddTx(c.UserID, int64(n))
	}
	return
}

func (c *TrafficConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		DeregisterConn(c.UserID, c)
		Global().DecrementSessionCount(c.UserID)
	})
	return err
}

func WrapConn(conn net.Conn, userID string) net.Conn {
	tc := &TrafficConn{
		Conn:   conn,
		UserID: userID,
	}
	RegisterConn(userID, tc)
	g := Global()
	g.IncrementSessionCount(userID)
	if addr := conn.RemoteAddr(); addr != nil {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			g.SetUserIP(userID, host)
		}
	}
	return tc
}

var connRegistry struct {
	mu    sync.Mutex
	conns map[string]map[net.Conn]struct{}
}

func init() {
	connRegistry.conns = make(map[string]map[net.Conn]struct{})
}

func RegisterConn(userID string, conn net.Conn) {
	connRegistry.mu.Lock()
	defer connRegistry.mu.Unlock()
	if connRegistry.conns[userID] == nil {
		connRegistry.conns[userID] = make(map[net.Conn]struct{})
	}
	connRegistry.conns[userID][conn] = struct{}{}
}

func DeregisterConn(userID string, conn net.Conn) {
	connRegistry.mu.Lock()
	defer connRegistry.mu.Unlock()
	if s, ok := connRegistry.conns[userID]; ok {
		delete(s, conn)
		if len(s) == 0 {
			delete(connRegistry.conns, userID)
		}
	}
}

func KillUserConns(userID string) int {
	connRegistry.mu.Lock()
	conns := connRegistry.conns[userID]
	delete(connRegistry.conns, userID)
	connRegistry.mu.Unlock()

	for conn := range conns {
		conn.Close()
	}
	return len(conns)
}

func ActiveConnCount(userID string) int {
	connRegistry.mu.Lock()
	defer connRegistry.mu.Unlock()
	return len(connRegistry.conns[userID])
}
