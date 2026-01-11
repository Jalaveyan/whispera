// Package userstats implements per-user statistics tracking
// Tracks bandwidth, connections, and usage patterns per user
package userstats

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("userstats")

const (
	ModuleName    = "stats.user"
	ModuleVersion = "1.0.0"
)

// UserStats holds statistics for a single user
type UserStats struct {
	mu sync.RWMutex

	// User identification
	UserID   string `json:"user_id"`
	Username string `json:"username,omitempty"`

	// Bandwidth
	BytesIn       uint64 `json:"bytes_in"`
	BytesOut      uint64 `json:"bytes_out"`
	BytesInToday  uint64 `json:"bytes_in_today"`
	BytesOutToday uint64 `json:"bytes_out_today"`

	// Connections
	TotalConnections  uint64 `json:"total_connections"`
	ActiveConnections int32  `json:"active_connections"`
	FailedConnections uint64 `json:"failed_connections"`

	// Sessions
	TotalSessions    uint64        `json:"total_sessions"`
	ActiveSessions   int32         `json:"active_sessions"`
	TotalSessionTime time.Duration `json:"total_session_time"`
	LastSessionStart time.Time     `json:"last_session_start,omitempty"`
	LastActivity     time.Time     `json:"last_activity"`

	// Limits
	BandwidthLimit  uint64 `json:"bandwidth_limit,omitempty"`  // 0 = unlimited
	ConnectionLimit int32  `json:"connection_limit,omitempty"` // 0 = unlimited

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ResetAt   time.Time `json:"reset_at"` // Daily stats reset

	// Usage patterns
	HourlyStats     [24]HourlyBucket  `json:"hourly_stats"`
	TopDestinations map[string]uint64 `json:"top_destinations,omitempty"`
	TopPorts        map[uint16]uint64 `json:"top_ports,omitempty"`
}

// HourlyBucket holds stats for one hour
type HourlyBucket struct {
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
	Requests uint64 `json:"requests"`
}

// NewUserStats creates new user statistics
func NewUserStats(userID string) *UserStats {
	now := time.Now()
	return &UserStats{
		UserID:          userID,
		CreatedAt:       now,
		UpdatedAt:       now,
		ResetAt:         now.Truncate(24 * time.Hour).Add(24 * time.Hour),
		TopDestinations: make(map[string]uint64),
		TopPorts:        make(map[uint16]uint64),
	}
}

// AddBytes adds transferred bytes
func (s *UserStats) AddBytes(in, out uint64) {
	atomic.AddUint64(&s.BytesIn, in)
	atomic.AddUint64(&s.BytesOut, out)
	atomic.AddUint64(&s.BytesInToday, in)
	atomic.AddUint64(&s.BytesOutToday, out)

	// Update hourly stats
	hour := time.Now().Hour()
	s.mu.Lock()
	s.HourlyStats[hour].BytesIn += in
	s.HourlyStats[hour].BytesOut += out
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

// AddConnection increments connection counters
func (s *UserStats) AddConnection() {
	atomic.AddUint64(&s.TotalConnections, 1)
	atomic.AddInt32(&s.ActiveConnections, 1)

	hour := time.Now().Hour()
	s.mu.Lock()
	s.HourlyStats[hour].Requests++
	s.mu.Unlock()
}

// RemoveConnection decrements active connections
func (s *UserStats) RemoveConnection() {
	atomic.AddInt32(&s.ActiveConnections, -1)
}

// AddFailedConnection increments failed connection counter
func (s *UserStats) AddFailedConnection() {
	atomic.AddUint64(&s.FailedConnections, 1)
}

// StartSession starts a new session
func (s *UserStats) StartSession() {
	atomic.AddUint64(&s.TotalSessions, 1)
	atomic.AddInt32(&s.ActiveSessions, 1)

	s.mu.Lock()
	s.LastSessionStart = time.Now()
	s.mu.Unlock()
}

// EndSession ends a session
func (s *UserStats) EndSession() {
	atomic.AddInt32(&s.ActiveSessions, -1)

	s.mu.Lock()
	if !s.LastSessionStart.IsZero() {
		duration := time.Since(s.LastSessionStart)
		s.TotalSessionTime += duration
	}
	s.mu.Unlock()
}

// AddDestination records a destination
func (s *UserStats) AddDestination(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.TopDestinations == nil {
		s.TopDestinations = make(map[string]uint64)
	}

	s.TopDestinations[host]++

	// Keep only top 100
	if len(s.TopDestinations) > 100 {
		// Find and remove smallest
		var minKey string
		minVal := uint64(^uint64(0))
		for k, v := range s.TopDestinations {
			if v < minVal {
				minVal = v
				minKey = k
			}
		}
		if minKey != "" {
			delete(s.TopDestinations, minKey)
		}
	}
}

// AddPort records a destination port
func (s *UserStats) AddPort(port uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.TopPorts == nil {
		s.TopPorts = make(map[uint16]uint64)
	}
	s.TopPorts[port]++
}

// CheckBandwidthLimit checks if user has exceeded bandwidth limit
func (s *UserStats) CheckBandwidthLimit() bool {
	if s.BandwidthLimit == 0 {
		return false
	}
	total := atomic.LoadUint64(&s.BytesInToday) + atomic.LoadUint64(&s.BytesOutToday)
	return total >= s.BandwidthLimit
}

// CheckConnectionLimit checks if user has exceeded connection limit
func (s *UserStats) CheckConnectionLimit() bool {
	if s.ConnectionLimit == 0 {
		return false
	}
	return atomic.LoadInt32(&s.ActiveConnections) >= s.ConnectionLimit
}

// ResetDaily resets daily statistics
func (s *UserStats) ResetDaily() {
	s.mu.Lock()
	defer s.mu.Unlock()

	atomic.StoreUint64(&s.BytesInToday, 0)
	atomic.StoreUint64(&s.BytesOutToday, 0)
	s.ResetAt = time.Now().Truncate(24 * time.Hour).Add(24 * time.Hour)

	// Reset hourly stats
	for i := range s.HourlyStats {
		s.HourlyStats[i] = HourlyBucket{}
	}
}

// UserStatsSnapshot is a copy-safe snapshot of user stats for serialization
type UserStatsSnapshot struct {
	UserID            string            `json:"user_id"`
	Username          string            `json:"username,omitempty"`
	BytesIn           uint64            `json:"bytes_in"`
	BytesOut          uint64            `json:"bytes_out"`
	BytesInToday      uint64            `json:"bytes_in_today"`
	BytesOutToday     uint64            `json:"bytes_out_today"`
	TotalConnections  uint64            `json:"total_connections"`
	ActiveConnections int32             `json:"active_connections"`
	FailedConnections uint64            `json:"failed_connections"`
	TotalSessions     uint64            `json:"total_sessions"`
	ActiveSessions    int32             `json:"active_sessions"`
	TotalSessionTime  time.Duration     `json:"total_session_time"`
	LastActivity      time.Time         `json:"last_activity"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	HourlyStats       [24]HourlyBucket  `json:"hourly_stats"`
	TopDestinations   map[string]uint64 `json:"top_destinations,omitempty"`
	TopPorts          map[uint16]uint64 `json:"top_ports,omitempty"`
}

// GetSnapshot returns a point-in-time snapshot (copy-safe, no mutex)
func (s *UserStats) GetSnapshot() UserStatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshot := UserStatsSnapshot{
		UserID:            s.UserID,
		Username:          s.Username,
		BytesIn:           atomic.LoadUint64(&s.BytesIn),
		BytesOut:          atomic.LoadUint64(&s.BytesOut),
		BytesInToday:      atomic.LoadUint64(&s.BytesInToday),
		BytesOutToday:     atomic.LoadUint64(&s.BytesOutToday),
		TotalConnections:  atomic.LoadUint64(&s.TotalConnections),
		ActiveConnections: atomic.LoadInt32(&s.ActiveConnections),
		FailedConnections: atomic.LoadUint64(&s.FailedConnections),
		TotalSessions:     atomic.LoadUint64(&s.TotalSessions),
		ActiveSessions:    atomic.LoadInt32(&s.ActiveSessions),
		TotalSessionTime:  s.TotalSessionTime,
		LastActivity:      s.LastActivity,
		CreatedAt:         s.CreatedAt,
		UpdatedAt:         s.UpdatedAt,
		HourlyStats:       s.HourlyStats,
		TopDestinations:   make(map[string]uint64),
		TopPorts:          make(map[uint16]uint64),
	}
	for k, v := range s.TopDestinations {
		snapshot.TopDestinations[k] = v
	}
	for k, v := range s.TopPorts {
		snapshot.TopPorts[k] = v
	}
	return snapshot
}

// Config holds stats collector configuration
type Config struct {
	// Persistence
	PersistPath     string
	PersistInterval time.Duration

	// Daily reset
	ResetHour int // Hour of day to reset daily stats (0-23)

	// Memory limits
	MaxUsers int

	// Cleanup
	InactiveTimeout time.Duration // Remove users after this inactivity
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		PersistPath:     "./stats",
		PersistInterval: 5 * time.Minute,
		ResetHour:       0,
		MaxUsers:        100000,
		InactiveTimeout: 30 * 24 * time.Hour, // 30 days
	}
}

// Collector manages per-user statistics
type Collector struct {
	*base.Module
	config *Config

	mu    sync.RWMutex
	users map[string]*UserStats

	stopCh chan struct{}
	wg     sync.WaitGroup

	// Global stats
	totalUsers    uint64
	totalBytesIn  uint64
	totalBytesOut uint64
}

// New creates a new stats collector
func New(cfg *Config) (*Collector, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	c := &Collector{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		users:  make(map[string]*UserStats),
		stopCh: make(chan struct{}),
	}

	// Load persisted stats
	if cfg.PersistPath != "" {
		if err := c.load(); err != nil {
			log.Warn("Failed to load persisted stats: %v", err)
		}
	}

	return c, nil
}

// GetOrCreate gets or creates user stats
func (c *Collector) GetOrCreate(userID string) *UserStats {
	c.mu.RLock()
	stats, ok := c.users[userID]
	c.mu.RUnlock()

	if ok {
		return stats
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check
	if stats, ok = c.users[userID]; ok {
		return stats
	}

	// Check max users
	if len(c.users) >= c.config.MaxUsers {
		c.evictOldest()
	}

	stats = NewUserStats(userID)
	c.users[userID] = stats
	atomic.AddUint64(&c.totalUsers, 1)

	return stats
}

// Get gets user stats if exists
func (c *Collector) Get(userID string) *UserStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.users[userID]
}

// Remove removes user stats
func (c *Collector) Remove(userID string) {
	c.mu.Lock()
	delete(c.users, userID)
	c.mu.Unlock()
}

// evictOldest removes the oldest inactive user
func (c *Collector) evictOldest() {
	var oldestID string
	oldestTime := time.Now()

	for id, stats := range c.users {
		stats.mu.RLock()
		if stats.LastActivity.Before(oldestTime) {
			oldestTime = stats.LastActivity
			oldestID = id
		}
		stats.mu.RUnlock()
	}

	if oldestID != "" {
		delete(c.users, oldestID)
	}
}

// RecordTransfer records a data transfer
func (c *Collector) RecordTransfer(userID string, bytesIn, bytesOut uint64) {
	stats := c.GetOrCreate(userID)
	stats.AddBytes(bytesIn, bytesOut)

	atomic.AddUint64(&c.totalBytesIn, bytesIn)
	atomic.AddUint64(&c.totalBytesOut, bytesOut)
}

// RecordConnection records a connection
func (c *Collector) RecordConnection(userID string, destination string, port uint16) {
	stats := c.GetOrCreate(userID)
	stats.AddConnection()
	stats.AddDestination(destination)
	stats.AddPort(port)
}

// RecordDisconnection records a disconnection
func (c *Collector) RecordDisconnection(userID string) {
	if stats := c.Get(userID); stats != nil {
		stats.RemoveConnection()
	}
}

// Start starts background tasks
func (c *Collector) Start(ctx context.Context) error {
	// Start persistence loop
	if c.config.PersistPath != "" {
		c.wg.Add(1)
		go c.persistLoop()
	}

	// Start daily reset loop
	c.wg.Add(1)
	go c.resetLoop()

	// Start cleanup loop
	c.wg.Add(1)
	go c.cleanupLoop()

	return nil
}

// Stop stops the collector
func (c *Collector) Stop(ctx context.Context) error {
	close(c.stopCh)
	c.wg.Wait()

	// Final persist
	if c.config.PersistPath != "" {
		return c.save()
	}
	return nil
}

// persistLoop periodically saves stats
func (c *Collector) persistLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.PersistInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			if err := c.save(); err != nil {
				log.Warn("Failed to persist stats: %v", err)
			}
		}
	}
}

// resetLoop handles daily resets
func (c *Collector) resetLoop() {
	defer c.wg.Done()

	for {
		// Calculate time until next reset
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), c.config.ResetHour, 0, 0, 0, now.Location())
		if now.After(next) {
			next = next.Add(24 * time.Hour)
		}

		select {
		case <-c.stopCh:
			return
		case <-time.After(time.Until(next)):
			c.resetAllDaily()
		}
	}
}

// resetAllDaily resets daily stats for all users
func (c *Collector) resetAllDaily() {
	c.mu.RLock()
	users := make([]*UserStats, 0, len(c.users))
	for _, stats := range c.users {
		users = append(users, stats)
	}
	c.mu.RUnlock()

	for _, stats := range users {
		stats.ResetDaily()
	}

	log.Info("Daily stats reset for %d users", len(users))
}

// cleanupLoop removes inactive users
func (c *Collector) cleanupLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup removes inactive users
func (c *Collector) cleanup() {
	threshold := time.Now().Add(-c.config.InactiveTimeout)

	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for id, stats := range c.users {
		stats.mu.RLock()
		inactive := stats.LastActivity.Before(threshold)
		stats.mu.RUnlock()

		if inactive && atomic.LoadInt32(&stats.ActiveConnections) == 0 {
			delete(c.users, id)
			removed++
		}
	}

	if removed > 0 {
		log.Info("Cleaned up %d inactive users", removed)
	}
}

// Persistence

// save persists stats to disk
func (c *Collector) save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if err := os.MkdirAll(c.config.PersistPath, 0755); err != nil {
		return err
	}

	// Save each user to separate file
	for id, stats := range c.users {
		snapshot := stats.GetSnapshot()
		data, err := json.Marshal(snapshot)
		if err != nil {
			log.Warn("Failed to marshal stats for %s: %v", id, err)
			continue
		}

		path := filepath.Join(c.config.PersistPath, fmt.Sprintf("%s.json", id))
		if err := os.WriteFile(path, data, 0644); err != nil {
			log.Warn("Failed to save stats for %s: %v", id, err)
		}
	}

	return nil
}

// load loads stats from disk
func (c *Collector) load() error {
	entries, err := os.ReadDir(c.config.PersistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(c.config.PersistPath, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Warn("Failed to read %s: %v", path, err)
			continue
		}

		var stats UserStats
		if err := json.Unmarshal(data, &stats); err != nil {
			log.Warn("Failed to unmarshal %s: %v", path, err)
			continue
		}

		c.users[stats.UserID] = &stats
	}

	log.Info("Loaded stats for %d users", len(c.users))
	return nil
}

// GetAllUsers returns all user IDs
func (c *Collector) GetAllUsers() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ids := make([]string, 0, len(c.users))
	for id := range c.users {
		ids = append(ids, id)
	}
	return ids
}

// GetTopUsers returns top users by bandwidth
func (c *Collector) GetTopUsers(n int) []*UserStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	users := make([]*UserStats, 0, len(c.users))
	for _, stats := range c.users {
		users = append(users, stats)
	}

	// Sort by total bytes
	for i := 0; i < len(users)-1; i++ {
		for j := i + 1; j < len(users); j++ {
			totalI := atomic.LoadUint64(&users[i].BytesIn) + atomic.LoadUint64(&users[i].BytesOut)
			totalJ := atomic.LoadUint64(&users[j].BytesIn) + atomic.LoadUint64(&users[j].BytesOut)
			if totalJ > totalI {
				users[i], users[j] = users[j], users[i]
			}
		}
	}

	if n > len(users) {
		n = len(users)
	}
	return users[:n]
}

// Interface implementation

func (c *Collector) Init(ctx context.Context) error {
	return nil
}

func (c *Collector) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_users":     atomic.LoadUint64(&c.totalUsers),
		"active_users":    len(c.users),
		"total_bytes_in":  atomic.LoadUint64(&c.totalBytesIn),
		"total_bytes_out": atomic.LoadUint64(&c.totalBytesOut),
	}
}
