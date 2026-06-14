package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/cache"
	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "session.manager"
	ModuleVersion = "1.0.0"
)

type Config struct {
	MaxSessions     int
	SessionTimeout  time.Duration
	CleanupInterval time.Duration
	EnableMetrics   bool
}

func DefaultConfig() *Config {
	return &Config{
		MaxSessions:     10000,
		SessionTimeout:  24 * time.Hour,
		CleanupInterval: 1 * time.Minute,
		EnableMetrics:   true,
	}
}

func (c *Config) Validate() error {
	if c.MaxSessions <= 0 {
		c.MaxSessions = 10000
	}
	if c.SessionTimeout <= 0 {
		c.SessionTimeout = 24 * time.Hour
	}
	if c.CleanupInterval <= 0 {
		c.CleanupInterval = 1 * time.Minute
	}
	return nil
}

const numShards = 16

type sessionShard struct {
	mu       sync.RWMutex
	sessions map[uint32]*Session
}

type Manager struct {
	*base.Module
	config *Config

	shards [numShards]*sessionShard

	byAddrMu sync.RWMutex
	byAddr   map[string]uint32

	eventChans   []chan interfaces.SessionEvent
	eventChansMu sync.RWMutex

	totalCreated uint64
	totalRemoved uint64

	cleanupStop    chan struct{}
	currentCleanup int32

	cache cache.Cache
}

type Session struct {
	mu           sync.RWMutex
	id           uint32
	clientAddr   net.Addr
	createdAt    time.Time
	lastActivity time.Time
	metadata     map[string]interface{}
	closed       bool

	seed    []byte
	sendKey []byte
	recvKey []byte

	streams   map[uint16]*Stream
	streamsMu sync.RWMutex

	seqSend uint32
	seqRecv uint32

	onClose func(id uint32)
}

type Stream struct {
	id        uint16
	state     StreamState
	buffer    []byte
	closed    bool
	createdAt time.Time
	mu        sync.RWMutex
}

type StreamState int

const (
	StreamStateOpen StreamState = iota
	StreamStateHalfClosed
	StreamStateClosed
)

func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	m := &Manager{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		config:      cfg,
		byAddr:      make(map[string]uint32),
		eventChans:  make([]chan interfaces.SessionEvent, 0),
		cleanupStop: make(chan struct{}),
	}

	for i := 0; i < numShards; i++ {
		m.shards[i] = &sessionShard{
			sessions: make(map[uint32]*Session),
		}
	}

	return m, nil
}

func (m *Manager) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := m.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if sessCfg, ok := cfg.(*Config); ok {
		m.config = sessCfg
	}

	return nil
}

func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	go m.cleanupLoop()

	m.SetHealthy(true, "session manager running")
	m.PublishEvent(events.EventTypeModuleStarted, nil)
	return nil
}

func (m *Manager) Stop() error {
	close(m.cleanupStop)

	for i := 0; i < numShards; i++ {
		shard := m.shards[i]
		shard.mu.Lock()
		for id := range shard.sessions {
			m.removeSessionFromShard(shard, id)
		}
		shard.mu.Unlock()
	}

	m.eventChansMu.Lock()
	for _, ch := range m.eventChans {
		close(ch)
	}
	m.eventChans = nil
	m.eventChansMu.Unlock()

	m.PublishEvent(events.EventTypeModuleStopped, nil)
	return m.Module.Stop()
}

func (m *Manager) GetSession(id uint32) (interfaces.Session, bool) {
	shard := m.getShard(id)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	session, exists := shard.sessions[id]
	if !exists || session.closed {
		return nil, false
	}
	return session, true
}

func (m *Manager) GetSessionByAddr(addr net.Addr) (interfaces.Session, bool) {
	m.byAddrMu.RLock()
	id, exists := m.byAddr[addr.String()]
	m.byAddrMu.RUnlock()

	if !exists {
		return nil, false
	}

	return m.GetSession(id)
}

func (m *Manager) CreateSession(params interfaces.SessionParams) (interfaces.Session, error) {
	total := m.countSessions()
	threshold := m.config.MaxSessions * 4 / 5 // 80%
	if total >= threshold {
		evict := (total - threshold) + 10
		m.evictOldest(evict)
	}
	if m.countSessions() >= m.config.MaxSessions {
		return nil, fmt.Errorf("max sessions reached (%d)", m.config.MaxSessions)
	}

	id, err := m.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	shard := m.getShard(id)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := time.Now()
	session := &Session{
		id:           id,
		clientAddr:   params.ClientAddr,
		createdAt:    now,
		lastActivity: now,
		metadata:     params.Metadata,
		seed:         params.Seed,
		streams:      make(map[uint16]*Stream),
		seqSend:      1,
		seqRecv:      0,
	}

	session.onClose = func(sid uint32) {
		m.RemoveSession(sid)
	}

	shard.sessions[id] = session
	if params.ClientAddr != nil {
		m.byAddrMu.Lock()
		m.byAddr[params.ClientAddr.String()] = id
		m.byAddrMu.Unlock()
	}

	if params.UserID != "" {
		if session.metadata == nil {
			session.metadata = make(map[string]interface{})
		}
		session.metadata["user_id"] = params.UserID
	}

	atomic.AddUint64(&m.totalCreated, 1)
	m.UpdateActivity()

	m.persistSession(session)

	m.publishSessionEvent(interfaces.SessionEventCreated, id, nil)

	return session, nil
}

func (m *Manager) RemoveSession(id uint32) {
	shard := m.getShard(id)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	m.removeSessionFromShard(shard, id)
}

func (m *Manager) removeSessionFromShard(shard *sessionShard, id uint32) {
	session, exists := shard.sessions[id]
	if !exists {
		return
	}

	if session.clientAddr != nil {
		m.byAddrMu.Lock()
		delete(m.byAddr, session.clientAddr.String())
		m.byAddrMu.Unlock()
	}

	session.mu.Lock()
	session.closed = true
	session.mu.Unlock()

	delete(shard.sessions, id)
	atomic.AddUint64(&m.totalRemoved, 1)

	m.unpersistSession(id)

	m.publishSessionEvent(interfaces.SessionEventRemoved, id, nil)
}

func (m *Manager) GetAllSessions() []interfaces.Session {
	sessions := make([]interfaces.Session, 0, m.config.MaxSessions/4)

	for i := 0; i < numShards; i++ {
		shard := m.shards[i]
		shard.mu.RLock()
		for _, s := range shard.sessions {
			if !s.closed {
				sessions = append(sessions, s)
			}
		}
		shard.mu.RUnlock()
	}
	return sessions
}

func (m *Manager) Count() int {
	return m.countSessions()
}

func (m *Manager) countSessions() int {
	total := 0
	for i := 0; i < numShards; i++ {
		shard := m.shards[i]
		shard.mu.RLock()
		total += len(shard.sessions)
		shard.mu.RUnlock()
	}
	return total
}

func (m *Manager) Subscribe(eventType interfaces.SessionEventType) <-chan interfaces.SessionEvent {
	ch := make(chan interfaces.SessionEvent, 100)

	m.eventChansMu.Lock()
	m.eventChans = append(m.eventChans, ch)
	m.eventChansMu.Unlock()

	return ch
}

func (m *Manager) SetMaxSessions(max int) {
	m.config.MaxSessions = max
}

func (m *Manager) SetTimeout(timeout time.Duration) {
	m.config.SessionTimeout = timeout
}

func (m *Manager) HealthCheck() interfaces.HealthStatus {
	status := m.Module.HealthCheck()
	status.Details["session_count"] = m.Count()
	status.Details["total_created"] = atomic.LoadUint64(&m.totalCreated)
	status.Details["total_removed"] = atomic.LoadUint64(&m.totalRemoved)
	status.Details["max_sessions"] = m.config.MaxSessions
	return status
}

func (m *Manager) generateSessionID() (uint32, error) {
	for attempts := 0; attempts < 10; attempts++ {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		id := binary.BigEndian.Uint32(buf[:])
		if id == 0 {
			continue
		}
		shard := m.getShard(id)
		shard.mu.RLock()
		_, exists := shard.sessions[id]
		shard.mu.RUnlock()
		if !exists {
			return id, nil
		}
	}
	return 0, fmt.Errorf("failed to generate unique session ID")
}

func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.cleanupStop:
			return
		case <-ticker.C:
			m.cleanupExpired()
		}
	}
}

func (m *Manager) cleanupExpired() {
	shardIdx := int(atomic.AddInt32(&m.currentCleanup, 1)) % numShards
	shard := m.shards[shardIdx]

	now := time.Now()
	expired := make([]uint32, 0)

	shard.mu.RLock()
	for id, session := range shard.sessions {
		session.mu.RLock()
		lastActivity := session.lastActivity
		session.mu.RUnlock()

		if now.Sub(lastActivity) > m.config.SessionTimeout {
			expired = append(expired, id)
		}
	}
	shard.mu.RUnlock()

	if len(expired) > 0 {
		shard.mu.Lock()
		for _, id := range expired {
			m.removeSessionFromShard(shard, id)
			m.publishSessionEvent(interfaces.SessionEventExpired, id, nil)
		}
		shard.mu.Unlock()
	}
}

func (m *Manager) evictOldest(n int) {
	type candidate struct {
		id    uint32
		t     time.Time
		shard *sessionShard
	}
	candidates := make([]candidate, 0, 64)

	for i := 0; i < numShards; i++ {
		shard := m.shards[i]
		shard.mu.RLock()
		for id, s := range shard.sessions {
			s.mu.RLock()
			last := s.lastActivity
			s.mu.RUnlock()
			candidates = append(candidates, candidate{id, last, shard})
		}
		shard.mu.RUnlock()
	}

	// sort oldest first (simple selection, n is small)
	for i := 0; i < n && i < len(candidates); i++ {
		minIdx := i
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].t.Before(candidates[minIdx].t) {
				minIdx = j
			}
		}
		candidates[i], candidates[minIdx] = candidates[minIdx], candidates[i]
		c := candidates[i]
		c.shard.mu.Lock()
		m.removeSessionFromShard(c.shard, c.id)
		c.shard.mu.Unlock()
		log.Printf("session evicted (idle since %s): %d", time.Since(c.t).Round(time.Second), c.id)
	}
}

func (m *Manager) getShard(id uint32) *sessionShard {
	return m.shards[id%numShards]
}

func (m *Manager) publishSessionEvent(eventType interfaces.SessionEventType, sessionID uint32, data interface{}) {
	event := interfaces.SessionEvent{
		Type:      eventType,
		SessionID: sessionID,
		Timestamp: time.Now(),
		Data:      data,
	}

	m.eventChansMu.RLock()
	defer m.eventChansMu.RUnlock()

	for _, ch := range m.eventChans {
		select {
		case ch <- event:
		default:
		}
	}

	m.PublishEvent(string(eventType), map[string]interface{}{
		"session_id": sessionID,
		"data":       data,
	})
}

func (s *Session) ID() uint32 {
	return s.id
}

func (s *Session) ClientAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientAddr
}

func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

func (s *Session) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()
}

func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	onClose := s.onClose
	id := s.id
	s.mu.Unlock()

	if onClose != nil {
		onClose(id)
	}
	return nil
}

func (s *Session) Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (s *Session) Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func (s *Session) GetStream(streamID uint16) (interfaces.Stream, bool) {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()

	stream, exists := s.streams[streamID]
	if !exists {
		return nil, false
	}
	return stream, true
}

func (s *Session) CreateStream(streamID uint16) (interfaces.Stream, error) {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()

	if _, exists := s.streams[streamID]; exists {
		return nil, fmt.Errorf("stream %d already exists", streamID)
	}

	stream := &Stream{
		id:        streamID,
		state:     StreamStateOpen,
		buffer:    make([]byte, 0),
		createdAt: time.Now(),
	}

	s.streams[streamID] = stream
	return stream, nil
}

func (s *Session) GetNextSeqSend() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.seqSend
	s.seqSend++
	return seq
}

func (s *Session) GetMetadata(key string) interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.metadata == nil {
		return nil
	}
	return s.metadata[key]
}

func (s *Session) SetMetadata(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.metadata == nil {
		s.metadata = make(map[string]interface{})
	}
	s.metadata[key] = value
}

func (st *Stream) ID() uint16 {
	return st.id
}

func (st *Stream) Read(buf []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.closed {
		return 0, fmt.Errorf("stream closed")
	}

	n := copy(buf, st.buffer)
	st.buffer = st.buffer[n:]
	return n, nil
}

func (st *Stream) Write(data []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.closed {
		return 0, fmt.Errorf("stream closed")
	}

	st.buffer = append(st.buffer, data...)
	return len(data), nil
}

func (st *Stream) Close() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.closed = true
	st.state = StreamStateClosed
	return nil
}

func (st *Stream) IsClosed() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.closed
}

type sessionData struct {
	ID           uint32                 `json:"id"`
	ClientAddr   string                 `json:"client_addr"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
	Metadata     map[string]interface{} `json:"metadata"`
	UserID       string                 `json:"user_id,omitempty"`
}

func (m *Manager) persistSession(s *Session) {
	s.mu.RLock()
	data := sessionData{
		ID:           s.id,
		ClientAddr:   s.clientAddr.String(),
		CreatedAt:    s.createdAt,
		LastActivity: s.lastActivity,
		Metadata:     s.metadata,
	}
	if uid, ok := s.metadata["user_id"].(string); ok {
		data.UserID = uid
	}
	s.mu.RUnlock()

	bytes, err := json.Marshal(data)
	if err != nil {
		return
	}

	key := fmt.Sprintf("session:%d", s.id)
	_ = m.cache.Set(context.Background(), key, bytes, m.config.SessionTimeout)
}

func (m *Manager) unpersistSession(id uint32) {
	key := fmt.Sprintf("session:%d", id)
	_ = m.cache.Delete(context.Background(), key)
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
