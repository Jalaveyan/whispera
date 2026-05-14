package keylimits

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// DenyReason describes why admission failed. Values are stable and intended
// to be surfaced to the client as part of a human-readable error.
type DenyReason string

const (
	ReasonNone      DenyReason = ""
	ReasonActiveCap DenyReason = "active_cap"
	ReasonGlobalCap DenyReason = "global_cap"
	ReasonSoftIPCap DenyReason = "soft_ip_cap"
	ReasonRateLimit DenyReason = "rate_limit"
)

// Limits holds per-key policy. Zero values mean "unlimited".
// GlobalCap is server-wide: it is always read from the Manager default,
// never from per-key overrides.
type Limits struct {
	MaxActiveSessions int           `json:"max_active_sessions"`
	GlobalCap         int           `json:"global_cap"`
	SoftIPCap         int           `json:"soft_ip_cap"`
	BurstPerMinute    int           `json:"burst_per_minute"`
	SessionTTL        time.Duration `json:"session_ttl"`
}

type Session struct {
	SessionID string
	KeyID     string
	RemoteIP  string
	StartedAt time.Time
	LastSeen  time.Time
}

type Snapshot struct {
	KeyID          string    `json:"key_id"`
	ActiveSessions int       `json:"active_sessions"`
	UniqueIPs      int       `json:"unique_ips"`
	Limits         Limits    `json:"limits"`
	Sessions       []Session `json:"sessions,omitempty"`
	BurstWindow    int       `json:"burst_window"`
	BurstSince     time.Time `json:"burst_since,omitempty"`
}

type burstWindow struct {
	since time.Time
	count int
}

type Manager struct {
	mu            sync.RWMutex
	defaultLimits Limits
	keyLimits     map[string]Limits
	sessions      map[string]map[string]*Session // keyID -> sessionID -> Session
	burst         map[string]*burstWindow
	totalSessions atomic.Int64 // server-wide session count (no lock needed)

	closersMu sync.Mutex
	closers   map[string]map[string]func() // keyID -> sessionID -> conn.Close

	onSessionsDrop func(keyID, sessionID string)
}

func New(defaults Limits) *Manager {
	m := &Manager{
		defaultLimits: defaults,
		keyLimits:     make(map[string]Limits),
		sessions:      make(map[string]map[string]*Session),
		burst:         make(map[string]*burstWindow),
		closers:       make(map[string]map[string]func()),
	}
	go m.gcLoop()
	return m
}

func (m *Manager) SetLimits(keyID string, l Limits) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keyLimits[keyID] = l
}

func (m *Manager) ClearLimits(keyID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keyLimits, keyID)
}

func (m *Manager) SetDefault(l Limits) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultLimits = l
}

func (m *Manager) limitsFor(keyID string) Limits {
	if l, ok := m.keyLimits[keyID]; ok {
		return l
	}
	return m.defaultLimits
}

// deleteSession removes a session from the map and returns true if it was present.
// Must be called with m.mu held for writing.
func (m *Manager) deleteSession(keyID, sessionID string) bool {
	km, ok := m.sessions[keyID]
	if !ok {
		return false
	}
	if _, ok := km[sessionID]; !ok {
		return false
	}
	delete(km, sessionID)
	if len(km) == 0 {
		delete(m.sessions, keyID)
	}
	return true
}

// Admit attempts to register a new session. On success returns an admission
// handle that MUST be closed via Release when the session ends.
// On denial returns a non-empty DenyReason and a human-readable message.
func (m *Manager) Admit(keyID, sessionID, remoteIP string) (DenyReason, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	l := m.limitsFor(keyID)

	if l.BurstPerMinute > 0 {
		bw := m.burst[keyID]
		now := time.Now()
		if bw == nil || now.Sub(bw.since) > time.Minute {
			bw = &burstWindow{since: now, count: 0}
			m.burst[keyID] = bw
		}
		if bw.count >= l.BurstPerMinute {
			return ReasonRateLimit, "too many reconnects in the last minute — wait and try again"
		}
		bw.count++
	}

	// GlobalCap is always the server default — per-key overrides don't affect it.
	if cap := m.defaultLimits.GlobalCap; cap > 0 {
		if int(m.totalSessions.Load()) >= cap {
			return ReasonGlobalCap, fmt.Sprintf(
				"Server connection limit reached (%d). Try again later.",
				cap,
			)
		}
	}

	km := m.sessions[keyID]
	if km == nil {
		km = make(map[string]*Session)
		m.sessions[keyID] = km
	}

	if l.MaxActiveSessions > 0 && len(km) >= l.MaxActiveSessions {
		return ReasonActiveCap, fmt.Sprintf(
			"Active connection limit reached (%d). To avoid this, obtain a subscription from your proxy provider or wait until another device disconnects.",
			l.MaxActiveSessions,
		)
	}

	if l.SoftIPCap > 0 {
		unique := countUniqueIPs(km, remoteIP)
		if unique > l.SoftIPCap {
			return ReasonSoftIPCap, fmt.Sprintf(
				"Too many distinct IPs on this key (%d > %d) — shared usage suspected.",
				unique, l.SoftIPCap,
			)
		}
	}

	km[sessionID] = &Session{
		SessionID: sessionID,
		KeyID:     keyID,
		RemoteIP:  remoteIP,
		StartedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	m.totalSessions.Add(1)
	return ReasonNone, ""
}

func (m *Manager) Touch(keyID, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if km, ok := m.sessions[keyID]; ok {
		if s, ok := km[sessionID]; ok {
			s.LastSeen = time.Now()
		}
	}
}

func (m *Manager) Release(keyID, sessionID string) {
	m.mu.Lock()
	deleted := m.deleteSession(keyID, sessionID)
	m.mu.Unlock()
	if deleted {
		m.totalSessions.Add(-1)
	}

	m.closersMu.Lock()
	if km, ok := m.closers[keyID]; ok {
		delete(km, sessionID)
		if len(km) == 0 {
			delete(m.closers, keyID)
		}
	}
	m.closersMu.Unlock()
}

// RegisterCloser associates a conn.Close function with an admitted session.
// Called by the connection handler after the connection is fully set up.
// The closer is called by EvictOldest and gcExpired to forcibly terminate the TCP connection.
func (m *Manager) RegisterCloser(keyID, sessionID string, fn func()) {
	m.closersMu.Lock()
	defer m.closersMu.Unlock()
	km := m.closers[keyID]
	if km == nil {
		km = make(map[string]func())
		m.closers[keyID] = km
	}
	km[sessionID] = fn
}

// EvictOldest closes the n oldest sessions for a specific key (client).
// Only that client's sessions are touched — other clients are unaffected.
// Sessions are removed from the admission map synchronously so that a retry
// Admit immediately sees the freed slots.
func (m *Manager) EvictOldest(keyID string, n int) {
	type entry struct {
		keyID     string
		sessionID string
		startedAt time.Time
	}

	m.mu.RLock()
	all := make([]entry, 0, 16)
	for sid, s := range m.sessions[keyID] {
		all = append(all, entry{keyID, sid, s.StartedAt})
	}
	m.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool {
		return all[i].startedAt.Before(all[j].startedAt)
	})
	if n > len(all) {
		n = len(all)
	}

	// Remove sessions from the map synchronously so a retry Admit sees freed slots.
	m.mu.Lock()
	var deleted int64
	for i := 0; i < n; i++ {
		e := all[i]
		if m.deleteSession(e.keyID, e.sessionID) {
			deleted++
			log.Printf("[keylimits] evicting session %s/%s (age %s)",
				e.keyID, e.sessionID, time.Since(e.startedAt).Round(time.Second))
		}
	}
	m.mu.Unlock()
	if deleted > 0 {
		m.totalSessions.Add(-deleted)
	}

	m.closersMu.Lock()
	toClose := make([]func(), 0, n)
	for i := 0; i < n; i++ {
		e := all[i]
		if km, ok := m.closers[e.keyID]; ok {
			if fn, ok := km[e.sessionID]; ok {
				toClose = append(toClose, fn)
				delete(km, e.sessionID)
			}
			if len(km) == 0 {
				delete(m.closers, e.keyID)
			}
		}
	}
	m.closersMu.Unlock()

	for _, fn := range toClose {
		fn()
	}
}

// EvictOldestGlobal closes the n oldest sessions server-wide (across all keys).
// Used when the global server cap is reached. Sessions are removed from the
// admission map synchronously so a retry Admit immediately sees freed slots.
func (m *Manager) EvictOldestGlobal(n int) {
	type entry struct {
		keyID     string
		sessionID string
		startedAt time.Time
	}

	m.mu.RLock()
	all := make([]entry, 0, 256)
	for kid, km := range m.sessions {
		for sid, s := range km {
			all = append(all, entry{kid, sid, s.StartedAt})
		}
	}
	m.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool {
		return all[i].startedAt.Before(all[j].startedAt)
	})
	if n > len(all) {
		n = len(all)
	}

	m.mu.Lock()
	var deleted int64
	for i := 0; i < n; i++ {
		e := all[i]
		if m.deleteSession(e.keyID, e.sessionID) {
			deleted++
			log.Printf("[keylimits] global-evict session %s/%s (age %s)",
				e.keyID, e.sessionID, time.Since(e.startedAt).Round(time.Second))
		}
	}
	m.mu.Unlock()
	if deleted > 0 {
		m.totalSessions.Add(-deleted)
	}

	m.closersMu.Lock()
	toClose := make([]func(), 0, n)
	for i := 0; i < n; i++ {
		e := all[i]
		if km, ok := m.closers[e.keyID]; ok {
			if fn, ok := km[e.sessionID]; ok {
				toClose = append(toClose, fn)
				delete(km, e.sessionID)
			}
			if len(km) == 0 {
				delete(m.closers, e.keyID)
			}
		}
	}
	m.closersMu.Unlock()

	for _, fn := range toClose {
		fn()
	}
}

// TotalSessions returns the current server-wide active session count.
func (m *Manager) TotalSessions() int {
	return int(m.totalSessions.Load())
}

func (m *Manager) Snapshot(keyID string) Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	l := m.limitsFor(keyID)
	km := m.sessions[keyID]
	snap := Snapshot{KeyID: keyID, Limits: l}
	if bw := m.burst[keyID]; bw != nil {
		snap.BurstWindow = bw.count
		snap.BurstSince = bw.since
	}
	if km == nil {
		return snap
	}
	snap.ActiveSessions = len(km)
	ipSet := make(map[string]struct{}, len(km))
	snap.Sessions = make([]Session, 0, len(km))
	for _, s := range km {
		ipSet[s.RemoteIP] = struct{}{}
		snap.Sessions = append(snap.Sessions, *s)
	}
	snap.UniqueIPs = len(ipSet)
	sort.Slice(snap.Sessions, func(i, j int) bool {
		return snap.Sessions[i].StartedAt.Before(snap.Sessions[j].StartedAt)
	})
	return snap
}

func (m *Manager) SnapshotAll() []Snapshot {
	m.mu.RLock()
	keys := make([]string, 0, len(m.sessions))
	for k := range m.sessions {
		keys = append(keys, k)
	}
	m.mu.RUnlock()

	out := make([]Snapshot, 0, len(keys))
	for _, k := range keys {
		out = append(out, m.Snapshot(k))
	}
	return out
}

func (m *Manager) gcLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		m.gcExpired()
	}
}

func (m *Manager) gcExpired() {
	m.mu.Lock()

	now := time.Now()
	type dead struct{ keyID, sessionID string }
	var expired []dead

	// Snapshot which sessions have an active closer (= live connection).
	// Sessions with a closer are owned by a live conn and will be released
	// via Release() when that conn closes — TTL must not evict them.
	m.closersMu.Lock()
	hasCloser := make(map[string]map[string]bool, len(m.closers))
	for kid, km := range m.closers {
		inner := make(map[string]bool, len(km))
		for sid := range km {
			inner[sid] = true
		}
		hasCloser[kid] = inner
	}
	m.closersMu.Unlock()

	for keyID, km := range m.sessions {
		ttl := m.limitsFor(keyID).SessionTTL
		if ttl <= 0 {
			ttl = 30 * time.Minute
		}
		for sid, s := range km {
			if hasCloser[keyID][sid] {
				continue // live connection — never evict by TTL
			}
			if now.Sub(s.LastSeen) > ttl {
				delete(km, sid)
				expired = append(expired, dead{keyID, sid})
			}
		}
		if len(km) == 0 {
			delete(m.sessions, keyID)
		}
	}
	for keyID, bw := range m.burst {
		if now.Sub(bw.since) > 5*time.Minute {
			delete(m.burst, keyID)
		}
	}
	m.mu.Unlock()

	if len(expired) > 0 {
		m.totalSessions.Add(-int64(len(expired)))
	}

	// Close expired connections outside the sessions lock.
	if len(expired) > 0 {
		m.closersMu.Lock()
		fns := make([]func(), 0, len(expired))
		for _, d := range expired {
			if km, ok := m.closers[d.keyID]; ok {
				if fn, ok := km[d.sessionID]; ok {
					fns = append(fns, fn)
					delete(km, d.sessionID)
				}
				if len(km) == 0 {
					delete(m.closers, d.keyID)
				}
			}
		}
		m.closersMu.Unlock()
		for _, fn := range fns {
			fn()
		}
	}
}

func countUniqueIPs(km map[string]*Session, adding string) int {
	seen := make(map[string]struct{}, len(km)+1)
	for _, s := range km {
		seen[s.RemoteIP] = struct{}{}
	}
	seen[adding] = struct{}{}
	return len(seen)
}
