package keylimits

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// DenyReason describes why admission failed. Values are stable and intended
// to be surfaced to the client as part of a human-readable error.
type DenyReason string

const (
	ReasonNone       DenyReason = ""
	ReasonActiveCap  DenyReason = "active_cap"
	ReasonSoftIPCap  DenyReason = "soft_ip_cap"
	ReasonRateLimit  DenyReason = "rate_limit"
)

// Limits holds per-key policy. Zero values mean "unlimited".
type Limits struct {
	MaxActiveSessions int           `json:"max_active_sessions"`
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
	KeyID          string        `json:"key_id"`
	ActiveSessions int           `json:"active_sessions"`
	UniqueIPs      int           `json:"unique_ips"`
	Limits         Limits        `json:"limits"`
	Sessions       []Session     `json:"sessions,omitempty"`
	BurstWindow    int           `json:"burst_window"`
	BurstSince     time.Time     `json:"burst_since,omitempty"`
}

type burstWindow struct {
	since time.Time
	count int
}

type Manager struct {
	mu             sync.RWMutex
	defaultLimits  Limits
	keyLimits      map[string]Limits
	sessions       map[string]map[string]*Session // keyID -> sessionID -> Session
	burst          map[string]*burstWindow
	onSessionsDrop func(keyID, sessionID string)
}

func New(defaults Limits) *Manager {
	m := &Manager{
		defaultLimits: defaults,
		keyLimits:     make(map[string]Limits),
		sessions:      make(map[string]map[string]*Session),
		burst:         make(map[string]*burstWindow),
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
	defer m.mu.Unlock()
	if km, ok := m.sessions[keyID]; ok {
		delete(km, sessionID)
		if len(km) == 0 {
			delete(m.sessions, keyID)
		}
	}
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
	defer m.mu.Unlock()

	now := time.Now()
	for keyID, km := range m.sessions {
		ttl := m.limitsFor(keyID).SessionTTL
		if ttl <= 0 {
			ttl = 30 * time.Minute
		}
		for sid, s := range km {
			if now.Sub(s.LastSeen) > ttl {
				delete(km, sid)
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
}

func countUniqueIPs(km map[string]*Session, adding string) int {
	seen := make(map[string]struct{}, len(km)+1)
	for _, s := range km {
		seen[s.RemoteIP] = struct{}{}
	}
	seen[adding] = struct{}{}
	return len(seen)
}
