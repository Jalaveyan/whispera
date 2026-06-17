package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"whispera/common/dns"
	"whispera/core/modules/agent"
	"whispera/core/modules/config"
	"whispera/core/modules/socks5"
	"whispera/core/modules/tunnel"
)

type connStatus string

const (
	connStatusConnecting   connStatus = "connecting"
	connStatusConnected    connStatus = "connected"
	connStatusDisconnected connStatus = "disconnected"
	connStatusFailed       connStatus = "failed"
	connStatusStandby      connStatus = "standby"
	connStatusRST          connStatus = "rst"
)

type TransportEntry struct {
	ID          string     `json:"id"`
	Transport   string     `json:"transport"`
	Server      string     `json:"server"`
	Status      connStatus `json:"status"`
	Enabled     bool       `json:"enabled"`
	Obfuscated  bool       `json:"obfuscated"`
	Mux         bool       `json:"mux"`
	RateLimitKB int        `json:"rate_limit_kb"`
	SNI         string     `json:"sni"`
	BytesUp     uint64     `json:"bytes_up"`
	BytesDown   uint64     `json:"bytes_down"`
	ConnectedAt time.Time  `json:"connected_at,omitempty"`
	Error       string     `json:"error,omitempty"`

	EncapsulatedIn string `json:"encapsulated_in,omitempty"`

	ForceObfuscation bool `json:"force_obfuscation"`

	BehavioralProfile string `json:"behavioral_profile,omitempty"`

	NoSNI bool `json:"no_sni"`

	mgr    *tunnel.Manager
	cancel context.CancelFunc
	mu     sync.Mutex

	onEncapsulate func(outerID string)
}

type TransportPool struct {
	mu      sync.RWMutex
	entries map[string]*TransportEntry
	counter uint64
}

var globalForceSNI atomic.Value

func getGlobalSNI() string {
	if v := globalForceSNI.Load(); v != nil {
		return v.(string)
	}
	return ""
}

var globalRegion atomic.Value

func getGlobalRegion() string {
	if v := globalRegion.Load(); v != nil {
		return v.(string)
	}
	return "auto"
}

var cfgRegions map[string][]string

var pool = &TransportPool{
	entries: make(map[string]*TransportEntry),
}

var reconnectEntry func(e *TransportEntry)

var controlAddr = "127.0.0.1:10801"

var adminToken string

var globalAgent *agent.ProxyAgent

var globalDNS *dns.Resolver
var globalMultiRouter *socks5.MultiRouter
var globalSubscriptionMgr *config.SubscriptionManager

var globalLogBuf *ringLogBuffer

type ringLogBuffer struct {
	mu   sync.Mutex
	buf  []string
	cap_ int
}

func newRingLogBuffer(capacity int) *ringLogBuffer {
	return &ringLogBuffer{buf: make([]string, 0, capacity), cap_: capacity}
}

func (r *ringLogBuffer) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	r.mu.Lock()
	if len(r.buf) >= r.cap_ {
		r.buf = r.buf[1:]
	}
	r.buf = append(r.buf, line)
	r.mu.Unlock()
	return len(p), nil
}

func (r *ringLogBuffer) Lines() []string {
	r.mu.Lock()
	out := make([]string, len(r.buf))
	copy(out, r.buf)
	r.mu.Unlock()
	return out
}

var socksUser string
var socksPass string

func generateSocksAuth() {
	if *connKey != "" {
		socksUser = "whisp"
		h := sha256.Sum256([]byte(*connKey))
		socksPass = hex.EncodeToString(h[:])
		return
	}
	b := make([]byte, 16)
	rand.Read(b)
	socksUser = "w"
	socksPass = hex.EncodeToString(b)
}

var newMultiBridgeTunnel func(ctx context.Context, bridgeID, bridgeAddr string, rules []string)

func (p *TransportPool) Add(entry *TransportEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries[entry.ID] = entry
}

func (p *TransportPool) Get(id string) (*TransportEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.entries[id]
	return e, ok
}

func (p *TransportPool) List() []*TransportEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*TransportEntry, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, e)
	}
	return out
}

func (p *TransportPool) NextID() string {
	n := atomic.AddUint64(&p.counter, 1)
	return fmt.Sprintf("conn-%d", n)
}

func (p *TransportPool) AnyConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, e := range p.entries {
		if e.Status == connStatusConnected && e.Enabled {
			return true
		}
	}
	return false
}

type entryView struct {
	ID                string     `json:"id"`
	Transport         string     `json:"transport"`
	Server            string     `json:"server"`
	Status            connStatus `json:"status"`
	Enabled           bool       `json:"enabled"`
	Obfuscated        bool       `json:"obfuscated"`
	Mux               bool       `json:"mux"`
	RateLimitKB       int        `json:"rate_limit_kb"`
	SNI               string     `json:"sni"`
	BytesUp           uint64     `json:"bytes_up"`
	BytesDown         uint64     `json:"bytes_down"`
	ConnectedAt       time.Time  `json:"connected_at,omitempty"`
	Error             string     `json:"error,omitempty"`
	EncapsulatedIn    string     `json:"encapsulated_in,omitempty"`
	ForceObfuscation  bool       `json:"force_obfuscation"`
	BehavioralProfile string     `json:"behavioral_profile,omitempty"`
	NoSNI             bool       `json:"no_sni"`
	QualityRTTMs      int64      `json:"quality_rtt_ms,omitempty"`
	QualityMissedKAs  int        `json:"quality_missed_kas,omitempty"`
}

func toView(e *TransportEntry) entryView {
	e.mu.Lock()
	defer e.mu.Unlock()
	var qualityRTT int64
	var missedKAs int
	if e.mgr != nil {
		e.BytesUp, e.BytesDown = e.mgr.Stats()
		e.ForceObfuscation = e.mgr.IsForceObfuscation()
		rtt, missed := e.mgr.GetQualityMetrics()
		qualityRTT = rtt.Milliseconds()
		missedKAs = missed
	}
	return entryView{
		ID: e.ID, Transport: e.Transport, Server: e.Server,
		Status: e.Status, Enabled: e.Enabled, Obfuscated: e.Obfuscated,
		Mux: e.Mux, RateLimitKB: e.RateLimitKB, SNI: e.SNI,
		BytesUp: e.BytesUp, BytesDown: e.BytesDown,
		ConnectedAt: e.ConnectedAt, Error: e.Error,
		EncapsulatedIn:    e.EncapsulatedIn,
		ForceObfuscation:  e.ForceObfuscation,
		BehavioralProfile: e.BehavioralProfile,
		NoSNI:             e.NoSNI,
		QualityRTTMs:      qualityRTT,
		QualityMissedKAs:  missedKAs,
	}
}
