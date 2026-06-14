package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/modules/config"
	"whispera/internal/modules/dns"
	"whispera/internal/modules/proxyagent"
	"whispera/internal/modules/socks5"
	"whispera/internal/modules/tunnel"
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
	Bridge      string     `json:"bridge"`
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

var globalAgent *proxyagent.ProxyAgent

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
	Bridge            string     `json:"bridge"`
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
		Mux: e.Mux, RateLimitKB: e.RateLimitKB, SNI: e.SNI, Bridge: e.Bridge,
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

func startControlServer(ctx context.Context) {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"username": socksUser,
			"password": socksPass,
		})
	})

	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		entries := pool.List()
		views := make([]entryView, 0, len(entries))
		for _, e := range entries {
			views = append(views, toView(e))
		}
		json.NewEncoder(w).Encode(views)
	})

	mux.HandleFunc("/connections/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/connections/"), "/")
		if len(parts) < 2 {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		id, action := parts[0], parts[1]
		entry, ok := pool.Get(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch action {
		case "close":
			entry.mu.Lock()
			entry.Enabled = false
			entry.Status = connStatusDisconnected
			if entry.cancel != nil {
				entry.cancel()
			}
			entry.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "toggle":
			var body struct {
				Enabled bool `json:"enabled"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			entry.Enabled = body.Enabled
			if !body.Enabled && entry.cancel != nil {
				entry.cancel()
				entry.Status = connStatusDisconnected
			}
			entry.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "obfuscation":
			var body struct {
				Enabled bool `json:"enabled"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			entry.Obfuscated = body.Enabled
			entry.ForceObfuscation = body.Enabled
			mgr := entry.mgr
			entry.mu.Unlock()
			if mgr != nil {
				mgr.SetForceObfuscation(body.Enabled)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "transport":
			var body struct {
				Transport string `json:"transport"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Transport != "" {
				entry.mu.Lock()
				entry.Transport = body.Transport
				entry.Status = connStatusConnecting
				entry.mu.Unlock()
				if reconnectEntry != nil {
					go reconnectEntry(entry)
				}
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "port":
			var body struct {
				Port string `json:"port"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Port != "" {
				entry.mu.Lock()
				host := entry.Server
				if idx := strings.LastIndex(host, ":"); idx > 0 {
					host = host[:idx]
				}
				entry.Server = host + ":" + body.Port
				entry.Status = connStatusConnecting
				entry.mu.Unlock()
				if reconnectEntry != nil {
					go reconnectEntry(entry)
				}
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "speed":
			var body struct {
				RateLimitKB int `json:"rate_limit_kb"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			entry.RateLimitKB = body.RateLimitKB
			mgr := entry.mgr
			entry.mu.Unlock()
			if mgr != nil {
				mgr.SetRateLimit(body.RateLimitKB)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "sni":
			var body struct {
				SNI string `json:"sni"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			entry.SNI = body.SNI
			entry.NoSNI = false
			entry.Status = connStatusConnecting
			entry.mu.Unlock()
			if reconnectEntry != nil {
				go reconnectEntry(entry)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "no_sni":
			var body struct {
				Enabled bool `json:"enabled"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			entry.NoSNI = body.Enabled
			if body.Enabled {
				entry.SNI = ""
			}
			entry.Status = connStatusConnecting
			entry.mu.Unlock()
			if reconnectEntry != nil {
				go reconnectEntry(entry)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "bridge":
			var body struct {
				Bridge string `json:"bridge"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			entry.Bridge = body.Bridge
			entry.Status = connStatusConnecting
			entry.mu.Unlock()
			if reconnectEntry != nil {
				go reconnectEntry(entry)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "duplicate":
			entry.mu.Lock()
			newEntry := &TransportEntry{
				ID:               pool.NextID(),
				Transport:        entry.Transport,
				Server:           entry.Server,
				Enabled:          true,
				Obfuscated:       entry.Obfuscated,
				ForceObfuscation: entry.ForceObfuscation,
				SNI:              entry.SNI,
				Bridge:           entry.Bridge,
				RateLimitKB:      entry.RateLimitKB,
				Mux:              entry.Mux,
				Status:           connStatusConnecting,
			}
			entry.mu.Unlock()
			pool.Add(newEntry)
			if reconnectEntry != nil {
				go reconnectEntry(newEntry)
			}
			json.NewEncoder(w).Encode(map[string]string{"id": newEntry.ID})

		case "mux":
			var body struct {
				Enabled bool `json:"enabled"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			entry.Mux = body.Enabled
			entry.Status = connStatusConnecting
			entry.mu.Unlock()
			if reconnectEntry != nil {
				go reconnectEntry(entry)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "encapsulate":
			var body struct {
				WrapIn string `json:"wrap_in"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			if body.WrapIn == id {
				http.Error(w, "cannot encapsulate into itself", http.StatusBadRequest)
				return
			}

			if body.WrapIn != "" {
				if _, exists := pool.Get(body.WrapIn); !exists {
					http.Error(w, "outer tunnel not found", http.StatusNotFound)
					return
				}
			}

			entry.mu.Lock()
			entry.EncapsulatedIn = body.WrapIn
			cb := entry.onEncapsulate
			entry.mu.Unlock()

			if cb != nil {
				go cb(body.WrapIn)
			}

			json.NewEncoder(w).Encode(map[string]string{
				"id":              id,
				"encapsulated_in": body.WrapIn,
			})

		case "tls_fragment":
			var body struct {
				Size int `json:"size"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			mgr := entry.mgr
			entry.mu.Unlock()
			if mgr != nil {
				mgr.SetTLSFragmentSize(body.Size)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "transport_secure":
			var body struct {
				Enabled bool `json:"enabled"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			entry.ForceObfuscation = !body.Enabled
			mgr := entry.mgr
			entry.mu.Unlock()
			if mgr != nil {
				mgr.SetForceObfuscation(!body.Enabled)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		case "profile":
			var body struct {
				Profile string `json:"profile"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			entry.mu.Lock()
			entry.BehavioralProfile = body.Profile
			mgr := entry.mgr
			entry.mu.Unlock()
			if mgr != nil {
				if err := mgr.SetBehavioralProfile(body.Profile); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})

		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	})

	mux.HandleFunc("/agent", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if globalAgent == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"state": "disabled"})
			return
		}
		json.NewEncoder(w).Encode(globalAgent.Stats())
	})

	mux.HandleFunc("/agent/recommend", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if globalAgent == nil {
			http.Error(w, "agent not running", http.StatusServiceUnavailable)
			return
		}
		transport, server := globalAgent.SelectTransport()
		json.NewEncoder(w).Encode(map[string]string{
			"transport": transport,
			"server":    server,
		})
	})

	mux.HandleFunc("/agent/report", func(w http.ResponseWriter, r *http.Request) {
		if globalAgent == nil {
			http.Error(w, "agent not running", http.StatusServiceUnavailable)
			return
		}
		var result proxyagent.ProbeResult
		if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if result.Timestamp.IsZero() {
			result.Timestamp = time.Now()
		}
		globalAgent.ReportResult(result)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	mux.HandleFunc("/connections/split", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		entries := pool.List()
		var addrs []string
		for _, e := range entries {
			e.mu.Lock()
			alive := e.Status == connStatusConnected && e.Enabled && e.mgr != nil
			e.mu.Unlock()
			if alive {
				addrs = append(addrs, e.Server)
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": len(addrs),
			"addrs": addrs,
		})
	})

	mux.HandleFunc("/spoof", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if adminToken != "" && r.Header.Get("X-Admin-Token") != adminToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			json.NewEncoder(w).Encode(map[string]bool{"ok": false})
			return
		}
		var body struct {
			IPs []string `json:"ips"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		for _, e := range pool.List() {
			e.mu.Lock()
			m := e.mgr
			e.mu.Unlock()
			if m != nil {
				m.SetSpoofIPs(body.IPs)
			}
		}
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	mux.HandleFunc("/subscription", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if globalSubscriptionMgr == nil {
			http.Error(w, `{"error":"no subscription configured"}`, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			keys, err := globalSubscriptionMgr.ForceRefresh()
			if err != nil {
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			names := make([]string, 0, len(keys))
			for _, k := range keys {
				if k.Name != "" {
					names = append(names, k.Name)
				} else {
					names = append(names, k.Server)
				}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": names, "count": len(keys)})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"active": globalSubscriptionMgr != nil})
	})

	mux.HandleFunc("/dns", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if globalDNS == nil {
			http.Error(w, "dns not available", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				Upstream string `json:"upstream"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			globalDNS.SetUpstream(body.Upstream)
			json.NewEncoder(w).Encode(map[string]string{"upstream": globalDNS.GetUpstream()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"upstream": globalDNS.GetUpstream()})
	})

	mux.HandleFunc("/multi-bridges", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if globalMultiRouter == nil {
			http.Error(w, "multi-bridge not available", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			h := globalMultiRouter.HTTPHandler()
			h.ServeHTTP(w, r)
		case http.MethodPost:
			var body struct {
				ID      string   `json:"id"`
				Address string   `json:"address"`
				Rules   []string `json:"rules"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" || body.Address == "" {
				http.Error(w, "id and address required", http.StatusBadRequest)
				return
			}
			globalMultiRouter.AddBridge(body.ID, body.Address, body.Rules, nil)
			if newMultiBridgeTunnel != nil {
				go newMultiBridgeTunnel(ctx, body.ID, body.Address, body.Rules)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/multi-bridges/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if globalMultiRouter == nil {
			http.Error(w, "multi-bridge not available", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/multi-bridges/")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		globalMultiRouter.RemoveBridge(id)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	mux.HandleFunc("/speedtest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Target     string `json:"target"`
			Token      string `json:"token"`
			DownloadMB int    `json:"download_mb"`
			UploadMB   int    `json:"upload_mb"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" || req.Token == "" {
			http.Error(w, `{"error":"target and token required"}`, http.StatusBadRequest)
			return
		}
		if req.DownloadMB <= 0 {
			req.DownloadMB = 10
		}
		if req.UploadMB <= 0 {
			req.UploadMB = 5
		}

		result := runSpeedTest(r.Context(), *socksAddr, req.Target, req.Token, req.DownloadMB, req.UploadMB)
		json.NewEncoder(w).Encode(result)
	})

	mux.HandleFunc("/region", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]string{"region": getGlobalRegion()})
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Region string `json:"region"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Region == "" {
			body.Region = "auto"
		}
		globalRegion.Store(body.Region)
		for _, e := range pool.List() {
			if reconnectEntry != nil {
				go reconnectEntry(e)
			}
		}
		json.NewEncoder(w).Encode(map[string]string{"region": body.Region})
	})

	mux.HandleFunc("/regions", func(w http.ResponseWriter, r *http.Request) {
		if len(cfgRegions) == 0 {
			writeJSON := func(v interface{}) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(v)
			}
			writeJSON(map[string]interface{}{"region": getGlobalRegion(), "regions": map[string]interface{}{}})
			return
		}
		type regionInfo struct {
			Servers   []string `json:"servers"`
			LatencyMs float64  `json:"latency_ms,omitempty"`
			Error     string   `json:"error,omitempty"`
		}
		result := make(map[string]*regionInfo, len(cfgRegions))
		var mu sync.Mutex
		var wg sync.WaitGroup
		for code, servers := range cfgRegions {
			code, servers := code, servers
			ri := &regionInfo{Servers: servers}
			result[code] = ri
			wg.Add(1)
			go func() {
				defer wg.Done()
				best := time.Duration(1<<62 - 1)
				for _, srv := range servers {
					conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(context.Background(), "tcp", srv)
					if err != nil {
						continue
					}
					t := time.Now()
					conn.Close()
					lat := time.Since(t)
					if lat < best {
						best = lat
					}
				}
				mu.Lock()
				if best < time.Duration(1<<62-1) {
					ri.LatencyMs = float64(best.Milliseconds())
				} else {
					ri.Error = "unreachable"
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"region":  getGlobalRegion(),
			"regions": result,
		})
	})

	mux.HandleFunc("/global-sni", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]string{"sni": getGlobalSNI()})
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			SNI string `json:"sni"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		globalForceSNI.Store(body.SNI)

		for _, e := range pool.List() {
			e.mu.Lock()
			hasSNI := e.SNI != ""
			e.mu.Unlock()
			if !hasSNI && reconnectEntry != nil {
				go reconnectEntry(e)
			}
		}
		json.NewEncoder(w).Encode(map[string]string{"sni": body.SNI})
	})

	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		if globalLogBuf == nil {
			http.Error(w, "logging to file — use tail on the log file instead", http.StatusNotFound)
			return
		}
		lines := globalLogBuf.Lines()
		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "application/json") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(lines)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, l := range lines {
			io.WriteString(w, l+"\n")
		}
	})

	srv := &http.Server{Addr: controlAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			stdlog.Printf("Control server error: %v", err)
		}
	}()
	stdlog.Printf("Control server listening on %s", controlAddr)
}
