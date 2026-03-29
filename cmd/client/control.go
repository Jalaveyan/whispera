package main

import (
	"context"
	"encoding/json"
	"fmt"
	stdlog "log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/modules/dnsmodule"
	"whispera/internal/modules/mitm"
	"whispera/internal/modules/proxyagent"
	relaymod "whispera/internal/modules/relay"
	"whispera/internal/modules/socks5"
	"whispera/internal/modules/tunnel"
)

type connStatus string

const (
	connStatusConnecting   connStatus = "connecting"
	connStatusConnected    connStatus = "connected"
	connStatusDisconnected connStatus = "disconnected"
	connStatusFailed       connStatus = "failed"
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

var pool = &TransportPool{
	entries: make(map[string]*TransportEntry),
}

var reconnectEntry func(e *TransportEntry)

var controlAddr = "127.0.0.1:10801"

var adminToken string

var globalAgent *proxyagent.ProxyAgent

type p2pState struct {
	mu         sync.Mutex
	client     *relaymod.P2PClient
	relayAddr  string
	registered bool
	connected  bool
}

var globalP2P = &p2pState{}

var globalDNS *dnsmodule.Resolver
var globalMITM *mitm.Proxy
var globalMultiRouter *socks5.MultiRouter

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

func (p *TransportPool) Remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.entries, id)
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
	ID             string     `json:"id"`
	Transport      string     `json:"transport"`
	Server         string     `json:"server"`
	Status         connStatus `json:"status"`
	Enabled        bool       `json:"enabled"`
	Obfuscated     bool       `json:"obfuscated"`
	Mux            bool       `json:"mux"`
	RateLimitKB    int        `json:"rate_limit_kb"`
	SNI            string     `json:"sni"`
	Bridge         string     `json:"bridge"`
	BytesUp        uint64     `json:"bytes_up"`
	BytesDown      uint64     `json:"bytes_down"`
	ConnectedAt    time.Time  `json:"connected_at,omitempty"`
	Error          string     `json:"error,omitempty"`
	EncapsulatedIn    string     `json:"encapsulated_in,omitempty"`
	ForceObfuscation  bool       `json:"force_obfuscation"`
	BehavioralProfile string     `json:"behavioral_profile,omitempty"`
}

func toView(e *TransportEntry) entryView {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mgr != nil {
		e.BytesUp, e.BytesDown = e.mgr.Stats()
		e.ForceObfuscation = e.mgr.IsForceObfuscation()
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
	}
}

func startControlServer(ctx context.Context) {
	mux := http.NewServeMux()

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

	mux.HandleFunc("/p2p", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		globalP2P.mu.Lock()
		defer globalP2P.mu.Unlock()
		peerID := ""
		if globalP2P.client != nil {
			peerID = globalP2P.client.PeerID()
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"registered": globalP2P.registered,
			"connected":  globalP2P.connected,
			"relay_addr": globalP2P.relayAddr,
			"peer_id":    peerID,
		})
	})

	mux.HandleFunc("/p2p/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			RelayAddr string `json:"relay_addr"`
			Secret    string `json:"secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RelayAddr == "" {
			http.Error(w, "relay_addr required", http.StatusBadRequest)
			return
		}

		globalP2P.mu.Lock()
		if globalP2P.client != nil {
			globalP2P.client.Close()
		}
		client := relaymod.NewP2PClient(body.RelayAddr, []byte(body.Secret))
		globalP2P.client = client
		globalP2P.relayAddr = body.RelayAddr
		globalP2P.registered = false
		globalP2P.connected = false
		globalP2P.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.Register(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		globalP2P.mu.Lock()
		globalP2P.registered = true
		globalP2P.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"peer_id": client.PeerID()})
	})

	mux.HandleFunc("/p2p/connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Target    string `json:"target"`
			RelayAddr string `json:"relay_addr"`
			Secret    string `json:"secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Target == "" {
			http.Error(w, "target required", http.StatusBadRequest)
			return
		}

		globalP2P.mu.Lock()
		client := globalP2P.client
		if client == nil || body.RelayAddr != "" {
			client = relaymod.NewP2PClient(func() string {
				if body.RelayAddr != "" {
					return body.RelayAddr
				}
				return globalP2P.relayAddr
			}(), []byte(body.Secret))
			globalP2P.client = client
			if body.RelayAddr != "" {
				globalP2P.relayAddr = body.RelayAddr
			}
		}
		globalP2P.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := client.ConnectTo(ctx, body.Target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_ = conn

		globalP2P.mu.Lock()
		globalP2P.connected = true
		globalP2P.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	mux.HandleFunc("/p2p/disconnect", func(w http.ResponseWriter, r *http.Request) {
		globalP2P.mu.Lock()
		if globalP2P.client != nil {
			globalP2P.client.Close()
			globalP2P.client = nil
		}
		globalP2P.registered = false
		globalP2P.connected = false
		globalP2P.mu.Unlock()
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

	mux.HandleFunc("/mitm/ca", func(w http.ResponseWriter, r *http.Request) {
		if globalMITM == nil {
			http.Error(w, "mitm not running", http.StatusServiceUnavailable)
			return
		}
		pem := globalMITM.CACertPEM()
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="whispera-ca.crt"`)
		w.Write(pem)
	})

	mux.HandleFunc("/mitm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		running := globalMITM != nil
		addr := ""
		if running {
			addr = globalMITM.ListenAddr()
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"running": running, "addr": addr})
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
