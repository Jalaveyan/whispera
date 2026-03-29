package socks5

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// RouteRule maps a pattern to a named bridge tunnel.
// Pattern forms:
//   - "*.example.com"  — domain suffix match
//   - "example.com"    — exact domain match
//   - "1.2.3.4"        — exact IP match
//   - "10.0.0.0/8"     — CIDR match
//   - "process:name"   — process name match (evaluated by the caller via RouteByProcess)
//   - "*"              — catch-all (matches everything)
type RouteRule struct {
	ID       string `json:"id"`
	Pattern  string `json:"pattern"`
	BridgeID string `json:"bridge_id"`
}

// BridgeEntry holds a named tunnel and its routing rules.
type BridgeEntry struct {
	ID      string       `json:"id"`
	Address string       `json:"address"`
	Rules   []*RouteRule `json:"rules"`
	tunnel  TunnelManager
}

// MultiRouter implements TunnelManager. It routes each connection to one of
// several tunnels based on registered rules, falling back to the primary tunnel.
type MultiRouter struct {
	primary TunnelManager
	mu      sync.RWMutex
	bridges []*BridgeEntry // in rule-priority order (first match wins)
	// process override: caller sets this before calling OpenStream/DialStream
	// to enable process-name-based routing.
	processOverride string // current process name being routed
}

// NewMultiRouter wraps primary as the default (fallback) tunnel.
func NewMultiRouter(primary TunnelManager) *MultiRouter {
	return &MultiRouter{primary: primary}
}

// SetPrimary replaces the fallback tunnel at runtime (e.g. on reconnect).
func (r *MultiRouter) SetPrimary(t TunnelManager) {
	r.mu.Lock()
	r.primary = t
	r.mu.Unlock()
}

// AddBridge registers a new named tunnel with routing rules.
// If a bridge with the same ID already exists it is replaced.
func (r *MultiRouter) AddBridge(id, address string, rules []string, tunnel TunnelManager) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// remove existing entry with same id
	for i, b := range r.bridges {
		if b.ID == id {
			r.bridges = append(r.bridges[:i], r.bridges[i+1:]...)
			break
		}
	}

	rr := make([]*RouteRule, 0, len(rules))
	for _, pat := range rules {
		rr = append(rr, &RouteRule{
			ID:       id + ":" + pat,
			Pattern:  pat,
			BridgeID: id,
		})
	}
	r.bridges = append(r.bridges, &BridgeEntry{
		ID:      id,
		Address: address,
		Rules:   rr,
		tunnel:  tunnel,
	})
}

// RemoveBridge removes a bridge and all its rules by ID.
func (r *MultiRouter) RemoveBridge(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, b := range r.bridges {
		if b.ID == id {
			r.bridges = append(r.bridges[:i], r.bridges[i+1:]...)
			return
		}
	}
}

// SetProcessContext sets the current process name for the next OpenStream/DialStream call.
// This must be called (and reset) by a goroutine that handles a single connection, so
// callers must synchronise externally if they rely on per-connection process routing.
func (r *MultiRouter) SetProcessContext(processName string) {
	r.mu.Lock()
	r.processOverride = processName
	r.mu.Unlock()
}

// IsConnected reports true when the primary tunnel is connected.
func (r *MultiRouter) IsConnected() bool {
	r.mu.RLock()
	p := r.primary
	r.mu.RUnlock()
	return p != nil && p.IsConnected()
}

// OpenStream routes the stream to the appropriate tunnel based on addr.
func (r *MultiRouter) OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	t := r.resolve(addr)
	return t.OpenStream(ctx, proto, addr, port)
}

// DialStream routes the stream to the appropriate tunnel based on addr.
func (r *MultiRouter) DialStream(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	t := r.resolve(host)
	return t.DialStream(ctx, network, addr)
}

// resolve picks the tunnel for a given target host. Falls back to primary.
func (r *MultiRouter) resolve(host string) TunnelManager {
	r.mu.RLock()
	bridges := r.bridges
	proc := r.processOverride
	primary := r.primary
	r.mu.RUnlock()

	for _, b := range bridges {
		if b.tunnel == nil || !b.tunnel.IsConnected() {
			continue
		}
		for _, rule := range b.Rules {
			if matchPattern(rule.Pattern, host, proc) {
				return b.tunnel
			}
		}
	}
	return primary
}

// matchPattern returns true if host or process matches the rule pattern.
func matchPattern(pattern, host, processName string) bool {
	switch {
	case pattern == "*":
		return true

	case strings.HasPrefix(pattern, "process:"):
		procPat := strings.ToLower(strings.TrimPrefix(pattern, "process:"))
		return strings.EqualFold(processName, procPat) ||
			strings.HasSuffix(strings.ToLower(processName), "/"+procPat) ||
			strings.HasSuffix(strings.ToLower(processName), "\\"+procPat)

	case strings.Contains(pattern, "/"):
		// CIDR match
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		_, cidr, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		return cidr.Contains(ip)

	case strings.HasPrefix(pattern, "*."):
		// wildcard suffix: *.example.com matches foo.example.com and example.com
		suffix := pattern[2:]
		return strings.EqualFold(host, suffix) ||
			strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(suffix))

	default:
		// exact domain or IP
		return strings.EqualFold(host, pattern)
	}
}

// --- HTTP control API ---

// MultiRouterStatus is returned by GET /multi-bridges.
type MultiRouterStatus struct {
	Bridges []*BridgeStatusEntry `json:"bridges"`
}

// BridgeStatusEntry is one bridge in the status response.
type BridgeStatusEntry struct {
	ID        string   `json:"id"`
	Address   string   `json:"address"`
	Connected bool     `json:"connected"`
	Rules     []string `json:"rules"`
}

// HTTPHandler returns an http.Handler for the /multi-bridges/* control API.
// The caller is responsible for mounting it at the desired path prefix.
//
//	GET  /multi-bridges          → list bridges and rules
//	POST /multi-bridges          → add/update a bridge (body: AddBridgeRequest)
//	DELETE /multi-bridges/{id}   → remove a bridge by id
func (r *MultiRouter) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/multi-bridges", func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			r.mu.RLock()
			out := &MultiRouterStatus{}
			for _, b := range r.bridges {
				rules := make([]string, 0, len(b.Rules))
				for _, rule := range b.Rules {
					rules = append(rules, rule.Pattern)
				}
				out.Bridges = append(out.Bridges, &BridgeStatusEntry{
					ID:        b.ID,
					Address:   b.Address,
					Connected: b.tunnel != nil && b.tunnel.IsConnected(),
					Rules:     rules,
				})
			}
			r.mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)

		case http.MethodPost:
			var body struct {
				ID      string   `json:"id"`
				Address string   `json:"address"`
				Rules   []string `json:"rules"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if body.ID == "" || body.Address == "" {
				http.Error(w, "id and address required", http.StatusBadRequest)
				return
			}
			// Tunnel itself is created externally by the client main.go after receiving this request.
			// Here we only register the routing rules; the actual tunnel attachment happens via
			// AttachBridgeTunnel called from main after the tunnel connects.
			r.mu.Lock()
			found := false
			for _, b := range r.bridges {
				if b.ID == body.ID {
					// update rules
					rr := make([]*RouteRule, 0, len(body.Rules))
					for _, pat := range body.Rules {
						rr = append(rr, &RouteRule{
							ID:       body.ID + ":" + pat,
							Pattern:  pat,
							BridgeID: body.ID,
						})
					}
					b.Rules = rr
					b.Address = body.Address
					found = true
					break
				}
			}
			if !found {
				rr := make([]*RouteRule, 0, len(body.Rules))
				for _, pat := range body.Rules {
					rr = append(rr, &RouteRule{
						ID:       body.ID + ":" + pat,
						Pattern:  pat,
						BridgeID: body.ID,
					})
				}
				r.bridges = append(r.bridges, &BridgeEntry{
					ID:      body.ID,
					Address: body.Address,
					Rules:   rr,
				})
			}
			r.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"ok":true}`)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/multi-bridges/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(req.URL.Path, "/multi-bridges/")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		r.RemoveBridge(id)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true}`)
	})

	return mux
}

// AttachBridgeTunnel sets (or replaces) the live tunnel for a previously registered bridge ID.
func (r *MultiRouter) AttachBridgeTunnel(id string, t TunnelManager) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.bridges {
		if b.ID == id {
			b.tunnel = t
			return nil
		}
	}
	return fmt.Errorf("bridge %q not found", id)
}
