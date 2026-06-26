package socks5

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"whispera/core/protocol"
)

type RouteRule struct {
	ID       string `json:"id"`
	Pattern  string `json:"pattern"`
	BridgeID string `json:"bridge_id"`
}

type BridgeEntry struct {
	ID      string       `json:"id"`
	Address string       `json:"address"`
	Rules   []*RouteRule `json:"rules"`
	tunnel  TunnelManager
}

type MultiRouter struct {
	primary         TunnelManager
	mu              sync.RWMutex
	bridges         []*BridgeEntry
	processOverride string
}

func NewMultiRouter(primary TunnelManager) *MultiRouter {
	return &MultiRouter{primary: primary}
}

func (r *MultiRouter) SetPrimary(t TunnelManager) {
	r.mu.Lock()
	r.primary = t
	r.mu.Unlock()
}

func (r *MultiRouter) AddBridge(id, address string, rules []string, tunnel TunnelManager) {
	r.mu.Lock()
	defer r.mu.Unlock()

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

func (r *MultiRouter) SetProcessContext(processName string) {
	r.mu.Lock()
	r.processOverride = processName
	r.mu.Unlock()
}

func (r *MultiRouter) IsConnected() bool {
	r.mu.RLock()
	p := r.primary
	r.mu.RUnlock()
	return p != nil && p.IsConnected()
}

func (r *MultiRouter) OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	t := r.resolve(addr)
	return t.OpenStream(ctx, proto, addr, port)
}

func (r *MultiRouter) DialStream(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	t := r.resolve(host)
	return t.DialStream(ctx, network, addr)
}

func (r *MultiRouter) RTDatagram(ctx context.Context, addr string) (*protocol.RTDatagramClient, func(), bool) {
	t := r.resolve(addr)
	if t == nil {
		return nil, nil, false
	}
	return t.RTDatagram(ctx, addr)
}

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
		suffix := pattern[2:]
		return strings.EqualFold(host, suffix) ||
			strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(suffix))

	default:
		return strings.EqualFold(host, pattern)
	}
}

type MultiRouterStatus struct {
	Bridges []*BridgeStatusEntry `json:"bridges"`
}

type BridgeStatusEntry struct {
	ID        string   `json:"id"`
	Address   string   `json:"address"`
	Connected bool     `json:"connected"`
	Rules     []string `json:"rules"`
}

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
			r.mu.Lock()
			found := false
			for _, b := range r.bridges {
				if b.ID == body.ID {
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
