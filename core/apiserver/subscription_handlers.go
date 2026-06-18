package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"whispera/common/ipdetect"
	"whispera/core/config"

	"golang.org/x/crypto/curve25519"
)

type Subscription struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Group      string    `json:"group,omitempty"`
	Token      string    `json:"token"`
	UserIDs    []int     `json:"user_ids"`
	KeyIDs     []string  `json:"key_ids,omitempty"`
	Transports []string  `json:"transports"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	SubURL     string    `json:"sub_url,omitempty"`
}

const subDataFile = "/etc/whispera/subscriptions.json"

var (
	subStoreMu sync.RWMutex
	subStore   = make(map[string]*Subscription)
	subByToken = make(map[string]*Subscription)
	subNextID  int
)

type subPersist struct {
	Subscriptions []*Subscription `json:"subscriptions"`
	NextID        int             `json:"next_id"`
}

func saveSubscriptions() {
	subStoreMu.RLock()
	list := make([]*Subscription, 0, len(subStore))
	for _, s := range subStore {
		list = append(list, s)
	}
	nid := subNextID
	subStoreMu.RUnlock()

	data, err := json.Marshal(subPersist{Subscriptions: list, NextID: nid})
	if err != nil {
		log.Error("failed to marshal subscriptions: %v", err)
		return
	}
	if err := os.WriteFile(subDataFile, data, 0600); err != nil {
		log.Error("failed to save subscriptions: %v", err)
	}
}

func loadSubscriptions() {
	data, err := os.ReadFile(subDataFile)
	if err != nil {
		return
	}
	var p subPersist
	if err := json.Unmarshal(data, &p); err != nil {
		log.Error("failed to load subscriptions: %v", err)
		return
	}
	subStoreMu.Lock()
	for _, s := range p.Subscriptions {
		subStore[s.ID] = s
		subByToken[s.Token] = s
	}
	if p.NextID > subNextID {
		subNextID = p.NextID
	}
	subStoreMu.Unlock()
}

func (s *Server) handleServeSubscription(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	subStoreMu.RLock()
	sub, ok := subByToken[token]
	subStoreMu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	serverIP, _ := ipdetect.DetectServerIP(ctx)

	var servers []map[string]interface{}
	if s.registry != nil {
		if mod, ok := s.registry.Get("config.provider"); ok {
			type cfgProvider interface {
				GetConfig() *config.ServerConfig
			}
			if provider, ok := mod.(cfgProvider); ok {
				cfg := provider.GetConfig()
				publicHost := publicHostFromURL(cfg.Server.PublicURL)
				addr := serverIP
				if publicHost != "" {
					addr = publicHost
				}
				servers = buildServerList(cfg, addr, sub.Transports)
			}
		}
	}

	var keys []string
	userStoreMu.RLock()
	if len(sub.KeyIDs) > 0 {
		keySet := make(map[string]bool, len(sub.KeyIDs))
		for _, kid := range sub.KeyIDs {
			keySet[kid] = true
		}
		for _, u := range userStore {
			if u.ConnectionURI != "" && keySet[u.ConnectionURI] {
				keys = append(keys, u.ConnectionURI)
			}
		}
	} else if len(sub.UserIDs) > 0 {
		for _, uid := range sub.UserIDs {
			if u, ok := userStore[uid]; ok && u.ConnectionURI != "" {
				keys = append(keys, u.ConnectionURI)
			}
		}
	} else {
		for _, u := range userStore {
			if u.ConnectionURI != "" {
				keys = append(keys, u.ConnectionURI)
			}
		}
	}
	userStoreMu.RUnlock()

	payload := map[string]interface{}{
		"version": "2",
		"name":    sub.Name,
		"updated": sub.UpdatedAt.UTC().Format(time.RFC3339),
		"servers": servers,
		"keys":    keys,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="whispera-sub.txt"`)
	w.Header().Set("Profile-Update-Interval", "24")
	fmt.Fprint(w, base64.StdEncoding.EncodeToString(raw))
}

func buildServerList(cfg *config.ServerConfig, serverIP string, preferredTransports []string) []map[string]interface{} {
	if cfg == nil {
		return nil
	}

	transportSet := make(map[string]bool)
	for _, t := range preferredTransports {
		transportSet[t] = true
	}

	var servers []map[string]interface{}

	for _, inbound := range cfg.Inbounds {
		network := inbound.StreamSettings.Network
		if network == "" {
			network = "tcp"
		}

		if len(transportSet) > 0 && !transportSet[network] {
			continue
		}

		entry := map[string]interface{}{
			"name":      inbound.Tag,
			"address":   serverIP,
			"port":      inbound.Port,
			"transport": network,
			"security":  inbound.StreamSettings.Security,
		}

		if len(inbound.Ports) > 0 {
			entry["ports"] = inbound.AllPorts()
		}

		if inbound.StreamSettings.WS.Path != "" {
			entry["ws_path"] = inbound.StreamSettings.WS.Path
		}

		for k, v := range inbound.StreamSettings.Params {
			if _, exists := entry[k]; !exists {
				entry[k] = v
			}
		}

		servers = append(servers, entry)
	}

	if cfg.Chameleon.Enabled && cfg.Chameleon.ListenAddr != "" && (len(transportSet) == 0 || transportSet["chameleon"]) {
		_, port, _ := splitHostPort(cfg.Chameleon.ListenAddr)
		cEntry := map[string]interface{}{
			"name":      "chameleon",
			"address":   serverIP,
			"port":      port,
			"transport": "chameleon",
		}
		if cfg.Chameleon.Domain != "" {
			cEntry["sni"] = cfg.Chameleon.Domain
		}
		servers = append(servers, cEntry)
	}

	if cfg.Transport.UDP.Enabled && (len(transportSet) == 0 || transportSet["udp"]) {
		_, port, _ := splitHostPort(cfg.Transport.UDP.ListenAddr)
		servers = append(servers, map[string]interface{}{
			"name":      "udp",
			"address":   serverIP,
			"port":      port,
			"transport": "udp",
		})
	}
	if cfg.Transport.TCP.Enabled && (len(transportSet) == 0 || transportSet["tcp"]) {
		_, port, _ := splitHostPort(cfg.Transport.TCP.ListenAddr)
		servers = append(servers, map[string]interface{}{
			"name":      "tcp",
			"address":   serverIP,
			"port":      port,
			"transport": "tcp",
		})
	}

	return servers
}

func publicHostFromURL(publicURL string) string {
	if publicURL == "" {
		return ""
	}
	s := strings.TrimPrefix(strings.TrimPrefix(publicURL, "https://"), "http://")
	s = strings.TrimRight(s, "/")
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

func splitHostPort(addr string) (host, port string, err error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return "", addr, nil
}

func derivePublicKeyB64(privKeyB64 string) string {
	b, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil || len(b) != 32 {
		return ""
	}
	var priv [32]byte
	copy(priv[:], b)
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}
