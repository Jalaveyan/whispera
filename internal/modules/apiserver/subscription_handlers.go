package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"whispera/internal/modules/config"
	"whispera/internal/network"
)


type Subscription struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Token       string    `json:"token"`
	UserIDs     []int     `json:"user_ids"`
	Transports  []string  `json:"transports"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	SubURL string `json:"sub_url,omitempty"`
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
		log.Printf("[API] Failed to marshal subscriptions: %v", err)
		return
	}
	if err := os.WriteFile(subDataFile, data, 0600); err != nil {
		log.Printf("[API] Failed to save subscriptions: %v", err)
	}
}

func loadSubscriptions() {
	data, err := os.ReadFile(subDataFile)
	if err != nil {
		return
	}
	var p subPersist
	if err := json.Unmarshal(data, &p); err != nil {
		log.Printf("[API] Failed to load subscriptions: %v", err)
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
	log.Printf("[API] Loaded %d subscriptions from %s", len(p.Subscriptions), subDataFile)
}


func (s *Server) handleGetSubscriptions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	serverIP, _ := network.DetectServerIP(ctx)

	subStoreMu.RLock()
	list := make([]*Subscription, 0, len(subStore))
	for _, sub := range subStore {
		cp := *sub
		cp.SubURL = buildSubURL(r, serverIP, sub.Token)
		list = append(list, &cp)
	}
	subStoreMu.RUnlock()

	s.jsonOK(w, map[string]interface{}{
		"success":       true,
		"subscriptions": list,
		"count":         len(list),
	})
}

func (s *Server) handleAddSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string   `json:"name"`
		UserIDs    []int    `json:"user_ids"`
		Transports []string `json:"transports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		req.Name = fmt.Sprintf("Sub-%d", time.Now().Unix())
	}

	token, err := randomBase64(24)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	token = base64.RawURLEncoding.EncodeToString([]byte(token))[:32]

	subStoreMu.Lock()
	subNextID++
	sub := &Subscription{
		ID:         fmt.Sprintf("%d", subNextID),
		Name:       req.Name,
		Token:      token,
		UserIDs:    req.UserIDs,
		Transports: req.Transports,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	subStore[sub.ID] = sub
	subByToken[token] = sub
	subStoreMu.Unlock()
	go saveSubscriptions()

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	serverIP, _ := network.DetectServerIP(ctx)

	cp := *sub
	cp.SubURL = buildSubURL(r, serverIP, token)

	s.jsonOK(w, map[string]interface{}{
		"success":      true,
		"subscription": &cp,
	})
}

func (s *Server) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		UserIDs    []int    `json:"user_ids"`
		Transports []string `json:"transports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		s.jsonError(w, http.StatusBadRequest, "id required")
		return
	}

	subStoreMu.Lock()
	defer subStoreMu.Unlock()

	sub, ok := subStore[req.ID]
	if !ok {
		s.jsonError(w, http.StatusNotFound, "subscription not found")
		return
	}
	if req.Name != "" {
		sub.Name = req.Name
	}
	if req.UserIDs != nil {
		sub.UserIDs = req.UserIDs
	}
	if req.Transports != nil {
		sub.Transports = req.Transports
	}
	sub.UpdatedAt = time.Now()
	go saveSubscriptions()

	s.jsonOK(w, map[string]interface{}{"success": true, "subscription": sub})
}

func (s *Server) handleDeleteSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		s.jsonError(w, http.StatusBadRequest, "id required")
		return
	}

	subStoreMu.Lock()
	sub, ok := subStore[req.ID]
	if ok {
		delete(subByToken, sub.Token)
		delete(subStore, req.ID)
	}
	subStoreMu.Unlock()
	go saveSubscriptions()

	s.jsonOK(w, map[string]interface{}{"success": true})
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
	serverIP, _ := network.DetectServerIP(ctx)

	var servers []map[string]interface{}
	if s.registry != nil {
		if mod, ok := s.registry.Get("config.provider"); ok {
			type cfgProvider interface {
				GetConfig() *config.ServerConfig
			}
			if provider, ok := mod.(cfgProvider); ok {
				cfg := provider.GetConfig()
				servers = buildServerList(cfg, serverIP, sub.Transports)
			}
		}
	}

	// Collect user connection keys from userStore
	var keys []string
	userStoreMu.RLock()
	if len(sub.UserIDs) > 0 {
		for _, uid := range sub.UserIDs {
			if u, ok := userStore[uid]; ok && u.ConnectionURI != "" {
				keys = append(keys, u.ConnectionURI)
			}
		}
	} else {
		// No specific users — include all users that have a connection URI
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


func buildSubURL(r *http.Request, serverIP, token string) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" || strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost") {
		if serverIP != "" && serverIP != "0.0.0.0" {
			host = serverIP
		}
	}
	return fmt.Sprintf("%s://%s/sub/%s", scheme, host, token)
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

		if pk := inbound.StreamSettings.Phantom.PrivateKey; pk != "" {
			entry["public_key"] = derivePublicKeyB64(pk)
		}
		if len(inbound.StreamSettings.Phantom.ServerNames) > 0 {
			entry["server_names"] = inbound.StreamSettings.Phantom.ServerNames
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
