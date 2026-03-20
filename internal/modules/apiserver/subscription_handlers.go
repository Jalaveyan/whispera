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

	"golang.org/x/crypto/curve25519"
	"whispera/internal/modules/config"
	"whispera/internal/network"
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
	log.Info("loaded %d subscriptions from %s", len(p.Subscriptions), subDataFile)
}


func (s *Server) handleGetSubscriptions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	serverIP, _ := network.DetectServerIP(ctx)
	publicURL := s.getPublicURL()

	subStoreMu.RLock()
	list := make([]*Subscription, 0, len(subStore))
	for _, sub := range subStore {
		cp := *sub
		cp.SubURL = buildSubURL(r, serverIP, publicURL, sub.Token)
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
		Group      string   `json:"group"`
		UserIDs    []int    `json:"user_ids"`
		KeyIDs     []string `json:"key_ids"`
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
		Group:      req.Group,
		Token:      token,
		UserIDs:    req.UserIDs,
		KeyIDs:     req.KeyIDs,
		Transports: req.Transports,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	subStore[sub.ID] = sub
	subByToken[token] = sub
	subStoreMu.Unlock()
	go saveSubscriptions()
	AppendEvent(EventSubscription, SeverityInfo, "subscription created", map[string]string{"id": sub.ID, "name": sub.Name})

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	serverIP, _ := network.DetectServerIP(ctx)

	cp := *sub
	cp.SubURL = buildSubURL(r, serverIP, s.getPublicURL(), token)

	s.jsonOK(w, map[string]interface{}{
		"success":      true,
		"subscription": &cp,
	})
}

func (s *Server) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		Group      string   `json:"group"`
		UserIDs    []int    `json:"user_ids"`
		KeyIDs     []string `json:"key_ids"`
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
	if req.Group != "" {
		sub.Group = req.Group
	}
	if req.UserIDs != nil {
		sub.UserIDs = req.UserIDs
	}
	if req.KeyIDs != nil {
		sub.KeyIDs = req.KeyIDs
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
	if ok {
		AppendEvent(EventSubscription, SeverityInfo, "subscription deleted", map[string]string{"id": req.ID})
	}

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


var internalPorts = map[string]bool{"3000": true, "8080": true, "8081": true, "8082": true}

func (s *Server) getPublicURL() string {
	if s.registry == nil {
		return ""
	}
	mod, ok := s.registry.Get("config.provider")
	if !ok {
		return ""
	}
	if p, ok := mod.(interface {
		GetConfig() *config.ServerConfig
	}); ok {
		return strings.TrimRight(p.GetConfig().Server.PublicURL, "/")
	}
	return ""
}

func buildSubURL(r *http.Request, serverIP, publicURL, token string) string {
	if publicURL != "" {
		return fmt.Sprintf("%s/sub/%s", publicURL, token)
	}

	scheme := "https"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	if h, port, err := net.SplitHostPort(host); err == nil && internalPorts[port] {
		host = h
	}

	if host == "" || strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost") || host == "whispera-ui" {
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

func (s *Server) handlePingKey(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if addr == "" {
		s.jsonError(w, http.StatusBadRequest, "addr required (host:port)")
		return
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		s.jsonOK(w, map[string]interface{}{
			"addr":    addr,
			"reachable": false,
			"error":   err.Error(),
		})
		return
	}
	conn.Close()
	s.jsonOK(w, map[string]interface{}{
		"addr":       addr,
		"reachable":  true,
		"latency_ms": time.Since(start).Milliseconds(),
	})
}

func (s *Server) handlePingAllKeys(w http.ResponseWriter, r *http.Request) {
	userStoreMu.RLock()
	type target struct {
		userID int
		addr   string
		name   string
	}
	var targets []target
	for uid, u := range userStore {
		if u.ConnectionURI == "" {
			continue
		}
		host, port := parseAddrFromURI(u.ConnectionURI)
		if host == "" {
			continue
		}
		targets = append(targets, target{uid, net.JoinHostPort(host, port), u.Username})
	}
	userStoreMu.RUnlock()

	type result struct {
		UserID    int    `json:"user_id"`
		Name      string `json:"name"`
		Addr      string `json:"addr"`
		Reachable bool   `json:"reachable"`
		LatencyMs int64  `json:"latency_ms,omitempty"`
		Error     string `json:"error,omitempty"`
	}

	results := make([]result, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t target) {
			defer wg.Done()
			start := time.Now()
			conn, err := net.DialTimeout("tcp", t.addr, 4*time.Second)
			if err != nil {
				results[i] = result{UserID: t.userID, Name: t.name, Addr: t.addr, Error: err.Error()}
				return
			}
			conn.Close()
			results[i] = result{UserID: t.userID, Name: t.name, Addr: t.addr,
				Reachable: true, LatencyMs: time.Since(start).Milliseconds()}
		}(i, t)
	}
	wg.Wait()
	s.jsonOK(w, map[string]interface{}{"results": results, "count": len(results)})
}

func parseAddrFromURI(uri string) (host, port string) {
	uri = strings.TrimPrefix(uri, "whispera://")
	if i := strings.Index(uri, "@"); i >= 0 {
		uri = uri[i+1:]
	}
	if i := strings.Index(uri, "?"); i >= 0 {
		uri = uri[:i]
	}
	if i := strings.Index(uri, "/"); i >= 0 {
		uri = uri[:i]
	}
	host, port, _ = net.SplitHostPort(uri)
	if port == "" {
		port = "8443"
	}
	return
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
