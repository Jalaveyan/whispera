package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// ── Adblock stubs ─────────────────────────────────────────────────────────────

type adblockRule struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

var (
	adblockMu      sync.RWMutex
	adblockRules   = make(map[string]*adblockRule)
	adblockNextID  = 1
	adblockBlocked int64
)

func (s *Server) handleAdblockStats(w http.ResponseWriter, r *http.Request) {
	adblockMu.RLock()
	total := adblockBlocked
	adblockMu.RUnlock()
	s.jsonOK(w, map[string]interface{}{
		"total_blocked": total,
		"dns_blocked":   total,
		"https_blocked": 0,
		"ml_blocked":    0,
	})
}

func (s *Server) handleAdblockRules(w http.ResponseWriter, r *http.Request) {
	adblockMu.RLock()
	rules := make([]*adblockRule, 0, len(adblockRules))
	for _, r := range adblockRules {
		rules = append(rules, r)
	}
	adblockMu.RUnlock()
	s.jsonOK(w, map[string]interface{}{"success": true, "rules": rules})
}

func (s *Server) handleAdblockAddRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Type   string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		s.jsonError(w, http.StatusBadRequest, "domain required")
		return
	}
	if req.Type == "" {
		req.Type = "domain"
	}
	adblockMu.Lock()
	id := fmt.Sprintf("%d", adblockNextID)
	adblockNextID++
	rule := &adblockRule{ID: id, Domain: req.Domain, Type: req.Type, Enabled: true}
	adblockRules[id] = rule
	adblockMu.Unlock()
	s.jsonOK(w, map[string]interface{}{"success": true, "rule": rule})
}

func (s *Server) handleAdblockDeleteRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		s.jsonError(w, http.StatusBadRequest, "id required")
		return
	}
	adblockMu.Lock()
	delete(adblockRules, req.ID)
	adblockMu.Unlock()
	s.jsonOK(w, map[string]interface{}{"success": true})
}

func (s *Server) handleAdblockSettings(w http.ResponseWriter, r *http.Request) {
	s.jsonOK(w, map[string]interface{}{"success": true})
}

// ── Renew cert stub ───────────────────────────────────────────────────────────

func (s *Server) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	s.jsonOK(w, map[string]interface{}{"success": true, "message": "Certificate renewal initiated"})
}
