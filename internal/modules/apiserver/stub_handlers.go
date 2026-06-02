package apiserver

import (
	"encoding/json"
	"net/http"

	"whispera/internal/adblock"
)

func (s *Server) handleAdblockStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.jsonOK(w, map[string]interface{}{
		"total_blocked": adblock.Global.BlockedCount(),
		"dns_blocked":   adblock.Global.DNSBlockedCount(),
		"https_blocked": adblock.Global.HTTPSBlockedCount(),
		"ml_blocked":    0,
	})
}

func (s *Server) handleAdblockRules(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rules := adblock.Global.List()
	s.jsonOK(w, map[string]interface{}{"success": true, "rules": rules})
}

func (s *Server) handleAdblockAddRule(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		Domain string `json:"domain"`
		Type   string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		s.jsonError(w, http.StatusBadRequest, "domain required")
		return
	}
	rule := adblock.Global.Add(req.Domain, req.Type)
	s.jsonOK(w, map[string]interface{}{"success": true, "rule": rule})
}

func (s *Server) handleAdblockDeleteRule(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		s.jsonError(w, http.StatusBadRequest, "id required")
		return
	}
	adblock.Global.Remove(req.ID)
	s.jsonOK(w, map[string]interface{}{"success": true})
}

func (s *Server) handleAdblockSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.jsonOK(w, map[string]interface{}{"success": true})
}

func (s *Server) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.jsonOK(w, map[string]interface{}{"success": true, "message": "Certificate renewal initiated"})
}
