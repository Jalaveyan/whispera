package apiserver

import (
	"encoding/json"
	"net/http"
	"time"
	"whispera/core/keylimits"
)

type keyLimitsRequest struct {
	MaxActiveSessions int   `json:"max_active_sessions"`
	SoftIPCap         int   `json:"soft_ip_cap"`
	BurstPerMinute    int   `json:"burst_per_minute"`
	SessionTTLSec     int64 `json:"session_ttl_sec"`
}

func (r keyLimitsRequest) toLimits() keylimits.Limits {
	return keylimits.Limits{
		MaxActiveSessions: r.MaxActiveSessions,
		SoftIPCap:         r.SoftIPCap,
		BurstPerMinute:    r.BurstPerMinute,
		SessionTTL:        time.Duration(r.SessionTTLSec) * time.Second,
	}
}

func (s *Server) handleKeyLimitsList(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.keyLimits == nil {
		s.jsonOK(w, map[string]interface{}{"success": true, "items": []interface{}{}})
		return
	}
	s.jsonOK(w, map[string]interface{}{"success": true, "items": s.keyLimits.SnapshotAll()})
}

func (s *Server) handleKeyLimitsGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.keyLimits == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "key limits not initialized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "missing key id")
		return
	}
	s.jsonOK(w, map[string]interface{}{"success": true, "item": s.keyLimits.Snapshot(id)})
}

func (s *Server) handleKeyLimitsSet(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.keyLimits == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "key limits not initialized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "missing key id")
		return
	}
	var req keyLimitsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.keyLimits.SetLimits(id, req.toLimits())
	s.jsonOK(w, map[string]interface{}{"success": true, "item": s.keyLimits.Snapshot(id)})
}

func (s *Server) handleKeyLimitsClear(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.keyLimits == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "key limits not initialized")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "missing key id")
		return
	}
	s.keyLimits.ClearLimits(id)
	s.jsonOK(w, map[string]interface{}{"success": true})
}

func (s *Server) handleKeyLimitsDefaults(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.keyLimits == nil {
		s.jsonOK(w, map[string]interface{}{"success": true, "defaults": keylimits.Limits{}})
		return
	}
	// Defaults are stored inside the manager; expose via a probe Snapshot on
	// an unused id which falls back to defaults.
	snap := s.keyLimits.Snapshot("__defaults_probe__")
	s.jsonOK(w, map[string]interface{}{"success": true, "defaults": snap.Limits})
}

func (s *Server) handleKeyLimitsSetDefaults(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.keyLimits == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "key limits not initialized")
		return
	}
	var req keyLimitsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.keyLimits.SetDefault(req.toLimits())
	s.jsonOK(w, map[string]interface{}{"success": true})
}
