package apiserver

import (
	"encoding/json"
	"net/http"
	"whispera/core/probedetector"
)

func (s *Server) SetProbeDetector(d *probedetector.Detector) {
	s.mu.Lock()
	s.probeDetector = d
	s.mu.Unlock()

	s.Handle("GET /api/probe/stats", s.handleProbeStats)
	s.Handle("POST /api/probe/block", s.handleProbeBlock)
	s.Handle("POST /api/probe/unblock", s.handleProbeUnblock)
}

func (s *Server) handleProbeStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.mu.RLock()
	d := s.probeDetector
	s.mu.RUnlock()
	if d == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "probe detector not configured")
		return
	}
	s.jsonOK(w, d.Stats())
}

func (s *Server) handleProbeBlock(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.mu.RLock()
	d := s.probeDetector
	s.mu.RUnlock()
	if d == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "probe detector not configured")
		return
	}

	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		s.jsonError(w, http.StatusBadRequest, "ip required")
		return
	}
	reason := req.Reason
	if reason == "" {
		reason = "manually blocked via admin panel"
	}
	d.BlockIP(req.IP, reason)
	s.jsonOK(w, map[string]string{"message": "IP blocked: " + req.IP})
}

func (s *Server) handleProbeUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.mu.RLock()
	d := s.probeDetector
	s.mu.RUnlock()
	if d == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "probe detector not configured")
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		s.jsonError(w, http.StatusBadRequest, "ip required")
		return
	}
	d.UnblockIP(req.IP)
	s.jsonOK(w, map[string]string{"message": "IP unblocked: " + req.IP})
}
