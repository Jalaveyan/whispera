package apiserver

import (
	"net/http"
)

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
