package apiserver

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

func (s *Server) handleBridgeStats(w http.ResponseWriter, r *http.Request) {
	s.jsonOK(w, s.bridgePool.BridgeStats())
}

func (s *Server) handleBridgeCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		s.jsonError(w, http.StatusBadRequest, "id required")
		return
	}

	isAlive, latency, err := s.bridgePool.CheckBridgeNow(req.ID)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"id":         req.ID,
		"is_alive":   isAlive,
		"latency_ms": latency,
	})
}

func (s *Server) handleServeBridgeScript(w http.ResponseWriter, r *http.Request) {
	candidates := []string{
		"/opt/whispera/scripts/install-bridge.sh",
		"/usr/local/share/whispera/install-bridge.sh",
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		root := filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "scripts", "install-bridge.sh")
		candidates = append([]string{root}, candidates...)
	}

	var data []byte
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err == nil {
			data = b
			break
		}
	}
	if data == nil {
		http.Error(w, "install-bridge.sh not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Header().Set("Content-Disposition", "attachment; filename=install-bridge.sh")
	w.Write(data)
}
