package apiserver

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"whispera/internal/modules/bridgepool"
)

// isAllowedBinaryURL ensures rollout URLs come only from the official repository.
func isAllowedBinaryURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Host)
	return host == "github.com" ||
		strings.HasSuffix(host, ".githubusercontent.com")
}

func (s *Server) handleBridgeStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.jsonOK(w, s.bridgePool.BridgeStats())
}

func (s *Server) handleBridgeCheck(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleBridgeRollout(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		Version   string `json:"version"`
		BinaryURL string `json:"binary_url"`
		Checksum  string `json:"checksum"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Version == "" || req.BinaryURL == "" {
		s.jsonError(w, http.StatusBadRequest, "version and binary_url required")
		return
	}
	if !isAllowedBinaryURL(req.BinaryURL) {
		s.jsonError(w, http.StatusBadRequest, "binary_url must be an HTTPS URL from github.com or githubusercontent.com")
		return
	}

	notifier := bridgepool.NewNotificationManager()
	delivery := bridgepool.NewUpdateDelivery(s.bridgePool, notifier, 5)
	results := delivery.DeliverUpdate(req.Version, req.BinaryURL, req.Checksum)

	success := 0
	for _, r := range results {
		if r.Success {
			success++
		}
	}
	s.jsonOK(w, map[string]interface{}{
		"success":  true,
		"total":    len(results),
		"ok":       success,
		"failed":   len(results) - success,
		"results":  results,
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
