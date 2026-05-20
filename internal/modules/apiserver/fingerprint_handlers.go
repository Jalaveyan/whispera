package apiserver

import (
	"encoding/json"
	"net/http"
)

type FingerprintInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Browser     string `json:"browser"`
	Platform    string `json:"platform"`
	Description string `json:"description"`
}

var availableFingerprints = []FingerprintInfo{
	{ID: "chrome", Name: "Chrome Auto", Browser: "Chrome", Platform: "Desktop", Description: "Latest Chrome TLS fingerprint (recommended)"},
	{ID: "chrome_120", Name: "Chrome 120", Browser: "Chrome", Platform: "Desktop", Description: "Chrome 120 specific fingerprint"},
	{ID: "chrome_115", Name: "Chrome 115", Browser: "Chrome", Platform: "Desktop", Description: "Chrome 115 specific fingerprint"},
	{ID: "firefox", Name: "Firefox Auto", Browser: "Firefox", Platform: "Desktop", Description: "Latest Firefox TLS fingerprint"},
	{ID: "firefox_120", Name: "Firefox 120", Browser: "Firefox", Platform: "Desktop", Description: "Firefox 120 specific fingerprint"},
	{ID: "safari", Name: "Safari Auto", Browser: "Safari", Platform: "macOS/iOS", Description: "Latest Safari TLS fingerprint"},
	{ID: "ios", Name: "iOS Safari", Browser: "Safari", Platform: "iOS", Description: "iOS Safari mobile fingerprint"},
	{ID: "android", Name: "Android OkHttp", Browser: "OkHttp", Platform: "Android", Description: "Android OkHttp client fingerprint"},
	{ID: "edge", Name: "Edge Auto", Browser: "Edge", Platform: "Desktop", Description: "Microsoft Edge TLS fingerprint"},
	{ID: "opera", Name: "Opera Auto", Browser: "Opera", Platform: "Desktop", Description: "Opera browser fingerprint"},
	{ID: "random", Name: "Random", Browser: "Mixed", Platform: "Any", Description: "Randomized fingerprint per connection"},
	{ID: "randomized_no_alpn", Name: "Random (No ALPN)", Browser: "Mixed", Platform: "Any", Description: "Randomized without ALPN extension"},
	{ID: "custom", Name: "Custom JA3", Browser: "Custom", Platform: "Any", Description: "Custom JA3 string (advanced)"},
}

func (s *Server) handleGetFingerprints(w http.ResponseWriter, r *http.Request) {
	current := s.getCurrentFingerprint()

	resp := map[string]interface{}{
		"fingerprints": availableFingerprints,
		"current":      current,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleSetFingerprint(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if req.Fingerprint == "" {
		s.jsonError(w, http.StatusBadRequest, "Fingerprint ID required")
		return
	}

	valid := false
	for _, fp := range availableFingerprints {
		if fp.ID == req.Fingerprint {
			valid = true
			break
		}
	}
	if !valid {
		s.jsonError(w, http.StatusBadRequest, "Unknown fingerprint ID")
		return
	}

	s.setCurrentFingerprint(req.Fingerprint)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":          true,
		"fingerprint": req.Fingerprint,
	})
}

func (s *Server) getCurrentFingerprint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.config != nil && s.config.TLSFingerprint != "" {
		return s.config.TLSFingerprint
	}
	return "chrome"
}

func (s *Server) setCurrentFingerprint(fp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config != nil {
		s.config.TLSFingerprint = fp
	}
}

func (s *Server) handleFailoverStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"block_state":     "none",
		"active_strategy": "direct",
		"available_strategies": []string{
			"direct", "domain_front", "cdn_worker",
			"alternate_ip", "meek", "split_http",
			"tg_bot", "vk_webrtc",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
