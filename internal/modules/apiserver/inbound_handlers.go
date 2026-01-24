package apiserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"whispera/internal/modules/config"

	"golang.org/x/crypto/curve25519"
)

// handleGetInbounds returns the list of configured inbounds
func (s *Server) handleGetInbounds(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonError(w, http.StatusInternalServerError, "Registry not available")
		return
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)
	cfg := cfgProvider.GetConfig()

	// Wrap in a response structure compatible with frontend expectations
	s.jsonOK(w, map[string]interface{}{
		"success":  true,
		"inbounds": cfg.Inbounds,
		"count":    len(cfg.Inbounds),
	})
}

// handleAddInbound adds a new inbound configuration
func (s *Server) handleAddInbound(w http.ResponseWriter, r *http.Request) {
	var req config.InboundConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[API] Failed to decode inbound request: %v", err)
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	log.Printf("[API] Received inbound add request: tag=%s, port=%d, security=%s",
		req.Tag, req.Port, req.StreamSettings.Security)

	// Enforce Whispera defaults if not set
	if req.Protocol == "" {
		req.Protocol = "whispera"
	}
	if req.Tag == "" {
		req.Tag = fmt.Sprintf("inbound-%d", time.Now().Unix())
	}
	if req.Listen == "" {
		req.Listen = "0.0.0.0"
	}
	// Force Phantom/TCP for now as it's the main mode
	if req.StreamSettings.Network == "" {
		req.StreamSettings.Network = "tcp"
	}
	if req.StreamSettings.Security == "" {
		req.StreamSettings.Security = "phantom"
	}

	log.Printf("[API] Normalized inbound config: tag=%s, port=%d, network=%s, security=%s, has_phantom_key=%v",
		req.Tag, req.Port, req.StreamSettings.Network, req.StreamSettings.Security,
		req.StreamSettings.Phantom.PrivateKey != "")

	// Auto-generate key if missing for Phantom
	if req.StreamSettings.Security == "phantom" && req.StreamSettings.Phantom.PrivateKey == "" {
		var privKey [32]byte
		if _, err := rand.Read(privKey[:]); err != nil {
			log.Printf("[API] Failed to generate random key: %v", err)
			s.jsonError(w, http.StatusInternalServerError, "Key generation failed")
			return
		}
		req.StreamSettings.Phantom.PrivateKey = base64Encode(privKey[:])
		log.Printf("[API] Auto-generated Phantom private key for inbound %s", req.Tag)
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		log.Printf("[API] Config provider not found in registry")
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)

	err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		// Dedup check by port
		for _, in := range cfg.Inbounds {
			if in.Port == req.Port {
				log.Printf("[API] Port %d already in use by inbound %s", req.Port, in.Tag)
				// Error or overwrite? Let's error for safety
				return // TODO: Return error properly
			}
		}
		cfg.Inbounds = append(cfg.Inbounds, req)
		log.Printf("[API] ✓ Added inbound %s (port %d) to config. Total inbounds: %d",
			req.Tag, req.Port, len(cfg.Inbounds))
	})

	if err != nil {
		log.Printf("[API] Failed to update config: %v", err)
		s.jsonError(w, http.StatusInternalServerError, "Failed to update config: "+err.Error())
		return
	}

	log.Printf("[API] ✓ Inbound %s saved to config.yaml successfully", req.Tag)

	// ⚡ DYNAMICALLY START THE INBOUND WITHOUT RESTART
	// Import dynamic manager package
	if err := startDynamicInbound(req); err != nil {
		log.Printf("[API] ⚠️ Warning: Inbound saved but failed to start dynamically: %v", err)
		log.Printf("[API] → Run 'systemctl restart whispera' to activate")

		s.jsonOK(w, map[string]interface{}{
			"success": true,
			"message": "Inbound added to config but requires restart to activate",
			"warning": fmt.Sprintf("Failed to start dynamically: %s. Please restart server.", err.Error()),
			"inbound": req,
		})
		return
	}

	log.Printf("[API] 🚀 Inbound %s started dynamically on port %d!", req.Tag, req.Port)

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Inbound added and started on port %d (no restart needed!)", req.Port),
		"inbound": req,
	})
}

// Helper to start inbound dynamically (bridge to global dynamic manager)
func startDynamicInbound(inbound config.InboundConfig) error {
	// This will be implemented via server/dynamic package
	// For now, return nil to indicate feature not yet connected
	// TODO: Connect to dynamic.Global.StartInbound(inbound)
	return fmt.Errorf("dynamic start not yet wired - restart server manually")
}

// handleUpdateInbound updates an existing inbound
func (s *Server) handleUpdateInbound(w http.ResponseWriter, r *http.Request) {
	var req config.InboundConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Tag == "" {
		s.jsonError(w, http.StatusBadRequest, "Tag required for update")
		return
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)

	err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		for i, in := range cfg.Inbounds {
			if in.Tag == req.Tag {
				// Update fields. Protocol/Tag usually static, but Port/Settings mutable
				cfg.Inbounds[i] = req
				break
			}
		}
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to update config: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]string{"message": "Inbound updated"})
}

// handleDeleteInbound deletes an inbound
func (s *Server) handleDeleteInbound(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)

	err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		newInbounds := make([]config.InboundConfig, 0)
		for _, in := range cfg.Inbounds {
			if in.Tag != req.Tag {
				newInbounds = append(newInbounds, in)
			}
		}
		cfg.Inbounds = newInbounds
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to update config: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]string{"message": "Inbound deleted"})
}

// handleGetInboundPublicKey returns the public key for a specific inbound port
func (s *Server) handleGetInboundPublicKey(w http.ResponseWriter, r *http.Request) {
	// Get port from query string
	portStr := r.URL.Query().Get("port")
	if portStr == "" {
		s.jsonError(w, http.StatusBadRequest, "Port parameter required")
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid port number")
		return
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)
	cfg := cfgProvider.GetConfig()

	// Find inbound by port
	var privateKey string
	for _, inbound := range cfg.Inbounds {
		if inbound.Port == port {
			// Check если у inbound есть свой Phantom ключ
			if inbound.StreamSettings.Phantom.PrivateKey != "" {
				privateKey = inbound.StreamSettings.Phantom.PrivateKey
			}
			break
		}
	}

	// Fallback to server's global key if inbound doesn't have its own
	if privateKey == "" {
		privateKey = cfg.Server.PrivateKey
	}

	if privateKey == "" {
		s.jsonError(w, http.StatusNotFound, "No private key configured for this port or server")
		return
	}

	// Calculate public key from private key
	privKeyBytes, err := decodeBase64OrHex(privateKey)
	if err != nil || len(privKeyBytes) != 32 {
		log.Printf("[API] Invalid private key format for port %d", port)
		s.jsonError(w, http.StatusInternalServerError, "Invalid private key format")
		return
	}

	var privKey [32]byte
	copy(privKey[:], privKeyBytes)

	// Calculate public key
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	// Encode to base64
	publicKeyB64 := base64Encode(pubKey[:])

	log.Printf("[API] ✓ Returned public key for port %d: %s...", port, publicKeyB64[:16])

	s.jsonOK(w, map[string]interface{}{
		"success":    true,
		"port":       port,
		"public_key": publicKeyB64,
	})
}

// Helper function to decode base64 or hex string
func decodeBase64OrHex(s string) ([]byte, error) {
	// Try base64 first
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	// Try hex
	return hex.DecodeString(s)
}

// Helper function to encode bytes to base64
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
