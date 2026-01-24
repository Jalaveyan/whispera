package apiserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
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

	// Debug info
	debugPorts := make([]string, 0, len(cfg.Inbounds))
	for _, in := range cfg.Inbounds {
		debugPorts = append(debugPorts, fmt.Sprintf("%d (%s)", in.Port, in.Tag))
	}

	s.jsonOK(w, map[string]interface{}{
		"success":     true,
		"inbounds":    cfg.Inbounds,
		"count":       len(cfg.Inbounds),
		"debug_ports": debugPorts,
		"config_path": cfgProvider.GetConfigPath(), // Need to check if GetConfigPath exists or add it
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

	// Auto-generate key if missing for Phantom/Reality
	isPhantomOrReality := req.StreamSettings.Security == "phantom" || req.StreamSettings.Security == "reality"
	if isPhantomOrReality && req.StreamSettings.Phantom.PrivateKey == "" {
		var privKey [32]byte
		if _, err := rand.Read(privKey[:]); err != nil {
			log.Printf("[API] Failed to generate random key: %v", err)
			s.jsonError(w, http.StatusInternalServerError, "Key generation failed")
			return
		}
		// Set to Phantom struct as it's the primary storage
		req.StreamSettings.Phantom.PrivateKey = base64Encode(privKey[:])

		// If Reality is used, duplicate it there for safety/compat
		if req.StreamSettings.Security == "reality" {
			req.StreamSettings.Reality.PrivateKey = req.StreamSettings.Phantom.PrivateKey
		}

		log.Printf("[API] Auto-generated unique Private Key for inbound %s (Security: %s)", req.Tag, req.StreamSettings.Security)
	}

	// Ensure DEST is set (inherit from global if missing)
	if isPhantomOrReality && req.StreamSettings.Phantom.Dest == "" {
		// Try to find global config to copy dest
		if module, ok := s.registry.Get("config.provider"); ok {
			if cfgProvider, ok := module.(*config.Provider); ok {
				globalCfg := cfgProvider.GetConfig()
				if globalCfg != nil && globalCfg.Phantom.Dest != "" {
					req.StreamSettings.Phantom.Dest = globalCfg.Phantom.Dest
					log.Printf("[API] Inherited global Phantom Dest: %s", req.StreamSettings.Phantom.Dest)
				}
			}
		}
		// Fallback if still empty
		if req.StreamSettings.Phantom.Dest == "" {
			req.StreamSettings.Phantom.Dest = "cloudflare.com:443"
		}
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		log.Printf("[API] Config provider not found in registry")
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)

	err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		// Dedup check by port - if exists, overwrite/update
		foundIndex := -1
		for i, in := range cfg.Inbounds {
			if in.Port == req.Port {
				log.Printf("[API] Port %d already in use by inbound %s. Overwriting.", req.Port, in.Tag)
				foundIndex = i
				break
			}
		}

		if foundIndex != -1 {
			// Overwrite existing
			cfg.Inbounds[foundIndex] = req
		} else {
			// Append new
			cfg.Inbounds = append(cfg.Inbounds, req)
		}

		log.Printf("[API] ✓ Added/Updated inbound %s (port %d) to config. Total inbounds: %d",
			req.Tag, req.Port, len(cfg.Inbounds))
	})

	if err != nil {
		log.Printf("[API] Failed to update config: %v", err)
		s.jsonError(w, http.StatusInternalServerError, "Failed to update config: "+err.Error())
		return
	}

	log.Printf("[API] ✓ Inbound %s saved to config.yaml successfully", req.Tag)

	// AUTOMATIC FIREWALL OPENING
	if err := openFirewallPort(req.Port); err != nil {
		log.Printf("[API] ⚠️ Warning: Failed to open firewall port %d: %v", req.Port, err)
	}

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
	var foundInbound *config.InboundConfig
	for i, inbound := range cfg.Inbounds {
		if inbound.Port == port {
			foundInbound = &cfg.Inbounds[i]
			// Check если у inbound есть свой Phantom ключ
			if inbound.StreamSettings.Phantom.PrivateKey != "" {
				privateKey = inbound.StreamSettings.Phantom.PrivateKey
			}
			break
		}
	}

	if foundInbound != nil {
		log.Printf("[API] Found inbound for port %d. Has private key: %v", port, privateKey != "")
	} else {
		log.Printf("[API] Inbound for port %d NOT found in current config (Total inbounds: %d)", port, len(cfg.Inbounds))
		// Debug: print all ports
		for _, in := range cfg.Inbounds {
			log.Printf("[API] - Available port: %d", in.Port)
		}
	}

	// Fallback to server's global key if inbound doesn't have its own
	if privateKey == "" {
		privateKey = cfg.Server.PrivateKey
		if privateKey != "" {
			log.Printf("[API] Using global server key for port %d", port)
		}
	}

	if privateKey == "" {
		log.Printf("[API] Error: No key found for port %d. Inbound found: %v", port, foundInbound != nil)
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

// Helper function to decode base64 string
func decodeBase64OrHex(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Helper function to encode bytes to base64
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// openFirewallPort executes ufw commands to allow traffic on the specified port
func openFirewallPort(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}

	log.Printf("[Firewall] Attempting to auto-configure UFW for port %d...", port)

	// Check if ufw exists
	if _, err := exec.LookPath("ufw"); err != nil {
		return fmt.Errorf("ufw not found in PATH, skipping firewall config")
	}

	// Allow UDP
	cmdUDP := exec.Command("ufw", "allow", fmt.Sprintf("%d/udp", port))
	if out, err := cmdUDP.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to allow UDP: %v (output: %s)", err, string(out))
	}

	// Allow TCP
	cmdTCP := exec.Command("ufw", "allow", fmt.Sprintf("%d/tcp", port))
	if out, err := cmdTCP.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to allow TCP: %v (output: %s)", err, string(out))
	}

	log.Printf("[Firewall] ✓ Successfully allowed port %d (TCP+UDP) in UFW", port)
	return nil
}
