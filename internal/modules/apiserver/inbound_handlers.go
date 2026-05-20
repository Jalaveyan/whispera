package apiserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"whispera/internal/modules/config"
	"whispera/internal/server/dynamic"

	"golang.org/x/crypto/curve25519"
)

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

	debugPorts := make([]string, 0, len(cfg.Inbounds))
	for _, in := range cfg.Inbounds {
		debugPorts = append(debugPorts, fmt.Sprintf("%d (%s)", in.Port, in.Tag))
	}

	s.jsonOK(w, map[string]interface{}{
		"success":     true,
		"inbounds":    cfg.Inbounds,
		"count":       len(cfg.Inbounds),
		"debug_ports": debugPorts,
		"config_path": cfgProvider.GetConfigPath(),
	})
}

func (s *Server) handleAddInbound(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req config.InboundConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[API] Failed to decode inbound request: %v", err)
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	log.Printf("[API] Received inbound add request: tag=%s, port=%d, security=%s",
		req.Tag, req.Port, req.StreamSettings.Security)

	if req.Protocol == "" {
		req.Protocol = "whispera"
	}
	if req.Tag == "" {
		req.Tag = fmt.Sprintf("inbound-%d", time.Now().Unix())
	}
	if req.Listen == "" {
		req.Listen = "0.0.0.0"
	}
	if req.StreamSettings.Network == "" {
		req.StreamSettings.Network = "tcp"
	}
	if req.StreamSettings.Security == "" {
		req.StreamSettings.Security = "phantom"
	}

	log.Printf("[API] Normalized inbound config: tag=%s, port=%d, network=%s, security=%s, has_phantom_key=%v",
		req.Tag, req.Port, req.StreamSettings.Network, req.StreamSettings.Security,
		req.StreamSettings.Phantom.PrivateKey != "")

	isPhantomOrReality := req.StreamSettings.Security == "phantom" || req.StreamSettings.Security == "reality"
	if isPhantomOrReality && req.StreamSettings.Phantom.PrivateKey == "" {
		var privKey [32]byte
		if _, err := rand.Read(privKey[:]); err != nil {
			log.Printf("[API] Failed to generate random key: %v", err)
			s.jsonError(w, http.StatusInternalServerError, "Key generation failed")
			return
		}
		req.StreamSettings.Phantom.PrivateKey = base64Encode(privKey[:])

		if req.StreamSettings.Security == "reality" {
			req.StreamSettings.Reality.PrivateKey = req.StreamSettings.Phantom.PrivateKey
		}

		log.Printf("[API] Auto-generated unique Private Key for inbound %s (Security: %s)", req.Tag, req.StreamSettings.Security)
	}

	if isPhantomOrReality && req.StreamSettings.Phantom.Dest == "" {
		if module, ok := s.registry.Get("config.provider"); ok {
			if cfgProvider, ok := module.(*config.Provider); ok {
				globalCfg := cfgProvider.GetConfig()
				if globalCfg != nil && globalCfg.Phantom.Dest != "" {
					req.StreamSettings.Phantom.Dest = globalCfg.Phantom.Dest
					log.Printf("[API] Inherited global Phantom Dest: %s", req.StreamSettings.Phantom.Dest)
				}
			}
		}
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
		foundIndex := -1
		reqNet := req.StreamSettings.Network
		if reqNet == "" {
			reqNet = "tcp"
		}
		for i, in := range cfg.Inbounds {
			if in.Tag == req.Tag {
				log.Printf("[API] Tag %s already exists. Overwriting.", req.Tag)
				foundIndex = i
				break
			}
			inNet := in.StreamSettings.Network
			if inNet == "" {
				inNet = "tcp"
			}
			if in.Port == req.Port && inNet == reqNet {
				log.Printf("[API] Port %d/%s already in use by inbound %s. Overwriting.", req.Port, reqNet, in.Tag)
				foundIndex = i
				break
			}
		}

		if foundIndex != -1 {
			cfg.Inbounds[foundIndex] = req
		} else {
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

	if err := openFirewallPort(req.Port); err != nil {
		log.Printf("[API] ⚠️ Warning: Failed to open firewall port %d: %v", req.Port, err)
	}

	if portOccupiedByExistingInbound(cfgProvider, req) {
		log.Printf("[API] Port %d already has an active inbound with network=%s, restart required",
			req.Port, req.StreamSettings.Network)
		s.jsonOK(w, map[string]interface{}{
			"success":         true,
			"message":         fmt.Sprintf("Inbound saved. Port %d already in use — restart required to activate.", req.Port),
			"restart_required": true,
			"inbound":         req,
		})
		return
	}

	if err := startDynamicInbound(req); err != nil {
		if isAddrInUseErr(err) {
			log.Printf("[API] Port %d busy (likely same-port multiport config), restart to activate", req.Port)
		} else {
			log.Printf("[API] ⚠️ Warning: Inbound saved but failed to start dynamically: %v", err)
		}
		log.Printf("[API] → Run 'systemctl restart whispera' to activate")

		s.jsonOK(w, map[string]interface{}{
			"success":         true,
			"message":         "Inbound saved, restart required to activate",
			"restart_required": true,
			"inbound":         req,
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

func portOccupiedByExistingInbound(cfgProvider *config.Provider, incoming config.InboundConfig) bool {
	cfg := cfgProvider.GetConfig()
	if cfg == nil {
		return false
	}
	inNet := incoming.StreamSettings.Network
	if inNet == "" {
		inNet = "tcp"
	}
	if inNet == "udp" {
		return false
	}
	for _, in := range cfg.Inbounds {
		if in.Tag == incoming.Tag {
			continue
		}
		if in.Port != incoming.Port {
			continue
		}
		net := in.StreamSettings.Network
		if net == "" {
			net = "tcp"
		}
		if net != "udp" {
			return true
		}
	}
	return false
}

func isAddrInUseErr(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "address already in use") ||
		strings.Contains(err.Error(), "bind: address already in use"))
}

func startDynamicInbound(inbound config.InboundConfig) error {
	return dynamic.Global.StartInbound(inbound)
}
func (s *Server) handleUpdateInbound(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
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

func (s *Server) handleDeleteInbound(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
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

func (s *Server) handleGetInboundPublicKey(w http.ResponseWriter, r *http.Request) {
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

	var privateKey string
	var foundInbound *config.InboundConfig
	for i, inbound := range cfg.Inbounds {
		if inbound.Port == port {
			foundInbound = &cfg.Inbounds[i]
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
		for _, in := range cfg.Inbounds {
			log.Printf("[API] - Available port: %d", in.Port)
		}
	}

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

	privKeyBytes, err := decodeBase64OrHex(privateKey)
	if err != nil || len(privKeyBytes) != 32 {
		log.Printf("[API] Invalid private key format for port %d", port)
		s.jsonError(w, http.StatusInternalServerError, "Invalid private key format")
		return
	}

	var privKey [32]byte
	copy(privKey[:], privKeyBytes)

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	publicKeyB64 := base64Encode(pubKey[:])

	log.Printf("[API] ✓ Returned public key for port %d: %s...", port, publicKeyB64[:16])

	s.jsonOK(w, map[string]interface{}{
		"success":    true,
		"port":       port,
		"public_key": publicKeyB64,
	})
}

func decodeBase64OrHex(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func openFirewallPort(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}

	log.Printf("[Firewall] Attempting to auto-configure UFW for port %d...", port)

	if _, err := exec.LookPath("ufw"); err != nil {
		return fmt.Errorf("ufw not found in PATH, skipping firewall config")
	}
	if out, err := runUFW("allow", fmt.Sprintf("%d/udp", port)); err != nil {
		return fmt.Errorf("failed to allow UDP: %v (output: %s)", err, string(out))
	}
	if out, err := runUFW("allow", fmt.Sprintf("%d/tcp", port)); err != nil {
		return fmt.Errorf("failed to allow TCP: %v (output: %s)", err, string(out))
	}

	log.Printf("[Firewall] ✓ Successfully allowed port %d (TCP+UDP) in UFW", port)
	return nil
}
