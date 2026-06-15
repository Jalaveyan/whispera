package apiserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"whispera/internal/modules/config"
	"whispera/internal/server"

	"golang.org/x/crypto/curve25519"
)

func portOf(listenAddr string) int {
	i := strings.LastIndex(listenAddr, ":")
	if i < 0 {
		return 0
	}
	p, _ := strconv.Atoi(listenAddr[i+1:])
	return p
}

func (s *Server) handleGetInbounds(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
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
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

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
		req.StreamSettings.Security = "none"
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}
	cfgProvider := module.(*config.Provider)

	if cfg := cfgProvider.GetConfig(); cfg != nil && cfg.Chameleon.Enabled {
		if p := portOf(cfg.Chameleon.ListenAddr); p != 0 && p == req.Port {
			s.jsonError(w, http.StatusConflict, fmt.Sprintf("port %d is reserved by chameleon", req.Port))
			return
		}
	}

	err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		foundIndex := -1
		reqNet := req.StreamSettings.Network
		if reqNet == "" {
			reqNet = "tcp"
		}
		for i, in := range cfg.Inbounds {
			if in.Tag == req.Tag {
				foundIndex = i
				break
			}
			inNet := in.StreamSettings.Network
			if inNet == "" {
				inNet = "tcp"
			}
			if in.Port == req.Port && inNet == reqNet {
				foundIndex = i
				break
			}
		}

		if foundIndex != -1 {
			cfg.Inbounds[foundIndex] = req
		} else {
			cfg.Inbounds = append(cfg.Inbounds, req)
		}

	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to update config: "+err.Error())
		return
	}

	if err := openFirewallPort(req.Port); err != nil {
	}

	if portOccupiedByExistingInbound(cfgProvider, req) {
		s.jsonOK(w, map[string]interface{}{
			"success":          true,
			"message":          fmt.Sprintf("Inbound saved. Port %d already in use — restart required to activate.", req.Port),
			"restart_required": true,
			"inbound":          req,
		})
		return
	}

	if err := startDynamicInbound(req); err != nil {
		s.jsonOK(w, map[string]interface{}{
			"success":          true,
			"message":          "Inbound saved, restart required to activate",
			"restart_required": true,
			"inbound":          req,
		})
		return
	}

	s.jsonCreated(w, map[string]interface{}{
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
	return server.Global.StartInbound(inbound)
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
			break
		}
	}

	if foundInbound != nil {
	} else {
		for range cfg.Inbounds {
		}
	}

	if privateKey == "" {
		privateKey = cfg.Server.PrivateKey
		if privateKey != "" {
		}
	}

	if privateKey == "" {
		s.jsonError(w, http.StatusNotFound, "No private key configured for this port or server")
		return
	}

	privKeyBytes, err := decodeBase64OrHex(privateKey)
	if err != nil || len(privKeyBytes) != 32 {
		s.jsonError(w, http.StatusInternalServerError, "Invalid private key format")
		return
	}

	var privKey [32]byte
	copy(privKey[:], privKeyBytes)

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	publicKeyB64 := base64Encode(pubKey[:])

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

	if _, err := exec.LookPath("ufw"); err != nil {
		return fmt.Errorf("ufw not found in PATH, skipping firewall config")
	}
	if out, err := runUFW("allow", fmt.Sprintf("%d/udp", port)); err != nil {
		return fmt.Errorf("failed to allow UDP: %v (output: %s)", err, string(out))
	}
	if out, err := runUFW("allow", fmt.Sprintf("%d/tcp", port)); err != nil {
		return fmt.Errorf("failed to allow TCP: %v (output: %s)", err, string(out))
	}

	return nil
}
