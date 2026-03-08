package bridgepool

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type APIHandler struct {
	registry          *Registry
	trustManager      *TrustManager
	registrationToken string
}

func NewAPIHandler(registry *Registry) *APIHandler {
	return &APIHandler{
		registry:     registry,
		trustManager: NewTrustManager(registry),
	}
}

func (h *APIHandler) SetRegistrationToken(token string) {
	h.registrationToken = token
}
func GenerateRegistrationToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *APIHandler) validateToken(token string) bool {
	if h.registrationToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(h.registrationToken)) == 1
}

func (h *APIHandler) HandleGetBridges(w http.ResponseWriter, r *http.Request) {
	bridges := h.registry.GetAliveBridges()

	type publicBridge struct {
		ID       string `json:"id"`
		Address  string `json:"address"`
		Provider string `json:"provider"`
		Latency  int    `json:"latency_ms"`
	}

	result := make([]publicBridge, len(bridges))
	for i, b := range bridges {
		result[i] = publicBridge{
			ID:       b.ID,
			Address:  b.Address,
			Provider: b.Provider,
			Latency:  b.Latency,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *APIHandler) HandleGetBridgesAdmin(w http.ResponseWriter, r *http.Request) {
	bridges := h.registry.GetAllBridges()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bridges)
}

func (h *APIHandler) HandleAddBridge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address   string `json:"address"`
		Type      string `json:"type"`
		Provider  string `json:"provider"`
		Region    string `json:"region"`
		PublicKey string `json:"public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Address == "" {
		http.Error(w, "Address is required", http.StatusBadRequest)
		return
	}

	bridgeType := BridgeOperator
	switch strings.ToLower(req.Type) {
	case "community":
		bridgeType = BridgeCommunity
	case "user":
		bridgeType = BridgeUser
	}

	info := &BridgeInfo{
		Address:   req.Address,
		Type:      bridgeType,
		Provider:  req.Provider,
		Region:    req.Region,
		PublicKey: req.PublicKey,
	}

	if err := h.registry.RegisterBridge(info); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[BridgePool] Registered new bridge: %s (%s)", info.ID, info.Address)

	isAlive, latencyMS, checkErr := h.registry.CheckBridgeNow(info.ID)
	msg := "Bridge registered and checked"
	if checkErr != nil {
		msg = "Bridge registered (health check failed: " + checkErr.Error() + ")"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"id":         info.ID,
		"is_alive":   isAlive,
		"latency_ms": latencyMS,
		"message":    msg,
	})
}

func (h *APIHandler) HandleDeleteBridge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		http.Error(w, "Bridge ID is required", http.StatusBadRequest)
		return
	}

	if err := h.registry.UnregisterBridge(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	log.Printf("[BridgePool] Removed bridge: %s", req.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Bridge removed successfully",
	})
}

func (h *APIHandler) HandleBridgeHealth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !h.validateToken(req.Token) {
		http.Error(w, "Invalid registration token", http.StatusUnauthorized)
		return
	}

	bridge, err := h.registry.GetBridge(req.ID)
	if err != nil {
		http.Error(w, "Bridge not found", http.StatusNotFound)
		return
	}

	h.registry.UpdateBridgeStatus(req.ID, true, bridge.Latency)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Heartbeat received",
	})
}

func (h *APIHandler) HandleRegisterBridge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address   string `json:"address"`
		Provider  string `json:"provider"`
		Region    string `json:"region"`
		PublicKey string `json:"public_key"`
		Type      string `json:"type"`
		Token     string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !h.validateToken(req.Token) {
		log.Printf("[BridgePool] Rejected registration from %s - invalid token", r.RemoteAddr)
		http.Error(w, "Invalid registration token", http.StatusUnauthorized)
		return
	}

	if req.Address == "" {
		http.Error(w, "Address is required", http.StatusBadRequest)
		return
	}

	bridgeType := BridgeCommunity
	switch strings.ToLower(req.Type) {
	case "operator":
		bridgeType = BridgeOperator
	case "user":
		bridgeType = BridgeUser
	}

	info := &BridgeInfo{
		Address:   req.Address,
		Type:      bridgeType,
		Provider:  req.Provider,
		Region:    req.Region,
		PublicKey: req.PublicKey,
		// Self-registration proves reachability — mark alive immediately.
		IsAlive: true,
	}

	if err := h.registry.RegisterBridge(info); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[BridgePool] Self-registration: %s (%s) from %s", info.ID, info.Address, r.RemoteAddr)

	// Async latency measurement — doesn't block the registration response.
	go func(id string) { h.registry.CheckBridgeNow(id) }(info.ID) //nolint:errcheck

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"id":      info.ID,
		"message": "Bridge registered successfully",
	})
}

func (h *APIHandler) HandleGetRegistrationToken(w http.ResponseWriter, r *http.Request) {
	if h.registrationToken == "" {
		h.registrationToken = GenerateRegistrationToken()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": h.registrationToken,
	})
}

func (h *APIHandler) HandleRegenerateToken(w http.ResponseWriter, r *http.Request) {
	h.registrationToken = GenerateRegistrationToken()
	log.Printf("[BridgePool] Registration token regenerated")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"token":   h.registrationToken,
		"message": "Token regenerated. Update all bridges with new token.",
	})
}

func (h *APIHandler) HandleGetCloudInit(w http.ResponseWriter, r *http.Request) {
	if h.registrationToken == "" {
		h.registrationToken = GenerateRegistrationToken()
	}

	serverAddr := r.Host
	if serverAddr == "" {
		serverAddr = "YOUR_SERVER:443"
	}
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "auto"
	}

	cloudInit := `#!/bin/bash
# Whispera Bridge Auto-Install (Generated)
# 
# Paste this as "User Data" when creating VPS

set -e
apt-get update && apt-get install -y curl

# Download and run installer
curl -sL "https://` + serverAddr + `/install-bridge.sh" -o /tmp/install.sh || \
    curl -sL "https://raw.githubusercontent.com/your-repo/whispera/main/scripts/install-bridge.sh" -o /tmp/install.sh

chmod +x /tmp/install.sh
/tmp/install.sh "` + serverAddr + `" "` + h.registrationToken + `" --provider "` + provider + `"
`

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=cloud-init-bridge.sh")
	w.Write([]byte(cloudInit))
}
