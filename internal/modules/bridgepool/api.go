package bridgepool

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

var mlHTTPClient = &http.Client{Timeout: 2 * time.Second}

func mlBaseURL() string {
	if u := os.Getenv("WHISPERA_ML_SERVER"); u != "" {
		return u
	}
	return "http://127.0.0.1:8000"
}

// mlRankBridges calls POST /rank/bridges on the ML server and returns a map[bridgeID]mlScore.
// Returns nil on any error (caller uses original order).
func mlRankBridges(bridges []*BridgeInfo) map[string]float64 {
	type payload struct {
		ID            string  `json:"id"`
		Lat           float64 `json:"lat"`
		Lon           float64 `json:"lon"`
		Country       string  `json:"country"`
		City          string  `json:"city"`
		Alive         bool    `json:"alive"`
		LatencyMs     float64 `json:"latency_ms"`
		Load          float64 `json:"load"`
		BandwidthMbps float64 `json:"bandwidth_mbps"`
		CurUsers      int     `json:"cur_users"`
		MaxUsers      int     `json:"max_users"`
		Type          string  `json:"type"`
	}
	items := make([]payload, len(bridges))
	for i, b := range bridges {
		items[i] = payload{
			ID:            b.ID,
			Lat:           b.Lat,
			Lon:           b.Lon,
			Country:       b.Country,
			City:          b.City,
			Alive:         true,
			LatencyMs:     float64(b.Latency),
			Load:          b.Load,
			BandwidthMbps: float64(b.Bandwidth),
			CurUsers:      b.CurUsers,
			MaxUsers:      b.MaxUsers,
			Type:          string(b.Type),
		}
	}
	body, _ := json.Marshal(items)
	resp, err := mlHTTPClient.Post(mlBaseURL()+"/rank/bridges", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var ranked []struct {
		ID      string  `json:"id"`
		MLScore float64 `json:"ml_score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ranked); err != nil {
		return nil
	}
	scores := make(map[string]float64, len(ranked))
	for _, r := range ranked {
		scores[r.ID] = r.MLScore
	}
	return scores
}

type APIHandler struct {
	registry          *Registry
	trustManager      *TrustManager
	registrationToken string
}

// geoInfo holds the result of an ipinfo.io lookup.
type geoInfo struct {
	Country string  `json:"country"`
	City    string  `json:"city"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

// lookupGeo queries ipinfo.io for country, city and coordinates of an IP.
// Returns zero-value geoInfo on any error (non-fatal).
func lookupGeo(addr string) geoInfo {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if net.ParseIP(host) == nil {
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return geoInfo{}
		}
		host = addrs[0]
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://ipinfo.io/%s/json", host), nil)
	if err != nil {
		return geoInfo{}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return geoInfo{}
	}
	defer resp.Body.Close()

	var result struct {
		Country string `json:"country"`
		City    string `json:"city"`
		Loc     string `json:"loc"` // "lat,lon"
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return geoInfo{}
	}

	var lat, lon float64
	fmt.Sscanf(result.Loc, "%f,%f", &lat, &lon)

	return geoInfo{
		Country: result.Country,
		City:    result.City,
		Lat:     lat,
		Lon:     lon,
	}
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

	// ML-rank bridges when available; falls back to original order silently
	mlScores := mlRankBridges(bridges)
	if mlScores != nil {
		sort.Slice(bridges, func(i, j int) bool {
			return mlScores[bridges[i].ID] > mlScores[bridges[j].ID]
		})
	}

	type publicBridge struct {
		ID       string     `json:"id"`
		Address  string     `json:"address"`
		Type     BridgeType `json:"type"`
		Provider string     `json:"provider"`
		Country  string     `json:"country,omitempty"`
		City     string     `json:"city,omitempty"`
		Latency  int        `json:"latency_ms"`
		MLScore  float64    `json:"ml_score,omitempty"`
	}

	result := make([]publicBridge, len(bridges))
	for i, b := range bridges {
		result[i] = publicBridge{
			ID:       b.ID,
			Address:  b.Address,
			Type:     b.Type,
			Provider: b.Provider,
			Country:  b.Country,
			City:     b.City,
			Latency:  b.Latency,
			MLScore:  mlScores[b.ID],
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
		Address   string  `json:"address"`
		Name      string  `json:"name"`
		Type      string  `json:"type"`
		Provider  string  `json:"provider"`
		Region    string  `json:"region"`
		PublicKey string  `json:"public_key"`
		Country   string  `json:"country"`
		City      string  `json:"city"`
		Lat       float64 `json:"lat"`
		Lon       float64 `json:"lon"`
		Bandwidth int     `json:"bandwidth_mbps"`
		SSHPubKey string  `json:"ssh_pub_key"`
		MaxUsers  int     `json:"max_users"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Address == "" {
		http.Error(w, "Address is required", http.StatusBadRequest)
		return
	}

	// Auto-fill geo info if not provided by the caller.
	if req.Lat == 0 && req.Lon == 0 {
		geo := lookupGeo(req.Address)
		if req.Country == "" {
			req.Country = geo.Country
		}
		if req.City == "" {
			req.City = geo.City
		}
		if geo.Lat != 0 || geo.Lon != 0 {
			req.Lat = geo.Lat
			req.Lon = geo.Lon
		}
	}

	bridgeType := BridgeOperator
	switch strings.ToLower(req.Type) {
	case "community":
		bridgeType = BridgeCommunity
	case "user":
		bridgeType = BridgeUser
	case "white":
		bridgeType = BridgeWhite
	}

	info := &BridgeInfo{
		Name:      req.Name,
		Address:   req.Address,
		Type:      bridgeType,
		Provider:  req.Provider,
		Region:    req.Region,
		PublicKey: req.PublicKey,
		Country:   req.Country,
		City:      req.City,
		Lat:       req.Lat,
		Lon:       req.Lon,
		Bandwidth: req.Bandwidth,
		SSHPubKey: req.SSHPubKey,
		MaxUsers:  req.MaxUsers,
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
	case "white":
		bridgeType = BridgeWhite
	}

	info := &BridgeInfo{
		Address:   req.Address,
		Type:      bridgeType,
		Provider:  req.Provider,
		Region:    req.Region,
		PublicKey: req.PublicKey,
		IsAlive: true,
	}

	if err := h.registry.RegisterBridge(info); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[BridgePool] Self-registration: %s (%s) from %s", info.ID, info.Address, r.RemoteAddr)

	go func(id string) { h.registry.CheckBridgeNow(id) }(info.ID)

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

	serverAddr := r.URL.Query().Get("server")
	if serverAddr == "" {
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			serverAddr = ip + ":8081"
		} else if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			if idx := strings.Index(ip, ","); idx != -1 {
				ip = strings.TrimSpace(ip[:idx])
			}
			serverAddr = ip + ":8081"
		} else {
			serverAddr = r.Host
		}
	}
	if serverAddr == "" {
		serverAddr = "YOUR_SERVER_IP:8081"
	}

	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "auto"
	}
	region := r.URL.Query().Get("region")
	if region == "" {
		region = "auto"
	}

	cloudInit := `#!/bin/bash
# Whispera Bridge Auto-Install
# Generated for server: ` + serverAddr + `
# Paste as "User Data" when creating a VPS, or run manually as root.

set -e

SERVER="` + serverAddr + `"
TOKEN="` + h.registrationToken + `"
PROVIDER="` + provider + `"
REGION="` + region + `"

apt-get update -qq && apt-get install -y curl 2>/dev/null || yum install -y curl 2>/dev/null || true

# Download install script from main server (falls back to GitHub)
curl -fsSL "https://${SERVER}/install-bridge.sh" -o /tmp/install-bridge.sh \
    --insecure --connect-timeout 10 2>/dev/null || \
curl -fsSL "https://raw.githubusercontent.com/Jalaveyan/Whispera/main/scripts/install-bridge.sh" \
    -o /tmp/install-bridge.sh

chmod +x /tmp/install-bridge.sh
/tmp/install-bridge.sh "${SERVER}" "${TOKEN}" --provider "${PROVIDER}" --region "${REGION}"
`

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=cloud-init-bridge.sh")
	w.Write([]byte(cloudInit))
}

func (h *APIHandler) HandleGetWhiteBridges(w http.ResponseWriter, r *http.Request) {
	bridges := h.registry.GetWhiteBridges()

	type whiteBridge struct {
		ID        string  `json:"id"`
		Address   string  `json:"address"`
		Country   string  `json:"country"`
		City      string  `json:"city"`
		Lat       float64 `json:"lat"`
		Lon       float64 `json:"lon"`
		Latency   int     `json:"latency_ms"`
		Bandwidth int     `json:"bandwidth_mbps"`
		Load      float64 `json:"load"`
		MaxUsers  int     `json:"max_users"`
		CurUsers  int     `json:"cur_users"`
	}

	result := make([]whiteBridge, len(bridges))
	for i, b := range bridges {
		result[i] = whiteBridge{
			ID:        b.ID,
			Address:   b.Address,
			Country:   b.Country,
			City:      b.City,
			Lat:       b.Lat,
			Lon:       b.Lon,
			Latency:   b.Latency,
			Bandwidth: b.Bandwidth,
			Load:      b.Load,
			MaxUsers:  b.MaxUsers,
			CurUsers:  b.CurUsers,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *APIHandler) HandleGetBridgeMap(w http.ResponseWriter, r *http.Request) {
	mapData := h.registry.GetBridgeMap()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mapData)
}

func (h *APIHandler) HandleBridgeConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BridgeID string `json:"bridge_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.BridgeID == "" {
		http.Error(w, "bridge_id required", http.StatusBadRequest)
		return
	}

	data, err := h.registry.GetBridgeForConnect(req.BridgeID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"connection": data,
	})
}

func (h *APIHandler) HandleBridgeScan(w http.ResponseWriter, r *http.Request) {
	results := h.registry.ScanAllBridges()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"results": results,
		"scanned": len(results),
	})
}

func (h *APIHandler) HandleBridgeHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string  `json:"id"`
		Token    string  `json:"token"`
		Load     float64 `json:"load"`
		CurUsers int     `json:"cur_users"`
		Version  string  `json:"version"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !h.validateToken(req.Token) {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	bridge, err := h.registry.GetBridge(req.ID)
	if err != nil {
		http.Error(w, "Bridge not found", http.StatusNotFound)
		return
	}

	h.registry.UpdateBridgeStatus(req.ID, true, bridge.Latency)
	h.registry.UpdateBridgeLoad(req.ID, req.Load, req.CurUsers)

	h.registry.mu.Lock()
	if b, exists := h.registry.bridges[req.ID]; exists && req.Version != "" {
		b.Version = req.Version
	}
	h.registry.mu.Unlock()

	adminKey := h.registry.GetAdminSSHKey()
	accessKeys := h.registry.GetAccessKeysForBridge(req.ID)

	authorizedKeys := make([]string, 0)
	if adminKey != "" {
		authorizedKeys = append(authorizedKeys, adminKey)
	}
	for _, ak := range accessKeys {
		if !ak.Used || !ak.OneTime {
			authorizedKeys = append(authorizedKeys, ak.SSHKey)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"authorized_keys": authorizedKeys,
	})
}

func (h *APIHandler) HandleSetAdminSSHKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SSHKey string `json:"ssh_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.SSHKey == "" {
		http.Error(w, "SSH key is required", http.StatusBadRequest)
		return
	}

	h.registry.SetAdminSSHKey(req.SSHKey)
	log.Printf("[BridgePool] Admin SSH key updated")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *APIHandler) HandleIssueAccessKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BridgeID string `json:"bridge_id"`
		UserID   string `json:"user_id"`
		OneTime  bool   `json:"one_time"`
		TTLHours int    `json:"ttl_hours"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.BridgeID == "" || req.UserID == "" {
		http.Error(w, "bridge_id and user_id required", http.StatusBadRequest)
		return
	}

	ttl := 24 * time.Hour
	if req.TTLHours > 0 {
		ttl = time.Duration(req.TTLHours) * time.Hour
	}

	ak, err := h.registry.IssueAccessKey(req.BridgeID, req.UserID, req.OneTime, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[BridgePool] Access key issued: %s for bridge %s (user: %s, one_time: %v)",
		ak.ID, req.BridgeID, req.UserID, req.OneTime)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"key_id":     ak.ID,
		"ssh_key":    ak.SSHKey,
		"expires_at": ak.ExpiresAt,
		"one_time":   ak.OneTime,
	})
}

func (h *APIHandler) HandleValidateAccessKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID string `json:"key_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ak, err := h.registry.ValidateAccessKey(req.KeyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"bridge_id": ak.BridgeID,
		"ssh_key":   ak.SSHKey,
	})
}

func (h *APIHandler) HandleRevokeAccessKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID string `json:"key_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.registry.RevokeAccessKey(req.KeyID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	log.Printf("[BridgePool] Access key revoked: %s", req.KeyID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *APIHandler) HandleGetWhiteCloudInit(w http.ResponseWriter, r *http.Request) {
	if h.registrationToken == "" {
		h.registrationToken = GenerateRegistrationToken()
	}

	serverAddr := r.URL.Query().Get("server")
	if serverAddr == "" {
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			serverAddr = ip + ":8081"
		} else if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			if idx := strings.Index(ip, ","); idx != -1 {
				ip = strings.TrimSpace(ip[:idx])
			}
			serverAddr = ip + ":8081"
		} else {
			serverAddr = r.Host
		}
	}
	if serverAddr == "" {
		serverAddr = "YOUR_SERVER_IP:8081"
	}

	country := r.URL.Query().Get("country")
	city := r.URL.Query().Get("city")
	bandwidth := r.URL.Query().Get("bandwidth")
	if bandwidth == "" {
		bandwidth = "100"
	}
	maxUsers := r.URL.Query().Get("max_users")
	if maxUsers == "" {
		maxUsers = "50"
	}

	cloudInit := `#!/bin/bash
set -e

SERVER="` + serverAddr + `"
TOKEN="` + h.registrationToken + `"
COUNTRY="` + country + `"
CITY="` + city + `"
BANDWIDTH="` + bandwidth + `"
MAX_USERS="` + maxUsers + `"

apt-get update -qq && apt-get install -y curl jq openssh-server 2>/dev/null || true

SSH_KEY=$(cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q && cat /etc/ssh/ssh_host_ed25519_key.pub)

sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true

MY_IP=$(curl -4 -s ifconfig.me || curl -4 -s icanhazip.com)
MY_PORT=8443

PAYLOAD=$(jq -n \
  --arg address "${MY_IP}:${MY_PORT}" \
  --arg type "white" \
  --arg token "${TOKEN}" \
  --arg ssh_pub_key "${SSH_KEY}" \
  --arg country "${COUNTRY}" \
  --arg city "${CITY}" \
  --argjson bandwidth_mbps "${BANDWIDTH}" \
  --argjson max_users "${MAX_USERS}" \
  '{address: $address, type: $type, token: $token, ssh_pub_key: $ssh_pub_key, country: $country, city: $city, bandwidth_mbps: ($bandwidth_mbps|tonumber), max_users: ($max_users|tonumber)}')

RESULT=$(curl -s -X POST "https://${SERVER}/api/bridge-register" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}" --insecure)

BRIDGE_ID=$(echo "${RESULT}" | jq -r '.id // empty')
if [ -z "${BRIDGE_ID}" ]; then
  echo "Registration failed: ${RESULT}"
  exit 1
fi

mkdir -p /etc/whispera
echo "${BRIDGE_ID}" > /etc/whispera/bridge-id
echo "${TOKEN}" > /etc/whispera/bridge-token
echo "${SERVER}" > /etc/whispera/bridge-server

cat > /usr/local/bin/whispera-bridge-heartbeat <<'HBEOF'
#!/bin/bash
BRIDGE_ID=$(cat /etc/whispera/bridge-id)
TOKEN=$(cat /etc/whispera/bridge-token)
SERVER=$(cat /etc/whispera/bridge-server)
LOAD=$(awk '{print $1}' /proc/loadavg)
USERS=$(who | wc -l)
VERSION=$(whispera --version 2>/dev/null || echo "unknown")
curl -s -X POST "https://${SERVER}/api/bridge-heartbeat" \
  -H "Content-Type: application/json" \
  -d "{\"id\":\"${BRIDGE_ID}\",\"token\":\"${TOKEN}\",\"load\":${LOAD},\"cur_users\":${USERS},\"version\":\"${VERSION}\"}" \
  --insecure | jq -r '.authorized_keys[]?' > /tmp/whispera_keys 2>/dev/null
if [ -s /tmp/whispera_keys ]; then
  mkdir -p /root/.ssh
  cp /tmp/whispera_keys /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi
rm -f /tmp/whispera_keys
HBEOF
chmod +x /usr/local/bin/whispera-bridge-heartbeat

(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/whispera-bridge-heartbeat") | sort -u | crontab -

echo "White bridge registered: ${BRIDGE_ID}"
echo "Server: ${SERVER}"
`

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=install-white-bridge.sh")
	w.Write([]byte(cloudInit))
}
