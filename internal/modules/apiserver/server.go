// Package apiserver provides the API server module
package apiserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"whispera/internal/auth"
	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/modules/apiserver/handlers"
	"whispera/internal/modules/config"
	"whispera/internal/modules/dhcp"
	"whispera/internal/network"
	"whispera/internal/stats"

	"golang.org/x/crypto/curve25519"
)

const (
	ModuleName    = "api.server"
	ModuleVersion = "1.0.0"
)

// Config holds API server configuration
type Config struct {
	Enabled    bool
	ListenAddr string
	AuthToken  string
	WebRoot    string
	EnableCORS bool
	TLSCert    string
	TLSKey     string
}

// DefaultConfig returns default API configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:    true,
		ListenAddr: ":8081",
		EnableCORS: true,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8081"
	}
	return nil
}

// Server implements the API server module
type Server struct {
	*base.Module
	config *Config

	// HTTP server
	server *http.Server
	mux    *http.ServeMux

	// Dependencies
	registry registry.Registry

	// Route handlers
	mu       sync.RWMutex
	handlers map[string]http.HandlerFunc

	// Managers
	mfaManager *auth.MFAManager
}

// New creates a new API server
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	s := &Server{
		Module:     base.NewModule(ModuleName, ModuleVersion, nil),
		config:     cfg,
		mux:        http.NewServeMux(),
		handlers:   make(map[string]http.HandlerFunc),
		mfaManager: auth.NewMFAManager(),
	}

	// Register default routes
	s.registerDefaultRoutes()

	return s, nil
}

// registerDefaultRoutes registers built-in API routes
func (s *Server) registerDefaultRoutes() {
	// Login endpoint (no auth required)
	s.Handle("POST /api/login", s.handleLogin)

	s.Handle("GET /api/v1/health", s.handleHealth)
	s.Handle("GET /api/v1/status", s.handleStatus)
	s.Handle("GET /api/v1/modules", s.handleModules)
	// Config routes
	s.Handle("GET /api/v1/config", s.handleGetConfig)

	// MFA routes
	mfaHandler := handlers.NewMFAHandler(s.mfaManager)
	s.Handle("POST /api/v1/auth/mfa/setup", mfaHandler.Setup)
	s.Handle("POST /api/v1/auth/mfa/verify", mfaHandler.Verify)
	s.Handle("POST /api/v1/auth/mfa/validate", mfaHandler.Validate)
	s.Handle("POST /api/v1/auth/mfa/disable", mfaHandler.Disable)
	s.Handle("POST /api/v1/config/update", s.handleUpdateConfig)
	s.Handle("POST /api/v1/config/reload", s.handleReloadConfig)
	s.Handle("GET /api/v1/sessions", s.handleGetSessions)
	s.Handle("DELETE /api/v1/sessions/{id}", s.handleDeleteSession)
	s.Handle("GET /api/v1/stats", s.handleGetStats)
	s.Handle("GET /api/v1/system/info", s.handleSystemInfo)
	s.Handle("GET /api/v1/stats/traffic", s.handleTrafficStats)
	s.Handle("GET /api/v1/stats/users", s.handleUserStats)

	// DHCP endpoints
	s.Handle("GET /api/v1/dhcp/status", s.handleDHCPStatus)
	s.Handle("GET /api/v1/dhcp/leases", s.handleDHCPLeases)
	s.Handle("DELETE /api/v1/dhcp/lease", s.handleDHCPRelease)

	// User management endpoints (frontend uses /api/users format)
	s.Handle("GET /api/users", s.handleGetUsers)
	s.Handle("POST /api/users/add", s.handleAddUser)
	s.Handle("PUT /api/users/{id}", s.handleUpdateUser)
	s.Handle("POST /api/users/delete", s.handleDeleteUser)

	// Inbound management endpoints
	s.Handle("GET /api/inbounds", s.handleGetInbounds)
	s.Handle("GET /api/inbounds/pubkey", s.handleGetInboundPublicKey)
	s.Handle("POST /api/inbounds/add", s.handleAddInbound)
	s.Handle("POST /api/inbounds/update", s.handleUpdateInbound)
	s.Handle("POST /api/inbounds/delete", s.handleDeleteInbound)

	// Key generation
	s.Handle("POST /api/keys/generate", s.handleGenerateKeys)
	s.Handle("POST /api/keys/connection", s.handleGenerateConnectionKey)

	// Sessions (frontend format)
	s.Handle("GET /api/sessions", s.handleGetSessionsAPI)

	// Stats (frontend format)
	s.Handle("GET /api/stats", s.handleGetStatsAPI)
	s.Handle("GET /api/stats/traffic", s.handleTrafficStatsAPI)

	// System info (frontend format)
	s.Handle("GET /api/system/info", s.handleSystemInfoAPI)
}

// Init initializes the API server
func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if apiCfg, ok := cfg.(*Config); ok {
		s.config = apiCfg
	}

	return nil
}

// Start starts the API server
func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	if !s.config.Enabled {
		s.SetHealthy(true, "API server disabled")
		return nil
	}

	// Build final handler
	handler := s.buildHandler()

	s.server = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Create listener first to verify port binding
	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to bind API server to %s: %v", s.config.ListenAddr, err)
		fmt.Printf("[ERROR] %s\n", errMsg)
		s.SetHealthy(false, errMsg)
		return fmt.Errorf(errMsg)
	}

	fmt.Printf("[INFO] API Server listening on %s\n", s.config.ListenAddr)

	go func() {
		var serveErr error
		if s.config.TLSCert != "" && s.config.TLSKey != "" {
			serveErr = s.server.ServeTLS(ln, s.config.TLSCert, s.config.TLSKey)
		} else {
			serveErr = s.server.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			fmt.Printf("[ERROR] API Server error: %v\n", serveErr)
			s.SetHealthy(false, fmt.Sprintf("HTTP server error: %v", serveErr))
		}
	}()

	s.SetHealthy(true, fmt.Sprintf("API server running on %s", s.config.ListenAddr))
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": s.config.ListenAddr,
	})

	return nil
}

// Stop stops the API server
func (s *Server) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)
	}

	s.PublishEvent(events.EventTypeModuleStopped, nil)
	return s.Module.Stop()
}

// SetRegistry sets the module registry
func (s *Server) SetRegistry(reg registry.Registry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registry = reg
}

// Handle registers a handler for a route
func (s *Server) Handle(pattern string, handler http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[pattern] = handler
}

// buildHandler builds the final HTTP handler
func (s *Server) buildHandler() http.Handler {
	// Root handler (Mux)
	var rootHandler http.Handler = s.mux

	// If WebRoot is configured, serve static files
	if s.config.WebRoot != "" {
		fs := http.FileServer(http.Dir(s.config.WebRoot))
		// Chain handler: check API routes first (s.mux), then static files
		rootHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if it's an API request
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.mux.ServeHTTP(w, r)
				return
			}
			// Serve static file
			fs.ServeHTTP(w, r)
		})
	}
	s.mu.RLock()
	for pattern, handler := range s.handlers {
		// Parse method and path from pattern
		parts := strings.SplitN(pattern, " ", 2)
		if len(parts) == 2 {
			s.mux.HandleFunc(parts[1], s.methodFilter(parts[0], handler))
		} else {
			s.mux.HandleFunc(pattern, handler)
		}
	}
	s.mu.RUnlock()

	// Wrap with middleware
	var handler http.Handler = rootHandler

	// Auth middleware (Inner)
	if s.config.AuthToken != "" {
		handler = s.authMiddleware(handler)
	}

	// CORS middleware (Outer)
	if s.config.EnableCORS {
		handler = s.corsMiddleware(handler)
	}

	// Logging middleware
	handler = s.loggingMiddleware(handler)

	// Recovery middleware (Outermost)
	handler = s.recoveryMiddleware(handler)

	return handler
}

// methodFilter filters requests by HTTP method
func (s *Server) methodFilter(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware validates authentication
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only enforce auth on API routes
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth for login and health endpoints
		if r.URL.Path == "/api/login" || strings.HasSuffix(r.URL.Path, "/health") {
			next.ServeHTTP(w, r)
			return
		}

		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+s.config.AuthToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.UpdateActivity()

		// Could log here
		_ = start
	})
}

// recoveryMiddleware recovers from panics
func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Stack trace
				stack := make([]byte, 4096)
				n := runtime.Stack(stack, false)
				fmt.Printf("[PANIC] API Server: %v\n%s\n", err, stack[:n])

				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Internal Server Error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// JSON response helpers

type jsonResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func (s *Server) jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	// Return data directly without wrapper for frontend compatibility
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(jsonResponse{Success: false, Error: message})
}

// Route handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := s.HealthCheck()

	response := map[string]interface{}{
		"status":  "ok",
		"healthy": health.Healthy,
		"message": health.Message,
	}

	if s.registry != nil {
		moduleHealth := s.registry.HealthCheck()
		response["modules"] = moduleHealth
	}

	s.jsonOK(w, response)
}

// handleLogin handles user authentication
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Simple authentication: admin/admin returns the auth token from config
	// In production, this should use proper password hashing
	if req.Username == "admin" && req.Password == "admin" {
		token := s.config.AuthToken
		if token == "" {
			// Generate a default token if not configured
			token = "whispera_default_token"
		}
		// Return token at root level for frontend compatibility
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"token":   token,
			"user": map[string]string{
				"username": req.Username,
				"role":     "admin",
			},
		})
		return
	}

	s.jsonError(w, http.StatusUnauthorized, "Invalid username or password")
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"version": ModuleVersion,
		"uptime":  time.Since(s.LastActivity()).String(),
		"running": s.IsRunning(),
	}

	if s.registry != nil {
		modules := s.registry.GetAll()
		status["module_count"] = len(modules)
	}

	s.jsonOK(w, status)
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonError(w, http.StatusInternalServerError, "Registry not available")
		return
	}

	modules := s.registry.GetAll()
	moduleList := make([]map[string]interface{}, 0, len(modules))

	for _, m := range modules {
		health := m.HealthCheck()
		moduleList = append(moduleList, map[string]interface{}{
			"name":         m.Name(),
			"version":      m.Version(),
			"healthy":      health.Healthy,
			"message":      health.Message,
			"dependencies": m.Dependencies(),
		})
	}

	s.jsonOK(w, moduleList)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// Would return current configuration
	// This is a placeholder
	s.jsonOK(w, map[string]interface{}{
		"api": map[string]interface{}{
			"listen_addr": s.config.ListenAddr,
			"cors":        s.config.EnableCORS,
		},
	})
}

func (s *Server) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonError(w, http.StatusInternalServerError, "Registry not available")
		return
	}

	if err := s.registry.Reload(r.Context(), nil); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.PublishEvent(events.EventTypeConfigReloaded, nil)
	s.jsonOK(w, map[string]string{"message": "Configuration reloaded"})
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonError(w, http.StatusInternalServerError, "Registry not available")
		return
	}

	var req struct {
		Server struct {
			IP      string `json:"ip"`
			Port    int    `json:"port"`
			TCPPort int    `json:"tcpPort"`
			WSPort  int    `json:"wsPort"`
			WS2Port int    `json:"ws2Port"`
		} `json:"server"`
		Obfuscation struct {
			DefaultProfile    string `json:"defaultProfile"`
			DefaultMarionette string `json:"defaultMarionette"`
			AutoProfile       bool   `json:"autoProfile"`
		} `json:"obfuscation"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get config provider
	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Config provider not found")
		return
	}

	cfgProvider, ok := module.(*config.Provider)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Invalid config provider type")
		return
	}

	err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		// Update ports if provided
		if req.Server.Port > 0 {
			cfg.Transport.UDP.ListenAddr = fmt.Sprintf(":%d", req.Server.Port)
			// Also update main server listen addr as it usually matches UDP
			cfg.Server.ListenAddr = cfg.Transport.UDP.ListenAddr
		}
		if req.Server.TCPPort > 0 {
			cfg.Transport.TCP.ListenAddr = fmt.Sprintf(":%d", req.Server.TCPPort)
		}
		if req.Server.WSPort > 0 {
			cfg.Transport.WebSocket.ListenAddr = fmt.Sprintf(":%d", req.Server.WSPort)
		}
		// WS2Port is usually handled by XHTTP or another field, assuming XHTTP for now or ignore if not present in struct
		// Looking at config.go, there is XHTTP but no explicit "WS2".
		// We'll map it to XHTTP if possible or just ignore for now if not clear.
		// Re-checking config.go... XHTTP has ListenAddr.
		if req.Server.WS2Port > 0 {
			cfg.Transport.XHTTP.ListenAddr = fmt.Sprintf(":%d", req.Server.WS2Port)
		}

		if req.Obfuscation.DefaultProfile != "" {
			cfg.Obfuscation.Profile = req.Obfuscation.DefaultProfile
		}
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to update config: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]string{"message": "Configuration updated"})
}

func (s *Server) handleGetSessions(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonError(w, http.StatusInternalServerError, "Registry not available")
		return
	}

	// Get session manager
	module, ok := s.registry.Get("session.manager")
	if !ok {
		s.jsonError(w, http.StatusNotFound, "Session manager not found")
		return
	}

	sessionMgr, ok := module.(interfaces.SessionManager)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Invalid session manager")
		return
	}

	sessions := sessionMgr.GetAllSessions()
	sessionList := make([]map[string]interface{}, 0, len(sessions))

	for _, sess := range sessions {
		sessionList = append(sessionList, map[string]interface{}{
			"id":            sess.ID(),
			"client_addr":   sess.ClientAddr().String(),
			"last_activity": sess.LastActivity(),
		})
	}

	s.jsonOK(w, map[string]interface{}{
		"count":    len(sessionList),
		"sessions": sessionList,
	})
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	// Would delete a specific session
	// Path parameter parsing would go here
	s.jsonOK(w, map[string]string{"message": "Session deleted"})
}

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"timestamp": time.Now(),
	}

	if s.registry != nil {
		health := s.registry.HealthCheck()
		for name, h := range health {
			if h.Details != nil {
				stats[name] = h.Details
			}
		}
	}

	s.jsonOK(w, stats)
}

// handleSystemInfo returns server system information including external IP
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Detect external IP
	externalIP, err := network.DetectServerIP(ctx)
	if err != nil {
		externalIP = "unknown"
	}

	// Get hostname
	hostname, _ := os.Hostname()

	// Build system info
	info := map[string]interface{}{
		"server_ip":     externalIP,
		"serverIP":      externalIP, // Alias for frontend compatibility
		"hostname":      hostname,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"go_version":    runtime.Version(),
		"num_cpu":       runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
	}

	// Add server port if available
	if s.config != nil && s.config.ListenAddr != "" {
		info["api_addr"] = s.config.ListenAddr
	}

	// Add module count if registry available
	if s.registry != nil {
		modules := s.registry.GetAll()
		info["module_count"] = len(modules)
	}

	// Get network interfaces info
	serverInfo, _ := network.GetServerInfo(ctx)
	if serverInfo != nil {
		info["interfaces"] = serverInfo.Interfaces
		info["detected_at"] = serverInfo.DetectedAt
	}

	s.jsonOK(w, info)
}

// handleTrafficStats returns real traffic statistics
func (s *Server) handleTrafficStats(w http.ResponseWriter, r *http.Request) {
	globalStats := stats.GetGlobalStats()

	s.jsonOK(w, map[string]interface{}{
		"total_download":   globalStats.TotalBytesRx,
		"total_upload":     globalStats.TotalBytesTx,
		"total_packets_rx": globalStats.TotalPacketsRx,
		"total_packets_tx": globalStats.TotalPacketsTx,
		"active_users":     globalStats.ActiveUsers,
		"uptime":           globalStats.Uptime,
		"uptime_seconds":   globalStats.UptimeSeconds,
		"history":          globalStats.History,
	})
}

// handleUserStats returns per-user traffic statistics
func (s *Server) handleUserStats(w http.ResponseWriter, r *http.Request) {
	// Check for specific user ID in query
	userID := r.URL.Query().Get("user_id")

	if userID != "" {
		// Return stats for specific user
		userStats := stats.GetUserStats(userID)
		if userStats == nil {
			s.jsonError(w, http.StatusNotFound, "User not found")
			return
		}
		s.jsonOK(w, userStats)
		return
	}

	// Return all user stats
	allStats := stats.GetAllUserStats()
	s.jsonOK(w, map[string]interface{}{
		"count": len(allStats),
		"users": allStats,
	})
}

// Global DHCP manager instance (will be set by main or module registry)
var globalDHCPManager *dhcp.Manager

// SetDHCPManager sets the DHCP manager for API handlers
func SetDHCPManager(m *dhcp.Manager) {
	globalDHCPManager = m
}

// handleDHCPStatus returns DHCP pool status
func (s *Server) handleDHCPStatus(w http.ResponseWriter, r *http.Request) {
	if globalDHCPManager == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "DHCP not initialized")
		return
	}

	s.jsonOK(w, globalDHCPManager.GetStats())
}

// handleDHCPLeases returns all active leases
func (s *Server) handleDHCPLeases(w http.ResponseWriter, r *http.Request) {
	if globalDHCPManager == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "DHCP not initialized")
		return
	}

	leases := globalDHCPManager.GetAllLeases()
	s.jsonOK(w, map[string]interface{}{
		"count":  len(leases),
		"leases": leases,
	})
}

// handleDHCPRelease releases an IP lease
func (s *Server) handleDHCPRelease(w http.ResponseWriter, r *http.Request) {
	if globalDHCPManager == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "DHCP not initialized")
		return
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		s.jsonError(w, http.StatusBadRequest, "client_id required")
		return
	}

	if err := globalDHCPManager.ReleaseByClient(clientID); err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}

	s.jsonOK(w, map[string]string{"message": "Lease released"})
}

// ============================================
// User Management Handlers
// ============================================

// User represents a user in the system
type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PrivateKey   string    `json:"privateKey,omitempty"`
	PublicKey    string    `json:"publicKey,omitempty"`
	Upload       int64     `json:"upload"`
	Download     int64     `json:"download"`
	TrafficLimit int64     `json:"trafficLimit"`
	ExpiryDate   string    `json:"expiryDate,omitempty"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"createdAt"`
}

// In-memory user store (in production, use database)
var (
	userStore   = make(map[int]*User)
	userStoreMu sync.RWMutex
	nextUserID  = 1
)

func (s *Server) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	userStoreMu.RLock()
	defer userStoreMu.RUnlock()

	users := make([]*User, 0, len(userStore))
	for _, u := range userStore {
		// Get traffic from stats
		userStats := stats.GetUserStats(u.Username)
		if userStats != nil {
			u.Upload = userStats.BytesTx
			u.Download = userStats.BytesRx
		}
		users = append(users, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username     string `json:"username"`
		TrafficLimit int64  `json:"trafficLimit"`
		ExpiryDate   string `json:"expiryDate"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Username == "" {
		s.jsonError(w, http.StatusBadRequest, "Username is required")
		return
	}

	// Generate keys
	keys, err := generateX25519Keys()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to generate keys: "+err.Error())
		return
	}

	userStoreMu.Lock()
	user := &User{
		ID:           nextUserID,
		Username:     req.Username,
		PrivateKey:   keys.PrivateKey,
		PublicKey:    keys.PublicKey,
		TrafficLimit: req.TrafficLimit,
		ExpiryDate:   req.ExpiryDate,
		Status:       "active",
		CreatedAt:    time.Now(),
	}
	userStore[nextUserID] = user
	nextUserID++
	userStoreMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"user":       user,
		"privateKey": keys.PrivateKey,
		"publicKey":  keys.PublicKey,
	})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path
	idStr := r.PathValue("id")
	if idStr == "" {
		s.jsonError(w, http.StatusBadRequest, "User ID required")
		return
	}

	var id int
	fmt.Sscanf(idStr, "%d", &id)

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	userStoreMu.Lock()
	defer userStoreMu.Unlock()

	user, ok := userStore[id]
	if !ok {
		s.jsonError(w, http.StatusNotFound, "User not found")
		return
	}

	// Update fields
	if username, ok := req["username"].(string); ok {
		user.Username = username
	}
	if status, ok := req["status"].(string); ok {
		user.Status = status
	}

	s.jsonOK(w, map[string]interface{}{"success": true, "user": user})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	userStoreMu.Lock()
	delete(userStore, req.ID)
	userStoreMu.Unlock()

	s.jsonOK(w, map[string]interface{}{"success": true, "message": "User deleted"})
}

// ============================================
// Key Generation
// ============================================

type KeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

func generateX25519Keys() (*KeyPair, error) {
	// Generate random 32 bytes for private key
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return nil, err
	}

	// Derive public key using X25519
	publicBytes, err := curve25519.X25519(privateBytes, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privateBytes),
		PublicKey:  base64.StdEncoding.EncodeToString(publicBytes),
	}, nil
}

func (s *Server) handleGenerateKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := generateX25519Keys()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to generate keys")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"privateKey": keys.PrivateKey,
		"publicKey":  keys.PublicKey,
	})
}

// handleGenerateConnectionKey generates a connection key for client provisioning
func (s *Server) handleGenerateConnectionKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string `json:"username"`
		Name      string `json:"name"`
		Transport string `json:"transport"` // auto, tcp, udp (ws optional)
		Obfs      string `json:"obfs"`      // default, stealth, aggressive
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	// Set defaults
	if req.Name == "" {
		req.Name = "Whispera VPN"
	}
	if req.Transport == "" {
		req.Transport = "auto"
	}
	if req.Obfs == "" {
		req.Obfs = "stealth"
	}

	// Get server external IP
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	serverIP, err := network.DetectServerIP(ctx)
	if err != nil {
		serverIP = "0.0.0.0"
	}

	// Generate keys for this connection
	keys, err := generateX25519Keys()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to generate keys")
		return
	}

	// Detect ports from config
	udpPort := "443"
	tcpPort := "443"

	if s.registry != nil {
		if configMod, ok := s.registry.Get("config.provider"); ok {
			// type assertions to get config
			type ConfigProvider interface {
				GetConfig() *config.ServerConfig
			}
			if provider, ok := configMod.(ConfigProvider); ok {
				cfg := provider.GetConfig()
				if cfg != nil {
					if cfg.Transport.UDP.Enabled {
						_, port, err := net.SplitHostPort(cfg.Transport.UDP.ListenAddr)
						if err == nil {
							udpPort = port
						} else if strings.HasPrefix(cfg.Transport.UDP.ListenAddr, ":") {
							udpPort = cfg.Transport.UDP.ListenAddr[1:]
						}
					}
					if cfg.Transport.TCP.Enabled {
						_, port, err := net.SplitHostPort(cfg.Transport.TCP.ListenAddr)
						if err == nil {
							tcpPort = port
						} else if strings.HasPrefix(cfg.Transport.TCP.ListenAddr, ":") {
							tcpPort = cfg.Transport.TCP.ListenAddr[1:]
						}
					}
				}
			}
		}
	}

	// Build key data
	keyData := map[string]interface{}{
		"v":          1,
		"name":       req.Name,
		"server":     fmt.Sprintf("%s:%s", serverIP, udpPort), // UDP (primary)
		"server_tcp": fmt.Sprintf("%s:%s", serverIP, tcpPort), // TCP fallback
		"psk":        keys.PrivateKey,
		"pub":        keys.PublicKey,
		"obfs":       req.Obfs,
		"transport":  req.Transport,
		"enable_ml":  true,
		"enable_fte": true,
	}

	// Encode to JSON then Base64
	jsonData, err := json.Marshal(keyData)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to encode key")
		return
	}

	connectionKey := "whispera://" + base64.StdEncoding.EncodeToString(jsonData)

	s.jsonOK(w, map[string]interface{}{
		"success":   true,
		"key":       connectionKey,
		"name":      req.Name,
		"server":    serverIP,
		"transport": req.Transport,
		"obfs":      req.Obfs,
	})
}

// ============================================
// Sessions API (frontend format)
// ============================================

func (s *Server) handleGetSessionsAPI(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonOK(w, []interface{}{})
		return
	}

	module, ok := s.registry.Get("session.manager")
	if !ok {
		s.jsonOK(w, []interface{}{})
		return
	}

	sessionMgr, ok := module.(interfaces.SessionManager)
	if !ok {
		s.jsonOK(w, []interface{}{})
		return
	}

	sessions := sessionMgr.GetAllSessions()
	sessionList := make([]map[string]interface{}, 0, len(sessions))

	for _, sess := range sessions {
		sessionList = append(sessionList, map[string]interface{}{
			"id":           fmt.Sprintf("sess_%d", sess.ID()),
			"user":         "user_" + sess.ClientAddr().String(),
			"ip":           sess.ClientAddr().String(),
			"connected_at": sess.LastActivity().Format(time.RFC3339),
			"status":       "active",
			"traffic":      0,
		})
	}

	s.jsonOK(w, sessionList)
}

// ============================================
// Stats API (frontend format)
// ============================================

func (s *Server) handleGetStatsAPI(w http.ResponseWriter, r *http.Request) {
	globalStats := stats.GetGlobalStats()

	userStoreMu.RLock()
	totalUsers := len(userStore)
	userStoreMu.RUnlock()

	s.jsonOK(w, map[string]interface{}{
		"total_users":     totalUsers,
		"active_sessions": globalStats.ActiveUsers,
		"total_upload":    globalStats.TotalBytesTx,
		"total_download":  globalStats.TotalBytesRx,
		"traffic": map[string]interface{}{
			"upload":   globalStats.TotalBytesTx,
			"download": globalStats.TotalBytesRx,
		},
	})
}

func (s *Server) handleTrafficStatsAPI(w http.ResponseWriter, r *http.Request) {
	globalStats := stats.GetGlobalStats()

	s.jsonOK(w, map[string]interface{}{
		"total_download":   globalStats.TotalBytesRx,
		"total_upload":     globalStats.TotalBytesTx,
		"total_packets_rx": globalStats.TotalPacketsRx,
		"total_packets_tx": globalStats.TotalPacketsTx,
		"active_users":     globalStats.ActiveUsers,
		"uptime":           globalStats.Uptime,
		"uptime_seconds":   globalStats.UptimeSeconds,
		"history":          globalStats.History,
	})
}

// ============================================
// System Info API (frontend format)
// ============================================

func (s *Server) handleSystemInfoAPI(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	externalIP, _ := network.DetectServerIP(ctx)
	if externalIP == "" {
		externalIP = "unknown"
	}

	hostname, _ := os.Hostname()

	// Get server public key from config provider
	var serverPub string
	if s.registry != nil {
		if configMod, ok := s.registry.Get("config.provider"); ok {
			if provider, ok := configMod.(interface{ GetConfig() interface{} }); ok {
				// Try to get public key
				_ = provider
			}
		}
	}

	// Detect ports
	udpPort := "443"
	tcpPort := "443"
	wsPort := "8080"

	if s.registry != nil {
		if configMod, ok := s.registry.Get("config.provider"); ok {
			type ConfigProvider interface {
				GetConfig() *config.ServerConfig
			}
			if provider, ok := configMod.(ConfigProvider); ok {
				cfg := provider.GetConfig()
				if cfg != nil {
					// UDP
					if cfg.Transport.UDP.Enabled {
						_, port, err := net.SplitHostPort(cfg.Transport.UDP.ListenAddr)
						if err == nil {
							udpPort = port
						} else if strings.HasPrefix(cfg.Transport.UDP.ListenAddr, ":") {
							udpPort = cfg.Transport.UDP.ListenAddr[1:]
						}
					}
					// TCP
					if cfg.Transport.TCP.Enabled {
						_, port, err := net.SplitHostPort(cfg.Transport.TCP.ListenAddr)
						if err == nil {
							tcpPort = port
						} else if strings.HasPrefix(cfg.Transport.TCP.ListenAddr, ":") {
							tcpPort = cfg.Transport.TCP.ListenAddr[1:]
						}
					}
					// WS
					if cfg.API.Enabled {
						_, port, err := net.SplitHostPort(cfg.API.ListenAddr)
						if err == nil {
							wsPort = port
						} else if strings.HasPrefix(cfg.API.ListenAddr, ":") {
							wsPort = cfg.API.ListenAddr[1:]
						}
					}
				}
			}
		}
	}

	info := map[string]interface{}{
		"server_ip":       externalIP,
		"serverIP":        externalIP,
		"server_port":     udpPort, // Dynamic
		"tcp_port":        tcpPort, // Dynamic
		"ws_port":         wsPort,  // Dynamic
		"server_pub":      serverPub,
		"serverPublicKey": serverPub,
		"hostname":        hostname,
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"go_version":      runtime.Version(),
		"num_cpu":         runtime.NumCPU(),
		"num_goroutine":   runtime.NumGoroutine(),
		"version":         ModuleVersion,
	}

	if s.registry != nil {
		modules := s.registry.GetAll()
		info["module_count"] = len(modules)
	}

	s.jsonOK(w, info)
}

// HealthCheck returns health status
func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()
	status.Details["listen_addr"] = s.config.ListenAddr
	status.Details["enabled"] = s.config.Enabled

	s.mu.RLock()
	status.Details["routes_registered"] = len(s.handlers)
	s.mu.RUnlock()

	return status
}

// Factory creates API server modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
