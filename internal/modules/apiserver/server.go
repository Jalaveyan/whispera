package apiserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"whispera/internal/auth"
	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/db"
	"whispera/internal/modules/apiserver/handlers"
	asn_bypass "whispera/internal/modules/transport/asn_bypass"
	"whispera/internal/modules/bridgepool"
	"whispera/internal/modules/config"
	"whispera/internal/modules/dhcp"
	"whispera/internal/network"
	"whispera/internal/stats"

	"golang.org/x/crypto/curve25519"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "api.server"
	ModuleVersion = "1.0.0"
)

type Config struct {
	Enabled        bool
	ListenAddr     string
	AuthToken      string
	WebRoot        string
	EnableCORS     bool
	AllowedOrigins []string
	TLSCert        string
	TLSKey         string
	AdminUsername  string
	AdminPassword  string
	LoginRateLimit int
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:    true,
		ListenAddr: ":8081",
		EnableCORS: true,
	}
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8081"
	}
	return nil
}

type Server struct {
	*base.Module
	config *Config
	server *http.Server
	mux    *http.ServeMux

	registry registry.Registry

	mu       sync.RWMutex
	handlers map[string]http.HandlerFunc

	mfaManager    *auth.MFAManager
	bridgePool    *bridgepool.Registry
	bridgeHandler *bridgepool.APIHandler

	loginAttempts   map[string][]time.Time
	loginAttemptsMu sync.Mutex

	sessionToken string

	cpuLoad    float64
	cpuMu      sync.Mutex
	cpuPrev    [2]uint64
}

func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll("/etc/whispera", 0755); err != nil {
		log.Printf("[API] Warning: failed to create /etc/whispera: %v", err)
	}

	bridgeReg := bridgepool.NewRegistry("/etc/whispera/bridges.json")

	loadUsers()
	loadSubscriptions()

	sessionToken := loadOrCreateSessionToken()

	s := &Server{
		Module:        base.NewModule(ModuleName, ModuleVersion, nil),
		config:        cfg,
		mux:           http.NewServeMux(),
		handlers:      make(map[string]http.HandlerFunc),
		mfaManager:    auth.NewMFAManager(),
		bridgePool:    bridgeReg,
		bridgeHandler: bridgepool.NewAPIHandler(bridgeReg),
		loginAttempts: make(map[string][]time.Time),
		sessionToken:  sessionToken,
	}

	s.registerDefaultRoutes()
	go s.cpuSampler()

	s.registerUserV2Routes()

	return s, nil
}

func (s *Server) registerDefaultRoutes() {
	s.Handle("POST /api/login", s.handleLogin)

	s.Handle("GET /api/v1/health", s.handleHealth)
	s.Handle("GET /api/v1/status", s.handleStatus)
	s.Handle("GET /api/v1/modules", s.handleModules)
	s.Handle("GET /api/v1/config", s.handleGetConfig)

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

	s.Handle("GET /api/v1/dhcp/status", s.handleDHCPStatus)
	s.Handle("GET /api/v1/dhcp/leases", s.handleDHCPLeases)
	s.Handle("DELETE /api/v1/dhcp/lease", s.handleDHCPRelease)
	s.Handle("GET /api/users", s.handleGetUsers)
	s.Handle("POST /api/users/add", s.handleAddUser)
	s.Handle("PUT /api/users/{id}", s.handleUpdateUser)
	s.Handle("POST /api/users/delete", s.handleDeleteUser)

	s.Handle("GET /api/routing/rules", s.handleGetRoutingRules)
	s.Handle("POST /api/routing/rules/add", s.handleAddRoutingRule)
	s.Handle("POST /api/routing/rules/delete", s.handleDeleteRoutingRule)
	s.Handle("GET /api/outbounds", s.handleGetOutbounds)
	s.Handle("POST /api/outbounds/add", s.handleAddOutbound)
	s.Handle("POST /api/outbounds/delete", s.handleDeleteOutbound)

	s.Handle("GET /api/inbounds", s.handleGetInbounds)
	s.Handle("GET /api/inbounds/pubkey", s.handleGetInboundPublicKey)
	s.Handle("POST /api/inbounds/add", s.handleAddInbound)
	s.Handle("POST /api/inbounds/update", s.handleUpdateInbound)
	s.Handle("POST /api/inbounds/delete", s.handleDeleteInbound)

	s.Handle("POST /api/keys/generate", s.handleGenerateKeys)
	s.Handle("POST /api/keys/connection", s.handleGenerateConnectionKey)
	s.Handle("POST /api/keys/transport", s.handleGenerateTransportKeys)
	s.Handle("POST /api/keys/multi-transport", s.handleGenerateMultiTransportKeys)

	s.Handle("GET /api/subscriptions", s.handleGetSubscriptions)
	s.Handle("POST /api/subscriptions/add", s.handleAddSubscription)
	s.Handle("POST /api/subscriptions/update", s.handleUpdateSubscription)
	s.Handle("POST /api/subscriptions/delete", s.handleDeleteSubscription)
	s.Handle("GET /sub/{token}", s.handleServeSubscription)

	s.Handle("GET /api/adblock/stats", s.handleAdblockStats)
	s.Handle("GET /api/adblock/rules", s.handleAdblockRules)
	s.Handle("POST /api/adblock/rules/add", s.handleAdblockAddRule)
	s.Handle("POST /api/adblock/rules/delete", s.handleAdblockDeleteRule)
	s.Handle("POST /api/adblock/settings", s.handleAdblockSettings)
	s.Handle("POST /api/v1/config/renew-cert", s.handleRenewCert)

	s.Handle("GET /api/sessions", s.handleGetSessionsAPI)
	s.Handle("POST /api/sessions/{id}/kill", s.handleKillSessionAPI)
	s.Handle("GET /api/stats", s.handleGetStatsAPI)
	s.Handle("GET /api/stats/traffic", s.handleTrafficStatsAPI)
	s.Handle("GET /api/stats/user/{id}", s.handleGetUserTrafficAPI)

	s.Handle("GET /api/system/info", s.handleSystemInfoAPI)
	s.Handle("POST /api/admin/update", s.handleAdminUpdate)
	s.Handle("GET /api/logs", s.handleGetLogsAPI)

	s.Handle("GET /api/bridge-list", s.bridgeHandler.HandleGetBridges)
	s.Handle("GET /api/bridge-admin", s.bridgeHandler.HandleGetBridgesAdmin)
	s.Handle("POST /api/bridge-add", s.bridgeHandler.HandleAddBridge)
	s.Handle("POST /api/bridge-delete", s.bridgeHandler.HandleDeleteBridge)
	s.Handle("POST /api/bridge-register", s.bridgeHandler.HandleRegisterBridge)
	s.Handle("POST /api/bridge-health", s.bridgeHandler.HandleBridgeHealth)
	s.Handle("GET /api/bridge-token", s.bridgeHandler.HandleGetRegistrationToken)
	s.Handle("POST /api/bridge-token-regenerate", s.bridgeHandler.HandleRegenerateToken)
	s.Handle("GET /api/bridge-cloudinit", s.bridgeHandler.HandleGetCloudInit)
}

func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if apiCfg, ok := cfg.(*Config); ok {
		s.config = apiCfg
	}

	return nil
}

func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	if !s.config.Enabled {
		s.SetHealthy(true, "API server disabled")
		return nil
	}

	handler := s.buildHandler()

	s.server = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to bind API server to %s: %v", s.config.ListenAddr, err)
		fmt.Printf("[ERROR] %s\n", errMsg)
		s.SetHealthy(false, errMsg)
		return fmt.Errorf("failed to bind API server to %s: %w", s.config.ListenAddr, err)
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

func (s *Server) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)
	}

	s.PublishEvent(events.EventTypeModuleStopped, nil)
	return s.Module.Stop()
}

func (s *Server) SetRegistry(reg registry.Registry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registry = reg
}

func (s *Server) Handle(pattern string, handler http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[pattern] = handler
}

type responseCapture struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *responseCapture) WriteHeader(code int) {
	r.status = code
	if !r.wrote {
		r.ResponseWriter.WriteHeader(code)
		r.wrote = true
	}
}

func (r *responseCapture) Write(b []byte) (int, error) {
	if !r.wrote {
		r.wrote = true
	}
	return r.ResponseWriter.Write(b)
}

func (s *Server) buildHandler() http.Handler {
	var rootHandler http.Handler = s.mux
	if s.config.WebRoot != "" {
		fs := http.FileServer(http.Dir(s.config.WebRoot))
		rootHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.mux.ServeHTTP(w, r)
				return
			}
			fs.ServeHTTP(w, r)
		})
	} else {
		rootHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.mux.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == "/" || r.URL.Path == "" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"name":   "Whispera API",
					"status": "running",
					"panel":  "http://" + func() string { if i := strings.LastIndex(r.Host, ":"); i >= 0 { return r.Host[:i] }; return r.Host }() + ":3000",
					"api":    "/api/v1/health",
				})
				return
			}
			s.mux.ServeHTTP(w, r)
		})
	}
	s.mu.RLock()
	for pattern, handler := range s.handlers {
		s.mux.HandleFunc(pattern, handler)
	}
	s.mu.RUnlock()

	var handler http.Handler = rootHandler

	handler = s.authMiddleware(handler)

	if s.config.EnableCORS {
		handler = s.corsMiddleware(handler)
	}

	handler = s.loggingMiddleware(handler)

	handler = s.recoveryMiddleware(handler)

	return handler
}

func (s *Server) methodFilter(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		allowedOrigin := ""
		if len(s.config.AllowedOrigins) > 0 {
			for _, allowed := range s.config.AllowedOrigins {
				if allowed == origin || allowed == "*" {
					allowedOrigin = origin
					break
				}
			}
		} else {
			if origin != "" {
				host := r.Host
				if strings.Contains(origin, host) {
					allowedOrigin = origin
				}
			}
		}

		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == "/api/login" ||
			r.URL.Path == "/api/v2/auth/login" ||
			strings.HasSuffix(r.URL.Path, "/health") {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := auth[len(prefix):]
		if token != s.sessionToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.UpdateActivity()
		_ = start
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
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

type jsonResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func (s *Server) jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(jsonResponse{Success: false, Error: message})
}

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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIP(r)
	if !s.checkLoginRateLimit(clientIP) {
		log.Printf("[API] Rate limit exceeded for IP: %s", clientIP)
		s.jsonError(w, http.StatusTooManyRequests, "Too many login attempts. Please wait 1 minute.")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if database := db.Global(); database != nil {
		user, err := database.AuthenticateUser(r.Context(), req.Username, req.Password)
		if err == nil && user.IsAdmin {
			s.clearLoginAttempts(clientIP)
			log.Printf("[API] Successful DB login from IP: %s (user: %s)", clientIP, req.Username)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"token":   s.sessionToken,
				"user": map[string]string{
					"username": req.Username,
					"role":     "admin",
					"id":       user.ID.String(),
				},
			})
			return
		}
	}

	expectedUsername := s.config.AdminUsername
	expectedPassword := s.config.AdminPassword

	if expectedUsername == "" {
		expectedUsername = "admin"
		log.Printf("[API] ⚠ WARNING: No admin_username configured, falling back to 'admin'")
	}

	if expectedPassword != "" {
		usernameMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(expectedUsername)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(req.Password), []byte(expectedPassword)) == 1

		if usernameMatch && passwordMatch {
			s.clearLoginAttempts(clientIP)

			log.Printf("[API] Successful login from IP: %s", clientIP)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"token":   s.sessionToken,
				"user": map[string]string{
					"username": req.Username,
					"role":     "admin",
				},
			})
			return
		}
	}

	log.Printf("[API] Failed login attempt from IP: %s (user: %s)", clientIP, req.Username)
	s.jsonError(w, http.StatusUnauthorized, "Invalid username or password")
}

func (s *Server) checkLoginRateLimit(ip string) bool {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()

	limit := s.config.LoginRateLimit
	if limit <= 0 {
		limit = 5
	}

	now := time.Now()
	windowStart := now.Add(-1 * time.Minute)

	attempts := s.loginAttempts[ip]
	var recentAttempts []time.Time
	for _, t := range attempts {
		if t.After(windowStart) {
			recentAttempts = append(recentAttempts, t)
		}
	}

	if len(recentAttempts) >= limit {
		return false
	}

	s.loginAttempts[ip] = append(recentAttempts, now)
	return true
}

func (s *Server) clearLoginAttempts(ip string) {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()
	delete(s.loginAttempts, ip)
}

func (s *Server) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
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
		if req.Server.Port > 0 {
			cfg.Transport.UDP.ListenAddr = fmt.Sprintf(":%d", req.Server.Port)
			cfg.Server.ListenAddr = cfg.Transport.UDP.ListenAddr
		}
		if req.Server.TCPPort > 0 {
			cfg.Transport.TCP.ListenAddr = fmt.Sprintf(":%d", req.Server.TCPPort)
		}
		if req.Server.WSPort > 0 {
			cfg.Transport.WebSocket.ListenAddr = fmt.Sprintf(":%d", req.Server.WSPort)
		}
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

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	externalIP, err := network.DetectServerIP(ctx)
	if err != nil {
		externalIP = "unknown"
	}

	info := map[string]interface{}{
		"server_ip":     externalIP,
		"serverIP":      externalIP,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"num_cpu":       runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
	}

	if s.config != nil && s.config.ListenAddr != "" {
		info["api_addr"] = s.config.ListenAddr
	}
	if s.registry != nil {
		modules := s.registry.GetAll()
		info["module_count"] = len(modules)
	}

	s.jsonOK(w, info)
}

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

func (s *Server) handleUserStats(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	if userID != "" {
		userStats := stats.GetUserStats(userID)
		if userStats == nil {
			s.jsonError(w, http.StatusNotFound, "User not found")
			return
		}
		s.jsonOK(w, userStats)
		return
	}

	allStats := stats.GetAllUserStats()
	s.jsonOK(w, map[string]interface{}{
		"count": len(allStats),
		"users": allStats,
	})
}

var globalDHCPManager *dhcp.Manager

func SetDHCPManager(m *dhcp.Manager) {
	globalDHCPManager = m
}

func (s *Server) handleDHCPStatus(w http.ResponseWriter, r *http.Request) {
	if globalDHCPManager == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "DHCP not initialized")
		return
	}

	s.jsonOK(w, globalDHCPManager.GetStats())
}

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

type User struct {
	ID            int       `json:"id"`
	Username      string    `json:"username"`
	PrivateKey    string    `json:"privateKey,omitempty"`
	PublicKey     string    `json:"publicKey,omitempty"`
	ConnectionURI string    `json:"connectionURI,omitempty"`
	Upload        int64     `json:"upload"`
	Download      int64     `json:"download"`
	TrafficLimit  int64     `json:"trafficLimit"`
	ExpiryDate    string    `json:"expiryDate,omitempty"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"createdAt"`

	ObfsProfile       string `json:"obfsProfile,omitempty"`
	MarionetteProfile string `json:"marionetteProfile,omitempty"`
	RussianService    string `json:"russianService,omitempty"`
}

const userDataFile = "/etc/whispera/users.json"

var (
	userStore   = make(map[int]*User)
	userStoreMu sync.RWMutex
	nextUserID  = 1
)

type userPersist struct {
	Users      []*User `json:"users"`
	NextUserID int     `json:"next_user_id"`
}

type RegisteredUser struct {
	UserID     string
	PrivateKey string
}

func GetRegisteredUsers() []RegisteredUser {
	userStoreMu.RLock()
	defer userStoreMu.RUnlock()
	result := make([]RegisteredUser, 0, len(userStore))
	for _, u := range userStore {
		if u.PrivateKey != "" && u.Status != "disabled" {
			result = append(result, RegisteredUser{UserID: u.Username, PrivateKey: u.PrivateKey})
		}
	}
	return result
}

const sessionTokenFile = "/etc/whispera/session.token"

func loadOrCreateSessionToken() string {
	data, err := os.ReadFile(sessionTokenFile)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			log.Println("[API] Loaded existing session token")
			return token
		}
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Printf("[API] Failed to generate session token: %v", err)
		return base64.StdEncoding.EncodeToString([]byte("fallback-token"))
	}
	token := base64.StdEncoding.EncodeToString(tokenBytes)
	if err := os.WriteFile(sessionTokenFile, []byte(token), 0600); err != nil {
		log.Printf("[API] Warning: failed to save session token: %v", err)
	} else {
		log.Println("[API] Generated and saved new session token")
	}
	return token
}

func saveUsers() {
	userStoreMu.RLock()
	list := make([]*User, 0, len(userStore))
	for _, u := range userStore {
		list = append(list, u)
	}
	nid := nextUserID
	userStoreMu.RUnlock()

	data, err := json.Marshal(userPersist{Users: list, NextUserID: nid})
	if err != nil {
		log.Printf("[API] Failed to marshal users: %v", err)
		return
	}
	if err := os.WriteFile(userDataFile, data, 0600); err != nil {
		log.Printf("[API] Failed to save users: %v", err)
	}
}

func loadUsers() {
	data, err := os.ReadFile(userDataFile)
	if err != nil {
		return
	}
	var p userPersist
	if err := json.Unmarshal(data, &p); err != nil {
		log.Printf("[API] Failed to load users: %v", err)
		return
	}
	userStoreMu.Lock()
	for _, u := range p.Users {
		userStore[u.ID] = u
	}
	if p.NextUserID > nextUserID {
		nextUserID = p.NextUserID
	}
	userStoreMu.Unlock()
	log.Printf("[API] Loaded %d users from %s", len(p.Users), userDataFile)
}

func (s *Server) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	userStoreMu.RLock()
	defer userStoreMu.RUnlock()

	users := make([]*User, 0, len(userStore))
	for _, u := range userStore {
		userStats := stats.GetUserStats(u.Username)
		if userStats != nil {
			u.Upload = userStats.BytesTx
			u.Download = userStats.BytesRx
		}
		users = append(users, u)
	}

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"users":   users,
	})
}

func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username          string `json:"username"`
		TrafficLimit      int64  `json:"trafficLimit"`
		ExpiryDate        string `json:"expiryDate"`
		ObfsProfile       string `json:"obfsProfile"`
		MarionetteProfile string `json:"marionetteProfile"`
		RussianService    string `json:"russianService"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Username == "" {
		s.jsonError(w, http.StatusBadRequest, "Username is required")
		return
	}

	keys, err := generateX25519Keys()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to generate keys: "+err.Error())
		return
	}

	userStoreMu.Lock()
	for _, u := range userStore {
		if u.Username == req.Username {
			userStoreMu.Unlock()
			s.jsonError(w, http.StatusConflict, "User already exists")
			return
		}
	}
	user := &User{
		ID:                nextUserID,
		Username:          req.Username,
		PrivateKey:        keys.PrivateKey,
		PublicKey:         keys.PublicKey,
		TrafficLimit:      req.TrafficLimit,
		ExpiryDate:        req.ExpiryDate,
		Status:            "active",
		CreatedAt:         time.Now(),
		ObfsProfile:       req.ObfsProfile,
		MarionetteProfile: req.MarionetteProfile,
		RussianService:    req.RussianService,
	}
	userStore[nextUserID] = user
	nextUserID++
	userStoreMu.Unlock()
	go saveUsers()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"user":       user,
		"privateKey": keys.PrivateKey,
		"publicKey":  keys.PublicKey,
	})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
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

	if username, ok := req["username"].(string); ok {
		user.Username = username
	}
	if status, ok := req["status"].(string); ok {
		user.Status = status
	}
	if uri, ok := req["connectionURI"].(string); ok {
		user.ConnectionURI = uri
	}

	go saveUsers()
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
	go saveUsers()

	s.jsonOK(w, map[string]interface{}{"success": true, "message": "User deleted"})
}

type KeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

func generateX25519Keys() (*KeyPair, error) {
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return nil, err
	}
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

func randomRussianSNI() string {
	sni, _ := asn_bypass.PickRandomSNI()
	if sni == "" {
		return "vk.com"
	}
	return sni
}

func (s *Server) handleGenerateConnectionKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username        string                 `json:"username"`
		Name            string                 `json:"name"`
		Transport       string                 `json:"transport"`
		Obfs            string                 `json:"obfs"`
		RussianService  string                 `json:"russianService"`
		PSK             string                 `json:"psk"`
		SNI             string                 `json:"sni"`
		PhantomEnabled  bool                   `json:"phantom"`
		ASNBypass       bool                   `json:"asn"`
		TLSFingerprint  string                 `json:"tls"`
		Port            int                    `json:"port"`
		TransportConfig map[string]interface{} `json:"transportConfig"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if req.Name == "" {
		req.Name = "Whispera VPN"
	}
	if req.Transport == "" {
		req.Transport = "tcp"
	}
	if req.Obfs == "" {
		req.Obfs = "stealth"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	serverIP, err := network.DetectServerIP(ctx)
	if err != nil {
		serverIP = "0.0.0.0"
	}

	userPrivKey := req.PSK
	userPubKey := ""
	if userPrivKey == "" {
		keys, err := generateX25519Keys()
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Failed to generate keys")
			return
		}
		userPrivKey = keys.PrivateKey
		userPubKey = keys.PublicKey
	} else {
		userPubKey = derivePublicKeyB64(userPrivKey)
	}

	serverAddr := fmt.Sprintf("%s:443", serverIP)
	serverPubKey := ""
	phantomEnabled := req.PhantomEnabled
	sni := req.SNI

	if s.registry != nil {
		if configMod, ok := s.registry.Get("config.provider"); ok {
			type ConfigProvider interface {
				GetConfig() *config.ServerConfig
			}
			if provider, ok := configMod.(ConfigProvider); ok {
				cfg := provider.GetConfig()
				if cfg != nil {
					matchTransports := map[string]bool{req.Transport: true}
					if strings.Contains(req.Transport, ",") {
						matchTransports = map[string]bool{}
						for _, p := range strings.Split(req.Transport, ",") {
							matchTransports[strings.TrimSpace(p)] = true
						}
					}
					for _, inbound := range cfg.Inbounds {
						network := inbound.StreamSettings.Network
						if network == "" {
							network = "tcp"
						}
						if matchTransports[network] {
							port := fmt.Sprintf("%d", inbound.Port)
							serverAddr = fmt.Sprintf("%s:%s", serverIP, port)
							if pk := inbound.StreamSettings.Phantom.PrivateKey; pk != "" {
								serverPubKey = derivePublicKeyB64(pk)
								phantomEnabled = true
							}
							break
						}
					}
					if serverPubKey == "" && cfg.Phantom.PrivateKey != "" {
						serverPubKey = derivePublicKeyB64(cfg.Phantom.PrivateKey)
					}
					if serverPubKey == "" && cfg.Server.PrivateKey != "" {
						serverPubKey = derivePublicKeyB64(cfg.Server.PrivateKey)
					}





					if serverAddr == fmt.Sprintf("%s:443", serverIP) {
						if req.Transport == "udp" && cfg.Transport.UDP.Enabled {
							_, port, _ := net.SplitHostPort(cfg.Transport.UDP.ListenAddr)
							if port != "" {
								serverAddr = fmt.Sprintf("%s:%s", serverIP, port)
							}
						} else if cfg.Transport.TCP.Enabled {
							_, port, _ := net.SplitHostPort(cfg.Transport.TCP.ListenAddr)
							if port != "" {
								serverAddr = fmt.Sprintf("%s:%s", serverIP, port)
							}
						}
					}
				}
			}
		}
	}

	if req.Port > 0 && req.Port < 65536 {
		serverAddr = fmt.Sprintf("%s:%d", serverIP, req.Port)
		proto := "tcp"
		if req.Transport == "udp" || req.Transport == "tuic" {
			proto = "udp"
		}
		go func() {
			portProto := fmt.Sprintf("%d/%s", req.Port, proto)
			if err := exec.Command("ufw", "allow", portProto).Run(); err != nil {
				exec.Command("iptables", "-I", "INPUT", "-p", proto,
					"--dport", fmt.Sprintf("%d", req.Port), "-j", "ACCEPT").Run()
			}
		}()
	}

	params := make([]string, 0, 9)
	if serverPubKey != "" {
		params = append(params, "pub="+serverPubKey)
	}
	if userPrivKey != "" {
		params = append(params, "psk="+userPrivKey)
	}
	if req.Transport != "" && req.Transport != "auto" {
		params = append(params, "transport="+req.Transport)
	}
	phantomEnabled = true
	if sni == "" {
		sni = randomRussianSNI()
	}
	params = append(params, "phantom=1")
	params = append(params, "sni="+sni)
	params = append(params, "asn=1")
	tlsFP := req.TLSFingerprint
	if tlsFP == "" {
		tlsFP = "chrome"
	}
	params = append(params, "tls="+tlsFP)
	if req.RussianService != "" {
		params = append(params, "russian="+req.RussianService)
	}
	if len(req.TransportConfig) > 0 {
		cfgJSON, err := json.Marshal(req.TransportConfig)
		if err == nil {
			params = append(params, "cfg="+base64.RawURLEncoding.EncodeToString(cfgJSON))
		}
	}

	connectionKey := fmt.Sprintf("whispera://%s?%s", serverAddr, strings.Join(params, "&"))

	s.jsonOK(w, map[string]interface{}{
		"success":        true,
		"key":            connectionKey,
		"psk":            userPrivKey,
		"pub":            userPubKey,
		"server":         serverAddr,
		"transport":      req.Transport,
		"phantom":        phantomEnabled,
		"sni":            sni,
		"russianService": req.RussianService,
	})
}

func (s *Server) handleGetSessionsAPI(w http.ResponseWriter, r *http.Request) {
	allUserStats := stats.GetAllUserStats()
	cutoff := time.Now().Add(-5 * time.Minute)

	sessionList := make([]map[string]interface{}, 0)
	for _, us := range allUserStats {
		activeConns := stats.ActiveConnCount(us.UserID)
		if activeConns == 0 && us.SessionCount <= 0 && !us.LastActivity.After(cutoff) {
			continue
		}
		sessionList = append(sessionList, map[string]interface{}{
			"id":              us.UserID,
			"user_id":         us.UserID,
			"client_ip":       us.AssignedIP,
			"connected_at":    us.LastActivity.Format(time.RFC3339),
			"bytes_in":        us.BytesRx,
			"bytes_out":       us.BytesTx,
			"active_conns":    activeConns,
		})
	}

	s.jsonOK(w, map[string]interface{}{
		"sessions": sessionList,
		"count":    len(sessionList),
	})
}

func (s *Server) handleKillSessionAPI(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		s.jsonError(w, http.StatusBadRequest, "session id required")
		return
	}

	closed := stats.KillUserConns(userID)

	if s.registry != nil {
		if mod, ok := s.registry.Get("session.manager"); ok {
			if sessionMgr, ok := mod.(interfaces.SessionManager); ok {
				for _, sess := range sessionMgr.GetAllSessions() {
					if uid, _ := sess.GetMetadata("user_id").(string); uid == userID {
						sessionMgr.RemoveSession(sess.ID())
					}
				}
			}
		}
	}

	s.jsonOK(w, map[string]interface{}{"success": true, "connections_closed": closed})
}

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

func (s *Server) handleGetUserTrafficAPI(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		s.jsonError(w, http.StatusBadRequest, "User ID required")
		return
	}

	var id int
	var username string
	if _, err := fmt.Sscanf(userID, "%d", &id); err == nil {
		userStoreMu.RLock()
		if user, ok := userStore[id]; ok {
			username = user.Username
		}
		userStoreMu.RUnlock()
	}

	if username == "" {
		username = userID
	}

	userStats := stats.GetUserStats(username)
	if userStats == nil {
		s.jsonOK(w, map[string]interface{}{
			"upload":   0,
			"download": 0,
		})
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"upload":   userStats.BytesTx,
		"download": userStats.BytesRx,
	})
}

func (s *Server) getRouter() (interfaces.Router, error) {
	if s.registry == nil {
		return nil, fmt.Errorf("registry not available")
	}
	module, ok := s.registry.Get("routing.engine")
	if !ok {
		return nil, fmt.Errorf("router module not found")
	}
	router, ok := module.(interfaces.Router)
	if !ok {
		return nil, fmt.Errorf("invalid router module type")
	}
	return router, nil
}

func (s *Server) handleGetRoutingRules(w http.ResponseWriter, r *http.Request) {
	router, err := s.getRouter()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	rawRules := router.GetRules()

	type FrontendRule struct {
		ID        string `json:"id"`
		Type      string `json:"type"`
		Condition string `json:"condition"`
		Outbound  string `json:"outbound"`
		Priority  int    `json:"priority"`
		Enabled   bool   `json:"enabled"`
	}

	frontendRules := make([]FrontendRule, 0, len(rawRules))
	for _, r := range rawRules {
		fr := FrontendRule{
			ID:       r.ID,
			Priority: r.Priority,
			Enabled:  true,
		}

		switch r.Destination.Type {
		case interfaces.DestinationDirect:
			fr.Outbound = "direct"
		case interfaces.DestinationProxy:
			fr.Outbound = "proxy"
		case interfaces.DestinationBlock:
			fr.Outbound = "block"
		default:
			fr.Outbound = string(r.Destination.Type)
		}

		if len(r.Conditions) > 0 {
			c := r.Conditions[0]
			fr.Type = c.Field
			if c.Operator == "eq" {
				fr.Condition = fmt.Sprintf("%v", c.Value)
			} else {
				fr.Condition = fmt.Sprintf("%v", c.Value)
			}
		}

		frontendRules = append(frontendRules, fr)
	}

	s.jsonOK(w, map[string]interface{}{
		"count": len(frontendRules),
		"rules": frontendRules,
	})
}

func (s *Server) handleAddRoutingRule(w http.ResponseWriter, r *http.Request) {
	router, err := s.getRouter()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	var req struct {
		Type      string `json:"type"`
		Condition string `json:"condition"`
		Outbound  string `json:"outbound"`
		Priority  int    `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	rule := interfaces.RoutingRule{
		ID:       fmt.Sprintf("rule_%d", time.Now().UnixNano()),
		Priority: req.Priority,
		Conditions: []interfaces.RuleCondition{
			{
				Field:    req.Type,
				Operator: "eq",
				Value:    req.Condition,
			},
		},
	}

	if req.Type == "domain" {
		rule.Conditions[0].Operator = "contains"
	} else if req.Type == "ip" {
		if strings.Contains(req.Condition, "/") {
			rule.Conditions[0].Operator = "cidr"
		} else {
			rule.Conditions[0].Operator = "eq"
		}
	}

	switch req.Outbound {
	case "direct":
		rule.Destination = interfaces.Destination{Type: interfaces.DestinationDirect}
	case "proxy":
		rule.Destination = interfaces.Destination{Type: interfaces.DestinationProxy}
	case "block":
		rule.Destination = interfaces.Destination{Type: interfaces.DestinationBlock}
	default:
		rule.Destination = interfaces.Destination{Type: interfaces.DestinationDirect}
	}

	if err := router.AddRule(rule); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"rule":    rule,
	})
}

func (s *Server) handleDeleteRoutingRule(w http.ResponseWriter, r *http.Request) {
	router, err := s.getRouter()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	var req struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if err := router.RemoveRule(req.ID); err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{"success": true})
}

func (s *Server) getConfigProvider() (interface{}, error) {
	if s.registry == nil {
		return nil, fmt.Errorf("registry not available")
	}
	module, ok := s.registry.Get("config.provider")
	if !ok {
		return nil, fmt.Errorf("config provider not found")
	}
	return module, nil
}

func (s *Server) handleGetOutbounds(w http.ResponseWriter, r *http.Request) {
	module, err := s.getConfigProvider()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	type ConfigProvider interface {
		GetConfig() *config.ServerConfig
	}

	provider, ok := module.(ConfigProvider)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "invalid config provider")
		return
	}

	cfg := provider.GetConfig()

	s.jsonOK(w, map[string]interface{}{
		"count":     len(cfg.Outbounds),
		"outbounds": cfg.Outbounds,
	})
}

func (s *Server) handleAddOutbound(w http.ResponseWriter, r *http.Request) {
	module, err := s.getConfigProvider()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	type ConfigUpdater interface {
		Update(func(*config.ServerConfig)) error
	}

	provider, ok := module.(ConfigUpdater)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "config provider does not support updates")
		return
	}

	var req config.OutboundConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if req.Tag == "" {
		req.Tag = fmt.Sprintf("outbound_%d", time.Now().UnixNano())
	}

	err = provider.Update(func(cfg *config.ServerConfig) {
		for _, out := range cfg.Outbounds {
			if out.Tag == req.Tag {
				return
			}
		}
		cfg.Outbounds = append(cfg.Outbounds, req)
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to save config: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"success":  true,
		"outbound": req,
	})
}

func (s *Server) handleDeleteOutbound(w http.ResponseWriter, r *http.Request) {
	module, err := s.getConfigProvider()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	type ConfigUpdater interface {
		Update(func(*config.ServerConfig)) error
	}

	provider, ok := module.(ConfigUpdater)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "config provider does not support updates")
		return
	}

	var req struct {
		Tag string `json:"tag"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	err = provider.Update(func(cfg *config.ServerConfig) {
		newOutbounds := make([]config.OutboundConfig, 0, len(cfg.Outbounds))
		for _, out := range cfg.Outbounds {
			if out.Tag != req.Tag {
				newOutbounds = append(newOutbounds, out)
			}
		}
		cfg.Outbounds = newOutbounds
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to save config: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{"success": true})
}

func (s *Server) handleSystemInfoAPI(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	externalIP, _ := network.DetectServerIP(ctx)
	if externalIP == "" {
		externalIP = "unknown"
	}

	hostname, _ := os.Hostname()

	var serverPub string
	if s.registry != nil {
		if configMod, ok := s.registry.Get("config.provider"); ok {
			if provider, ok := configMod.(interface{ GetConfig() interface{} }); ok {
				_ = provider
			}
		}
	}

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

	globalStats := stats.GetGlobalStats()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memMiB := memStats.Sys / 1024 / 1024

	info := map[string]interface{}{
		"server_ip":       externalIP,
		"serverIP":        externalIP,
		"server_port":     udpPort,
		"tcp_port":        tcpPort,
		"ws_port":         wsPort,
		"server_pub":      serverPub,
		"serverPublicKey": serverPub,
		"hostname":        hostname,
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"go_version":      runtime.Version(),
		"num_cpu":         runtime.NumCPU(),
		"num_goroutine":   runtime.NumGoroutine(),
		"version":         ModuleVersion,
		"uptime":          globalStats.UptimeSeconds,
		"uptime_str":      globalStats.Uptime,
		"memory_usage":    fmt.Sprintf("%d MiB", memMiB),
		"memory_bytes":    memStats.Sys,
		"cpu_load":        func() float64 { s.cpuMu.Lock(); v := s.cpuLoad; s.cpuMu.Unlock(); return v }(),
	}

	if s.registry != nil {
		modules := s.registry.GetAll()
		info["module_count"] = len(modules)
	}

	if s.config.TLSCert != "" {
		if certPEM, err := os.ReadFile(s.config.TLSCert); err == nil {
			if block, _ := pem.Decode(certPEM); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					info["ssl_expiry"] = cert.NotAfter.Format("2006-01-02")
					info["ssl_status"] = "active"
				}
			}
		}
	}

	s.jsonOK(w, info)
}

func (s *Server) handleAdminUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" {
		s.jsonError(w, http.StatusBadRequest, "username required")
		return
	}

	module, ok := s.registry.Get("config.provider")
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "config provider not found")
		return
	}
	cfgProvider, ok := module.(*config.Provider)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "invalid config provider")
		return
	}

	if err := cfgProvider.Update(func(cfg *config.ServerConfig) {
		cfg.API.AdminUsername = req.Username
		if req.Password != "" {
			cfg.API.AdminPassword = req.Password
		}
	}); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
		return
	}

	s.config.AdminUsername = req.Username
	if req.Password != "" {
		s.config.AdminPassword = req.Password
	}

	s.jsonOK(w, map[string]interface{}{"success": true})
}

func (s *Server) handleGetLogsAPI(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 200
	if limitStr != "" {
		if n, err := fmt.Sscanf(limitStr, "%d", &limit); n != 1 || err != nil || limit <= 0 || limit > 2000 {
			limit = 200
		}
	}

	out, err := exec.Command("journalctl", "-u", "whispera", "-n", fmt.Sprintf("%d", limit), "--no-pager", "--output=short-iso").Output()
	if err == nil && len(out) > 0 {
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		s.jsonOK(w, map[string]interface{}{"success": true, "logs": lines, "source": "journalctl"})
		return
	}

	logPaths := []string{"/var/log/whispera/whispera.log", "/var/log/whispera.log", "/tmp/whispera.log"}
	for _, path := range logPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(all) > limit {
			all = all[len(all)-limit:]
		}
		s.jsonOK(w, map[string]interface{}{"success": true, "logs": all, "source": path})
		return
	}

	s.jsonOK(w, map[string]interface{}{"success": true, "logs": []string{}, "source": "none"})
}

func readProcStatCPU() (idle, total uint64, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.SplitN(string(data), "\n", 2) {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		var name string
		var fields [10]uint64
		fmt.Sscanf(line, "%s %d %d %d %d %d %d %d %d %d %d",
			&name,
			&fields[0], &fields[1], &fields[2], &fields[3],
			&fields[4], &fields[5], &fields[6], &fields[7],
			&fields[8], &fields[9],
		)
		idle = fields[3] + fields[4]
		for _, v := range fields {
			total += v
		}
		return idle, total, nil
	}
	return 0, 0, fmt.Errorf("cpu line not found")
}

func (s *Server) cpuSampler() {
	idle0, total0, err := readProcStatCPU()
	if err != nil {
		return
	}
	s.cpuMu.Lock()
	s.cpuPrev = [2]uint64{idle0, total0}
	s.cpuMu.Unlock()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		idle1, total1, err := readProcStatCPU()
		if err != nil {
			continue
		}
		s.cpuMu.Lock()
		idleDelta := idle1 - s.cpuPrev[0]
		totalDelta := total1 - s.cpuPrev[1]
		if totalDelta > 0 {
			s.cpuLoad = (1.0 - float64(idleDelta)/float64(totalDelta)) * 100.0
		}
		s.cpuPrev = [2]uint64{idle1, total1}
		s.cpuMu.Unlock()
	}
}

func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()
	status.Details["listen_addr"] = s.config.ListenAddr
	status.Details["enabled"] = s.config.Enabled

	s.mu.RLock()
	status.Details["routes_registered"] = len(s.handlers)
	s.mu.RUnlock()

	return status
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
