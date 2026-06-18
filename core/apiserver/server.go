package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"whispera/app/auth"
	"whispera/app/db"
	logger "whispera/common/log"
	"whispera/common/runtime/base"
	"whispera/common/runtime/events"
	"whispera/common/runtime/interfaces"
	"whispera/common/runtime/registry"
	"whispera/common/stats"
	config2 "whispera/core/config"
	"whispera/core/keylimits"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "api.server"
	ModuleVersion = "1.0.0"
)

var log = logger.Module("apiserver")

type ctxKey int

const ctxKeyClaims ctxKey = 1

func GetClaims(r *http.Request) *auth.Claims {
	if c, ok := r.Context().Value(ctxKeyClaims).(*auth.Claims); ok {
		return c
	}
	return nil
}

type Config struct {
	Enabled           bool
	ListenAddr        string
	AuthToken         string
	WebRoot           string
	EnableCORS        bool
	AllowedOrigins    []string
	TLSCert           string
	TLSKey            string
	AdminUsername     string
	AdminPassword     string
	AdminPasswordHash string
	LoginRateLimit    int
	TLSFingerprint    string
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:    true,
		ListenAddr: ":8081",
		EnableCORS: true,
	}
}

var weakPasswords = map[string]struct{}{
	"admin": {}, "password": {}, "12345678": {}, "qwerty": {},
	"whispera": {}, "changeme": {}, "secret": {}, "letmein": {},
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8081"
	}
	if c.AdminPasswordHash == "" {
		if p := c.AdminPassword; p != "" {
			if len(p) < 12 {
				return fmt.Errorf("admin_password is too short (minimum 12 characters) — generate one with: openssl rand -base64 16")
			}
			if _, weak := weakPasswords[strings.ToLower(p)]; weak {
				return fmt.Errorf("admin_password %q is a known default — change it in config.yaml", p)
			}
		}
	}
	return nil
}

type Server struct {
	*base.Module
	config      *Config
	server      *http.Server
	http3Server *http3.Server
	mux         *http.ServeMux

	registry registry.Registry

	mu       sync.RWMutex
	handlers map[string]http.HandlerFunc

	jwtManager    *auth.JWTManager
	keyLimits     *keylimits.Manager
	probeDetector interface {
		Stats() map[string]interface{}
		BlockIP(ip, reason string)
		UnblockIP(ip string)
	}

	loginAttempts   map[string][]time.Time
	loginAttemptsMu sync.Mutex

	sessionToken  string
	signingSecret []byte

	revokedTokens   map[string]time.Time
	revokedTokensMu sync.Mutex

	revokedKeys   map[string]time.Time
	revokedKeysMu sync.RWMutex

	cpuLoad float64
	cpuMu   sync.Mutex
	cpuPrev [2]uint64

	activeConns   map[string]int32
	activeConnsMu sync.Mutex
	maxConnsPerIP int

	apiRateBuckets   map[string]*apiRateBucket
	apiRateBucketsMu sync.Mutex
	apiRateClean     time.Time

	inflight  sync.WaitGroup
	startTime time.Time
}

func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll("/etc/whispera", 0755); err != nil {
	}

	loadUsers()
	loadSubscriptions()

	sessionToken := loadOrCreateSessionToken()
	signingSecret := loadOrCreateSigningSecret()

	s := &Server{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		config:         cfg,
		mux:            http.NewServeMux(),
		handlers:       make(map[string]http.HandlerFunc),
		jwtManager:     auth.NewJWTManager(signingSecret),
		loginAttempts:  make(map[string][]time.Time),
		sessionToken:   sessionToken,
		signingSecret:  signingSecret,
		revokedTokens:  make(map[string]time.Time),
		revokedKeys:    make(map[string]time.Time),
		activeConns:    make(map[string]int32),
		maxConnsPerIP:  50,
		apiRateBuckets: make(map[string]*apiRateBucket),
		apiRateClean:   time.Now(),
	}

	s.loadRevokedKeys()
	s.registerDefaultRoutes()
	go s.cpuSampler()

	s.registerUserV2Routes()

	return s, nil
}

func (s *Server) SetKeyLimits(m *keylimits.Manager) {
	s.keyLimits = m
}

// handleDisabledEndpoint stands in for panel-era admin routes that have no
// remaining caller (the web panel is gone; the chameleon/CLI key flow
// bypasses this HTTP API entirely). Kept registered rather than deleted so
// the underlying handler code survives for potential future use, but
// unreachable until explicitly re-wired.
func (s *Server) handleDisabledEndpoint(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"endpoint disabled"}`, http.StatusForbidden)
}

func (s *Server) registerDefaultRoutes() {
	s.Handle("POST /api/login", s.handleLogin)
	s.Handle("POST /api/auth/login", s.handleDisabledEndpoint)
	s.Handle("POST /api/logout", s.handleLogout)
	s.Handle("POST /api/v2/auth/login", s.handleLoginV2)
	s.Handle("POST /api/v2/auth/refresh", s.handleRefreshToken)
	s.Handle("POST /api/v2/auth/logout", s.handleLogoutV2)

	s.Handle("GET /api/v1/health", s.handleHealth)
	s.Handle("GET /api/v1/status", s.handleStatus)
	s.Handle("GET /api/v1/modules", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/config", s.handleGetConfig)

	s.Handle("POST /api/v1/config/update", s.handleDisabledEndpoint)
	s.Handle("POST /api/v1/config/reload", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/sessions", s.handleDisabledEndpoint)
	s.Handle("DELETE /api/v1/sessions/{id}", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/stats", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/system/info", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/stats/traffic", s.handleTrafficStats)
	s.Handle("GET /api/v1/stats/users", s.handleDisabledEndpoint)

	s.Handle("GET /api/v1/dhcp/status", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/dhcp/leases", s.handleDisabledEndpoint)
	s.Handle("DELETE /api/v1/dhcp/lease", s.handleDisabledEndpoint)
	s.Handle("GET /api/users", s.handleDisabledEndpoint)
	s.Handle("POST /api/users/add", s.handleDisabledEndpoint)
	s.Handle("POST /api/users", s.handleDisabledEndpoint)
	s.Handle("PUT /api/users/{id}", s.handleDisabledEndpoint)
	s.Handle("POST /api/users/delete", s.handleDisabledEndpoint)

	s.Handle("GET /api/routing/rules", s.handleDisabledEndpoint)
	s.Handle("POST /api/routing/rules/add", s.handleDisabledEndpoint)
	s.Handle("POST /api/routing/rules/delete", s.handleDisabledEndpoint)
	s.Handle("GET /api/outbounds", s.handleGetOutbounds)
	s.Handle("POST /api/outbounds/add", s.handleAddOutbound)
	s.Handle("POST /api/outbounds/delete", s.handleDeleteOutbound)

	s.Handle("GET /api/inbounds", s.handleDisabledEndpoint)
	s.Handle("GET /api/inbounds/pubkey", s.handleDisabledEndpoint)
	s.Handle("POST /api/inbounds/add", s.handleDisabledEndpoint)
	s.Handle("POST /api/inbounds/update", s.handleDisabledEndpoint)
	s.Handle("POST /api/inbounds/delete", s.handleDisabledEndpoint)

	s.Handle("POST /api/keys/generate", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/connection", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/transport", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/multi-transport", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/revoke", s.handleDisabledEndpoint)
	s.Handle("GET /api/keys/revoked", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/check", s.handleDisabledEndpoint)
	s.Handle("GET /api/keys/ping", s.handleDisabledEndpoint)
	s.Handle("GET /api/keys/ping/all", s.handleDisabledEndpoint)

	s.Handle("GET /api/key-limits", s.handleDisabledEndpoint)
	s.Handle("GET /api/key-limits/{id}", s.handleDisabledEndpoint)
	s.Handle("POST /api/key-limits/{id}", s.handleDisabledEndpoint)
	s.Handle("DELETE /api/key-limits/{id}", s.handleDisabledEndpoint)
	s.Handle("GET /api/key-limits-defaults", s.handleDisabledEndpoint)
	s.Handle("POST /api/key-limits-defaults", s.handleDisabledEndpoint)

	s.Handle("GET /api/subscriptions", s.handleDisabledEndpoint)
	s.Handle("POST /api/subscriptions/add", s.handleDisabledEndpoint)
	s.Handle("POST /api/subscriptions/update", s.handleDisabledEndpoint)
	s.Handle("POST /api/subscriptions/delete", s.handleDisabledEndpoint)
	s.Handle("GET /sub/{token}", s.handleServeSubscription)

	s.Handle("GET /api/firewall/status", s.handleDisabledEndpoint)
	s.Handle("POST /api/firewall/rules", s.handleDisabledEndpoint)
	s.Handle("DELETE /api/firewall/rules", s.handleDisabledEndpoint)
	s.Handle("POST /api/firewall/toggle", s.handleDisabledEndpoint)
	s.Handle("GET /api/backup", s.handleGetBackup)
	s.Handle("GET /api/backup/full", s.handleGetBackupFull)
	s.Handle("GET /api/backup/list", s.handleBackupList)
	s.Handle("POST /api/backup/restore", s.handleRestoreBackup)

	s.Handle("GET /api/sessions", s.handleDisabledEndpoint)
	s.Handle("POST /api/sessions/{id}/kill", s.handleDisabledEndpoint)
	s.Handle("GET /api/stats", s.handleDisabledEndpoint)
	s.Handle("GET /api/stats/live", s.handleDisabledEndpoint)
	s.Handle("GET /api/stats/traffic", s.handleDisabledEndpoint)
	s.Handle("GET /api/stats/user/{id}", s.handleDisabledEndpoint)

	s.Handle("GET /api/system/info", s.handleDisabledEndpoint)
	s.Handle("POST /api/admin/update", s.handleDisabledEndpoint)
	s.Handle("GET /api/system/update-check", s.handleDisabledEndpoint)
	s.Handle("GET /api/logs", s.handleDisabledEndpoint)

	s.Handle("GET /api/ml/config", s.handleDisabledEndpoint)
	s.Handle("POST /api/ml/token/rotate", s.handleDisabledEndpoint)
	s.Handle("GET /api/events", s.handleDisabledEndpoint)

	s.Handle("GET /api/fingerprints", s.handleDisabledEndpoint)
	s.Handle("POST /api/fingerprints/set", s.handleDisabledEndpoint)
	s.Handle("GET /api/failover/status", s.handleDisabledEndpoint)

	s.Handle("GET /api/v1/speed/ping", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/speed/download", s.handleDisabledEndpoint)
	s.Handle("POST /api/v1/speed/upload", s.handleDisabledEndpoint)
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

	s.startTime = time.Now()

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		ctx := s.Module.Context()
		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-2 * time.Minute)
				s.loginAttemptsMu.Lock()
				for ip, attempts := range s.loginAttempts {
					var fresh []time.Time
					for _, t := range attempts {
						if t.After(cutoff) {
							fresh = append(fresh, t)
						}
					}
					if len(fresh) == 0 {
						delete(s.loginAttempts, ip)
					} else {
						s.loginAttempts[ip] = fresh
					}
				}
				s.loginAttemptsMu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

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
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.config.ListenAddr)
	if err != nil {
		errMsg := fmt.Sprintf("failed to bind to %s: %v", s.config.ListenAddr, err)
		s.SetHealthy(false, errMsg)
		return fmt.Errorf("failed to bind API server to %s: %w", s.config.ListenAddr, err)
	}

	log.Printf("listening on %s", s.config.ListenAddr)

	go func() {
		var serveErr error
		if s.config.TLSCert != "" && s.config.TLSKey != "" {
			serveErr = s.server.ServeTLS(ln, s.config.TLSCert, s.config.TLSKey)
		} else {
			serveErr = s.server.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Error("HTTP server error: %v", serveErr)
			s.SetHealthy(false, fmt.Sprintf("HTTP server error: %v", serveErr))
		}
	}()

	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		s.http3Server = &http3.Server{
			Addr:    s.config.ListenAddr,
			Handler: handler,
		}
		go func() {
			if err := s.http3Server.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey); err != nil {
			}
		}()
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.cleanupRevokedTokens()
		}
	}()

	s.SetHealthy(true, fmt.Sprintf("API server running on %s", s.config.ListenAddr))
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": s.config.ListenAddr,
	})

	return nil
}

func (s *Server) Stop() error {
	if s.http3Server != nil {
		s.http3Server.Close()
	}
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)

		done := make(chan struct{})
		go func() { s.inflight.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
		}
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

func (s *Server) buildHandler() http.Handler {
	var rootHandler http.Handler
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
					"panel": "http://" + func() string {
						if i := strings.LastIndex(r.Host, ":"); i >= 0 {
							return r.Host[:i]
						}
						return r.Host
					}() + ":3000",
					"api": "/api/v1/health",
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

	handler = s.requestBodyLimitMiddleware(handler)

	handler = s.apiRateMiddleware(handler)

	if s.config.EnableCORS {
		handler = s.corsMiddleware(handler)
	}

	handler = s.securityHeadersMiddleware(handler)

	handler = s.loggingMiddleware(handler)

	handler = s.connLimitMiddleware(handler)

	handler = s.timeoutMiddleware(handler, 30*time.Second)

	handler = s.recoveryMiddleware(handler)

	return handler
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
				originHost := origin
				if i := strings.Index(originHost, "://"); i >= 0 {
					originHost = originHost[i+3:]
				}
				originHost = strings.TrimRight(originHost, "/")
				reqHost := r.Host
				if h, _, err := net.SplitHostPort(reqHost); err == nil {
					reqHost = h
				}
				if h, _, err := net.SplitHostPort(originHost); err == nil {
					originHost = h
				}
				if originHost == reqHost {
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
		w.Header().Set("Access-Control-Max-Age", "3600")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			if s.http3Server != nil {
				h.Set("Alt-Svc", `h3="`+s.config.ListenAddr+`"; ma=86400`)
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/sub/") {
			h.Set("Content-Security-Policy", "default-src 'none'")
		} else {
			h.Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'")
		}

		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")
			if origin != "" && !s.isAllowedOrigin(origin) {
				http.Error(w, `{"error":"origin not allowed"}`, http.StatusForbidden)
				return
			}
			if origin == "" && referer == "" {
				ct := r.Header.Get("Content-Type")
				if !strings.Contains(ct, "application/json") && !strings.Contains(ct, "multipart/form-data") {
					http.Error(w, `{"error":"missing origin"}`, http.StatusForbidden)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) isAllowedOrigin(origin string) bool {
	if len(s.config.AllowedOrigins) == 0 || s.config.AllowedOrigins[0] == "*" {
		return true
	}
	for _, o := range s.config.AllowedOrigins {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	authHdr := r.Header.Get("Authorization")
	if strings.HasPrefix(authHdr, "Bearer ") {
		token := authHdr[len("Bearer "):]
		if s.sessionToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.sessionToken)) == 1 {
			return true
		}
		if s.validateTimedToken(token) {
			return true
		}
	}
	if qt := r.URL.Query().Get("token"); qt != "" && s.validateTimedToken(qt) {
		return true
	}
	if claims := GetClaims(r); claims != nil && claims.HasRole(auth.RoleAdmin) {
		return true
	}
	http.Error(w, `{"error":"admin access required"}`, http.StatusForbidden)
	return false
}

const maxAPIBodyBytes = 1 << 20

func (s *Server) requestBodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodyBytes)
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
			r.URL.Path == "/api/auth/login" ||
			r.URL.Path == "/api/v2/auth/login" ||
			r.URL.Path == "/api/v2/auth/register" ||
			r.URL.Path == "/api/v2/users/login" ||
			r.URL.Path == "/api/v2/auth/refresh" ||
			r.URL.Path == "/api/logout" ||
			r.URL.Path == "/api/keys/check" ||
			r.URL.Path == "/api/v1/speed/ping" ||
			strings.HasSuffix(r.URL.Path, "/health") {
			next.ServeHTTP(w, r)
			return
		}

		var token string
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) {
			token = auth[len(prefix):]
		} else if qt := r.URL.Query().Get("token"); qt != "" {
			token = qt
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if s.sessionToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.sessionToken)) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		if claims, err := s.jwtManager.ValidateAccessToken(token); err == nil {
			ctx := context.WithValue(r.Context(), ctxKeyClaims, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if s.validateTimedToken(token) {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("WWW-Authenticate", `Bearer realm="api", error="invalid_token", error_description="token expired or invalid"`)
		http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.inflight.Add(1)
		defer s.inflight.Done()
		start := time.Now()
		next.ServeHTTP(w, r)
		s.UpdateActivity()
		_ = start
	})
}

func (s *Server) timeoutMiddleware(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) connLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if i := strings.LastIndex(ip, ":"); i >= 0 {
			ip = ip[:i]
		}
		ip = strings.Trim(ip, "[]")

		s.activeConnsMu.Lock()
		count := s.activeConns[ip]
		if int(count) >= s.maxConnsPerIP {
			s.activeConnsMu.Unlock()
			http.Error(w, `{"error":"too many connections"}`, http.StatusTooManyRequests)
			return
		}
		s.activeConns[ip] = count + 1
		s.activeConnsMu.Unlock()

		defer func() {
			s.activeConnsMu.Lock()
			s.activeConns[ip]--
			if s.activeConns[ip] <= 0 {
				delete(s.activeConns, ip)
			}
			s.activeConnsMu.Unlock()
		}()

		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stack := make([]byte, 4096)
				n := runtime.Stack(stack, false)
				log.Error("panic: %v\n%s", err, stack[:n])

				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Internal Server Error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type apiRateBucket struct {
	tokens   float64
	lastTime time.Time
}

func (s *Server) apiRateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		ip := s.getClientIP(r)
		key := ip + "|" + r.URL.Path

		s.apiRateBucketsMu.Lock()
		now := time.Now()

		if now.Sub(s.apiRateClean) > 5*time.Minute {
			cutoff := now.Add(-10 * time.Minute)
			for k, b := range s.apiRateBuckets {
				if b.lastTime.Before(cutoff) {
					delete(s.apiRateBuckets, k)
				}
			}
			s.apiRateClean = now
		}

		b, exists := s.apiRateBuckets[key]
		if !exists {
			b = &apiRateBucket{tokens: 60, lastTime: now}
			s.apiRateBuckets[key] = b
		}

		elapsed := now.Sub(b.lastTime).Seconds()
		b.lastTime = now
		b.tokens += elapsed * 30
		if b.tokens > 60 {
			b.tokens = 60
		}

		allowed := b.tokens >= 1
		if allowed {
			b.tokens--
		}
		s.apiRateBucketsMu.Unlock()

		if !allowed {
			w.Header().Set("Retry-After", "2")
			http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
			return
		}

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

func (s *Server) jsonCreated(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(jsonResponse{Success: false, Error: message})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := s.HealthCheck()
	allHealthy := health.Healthy

	response := map[string]interface{}{
		"status":  "ok",
		"healthy": health.Healthy,
		"message": health.Message,
		"uptime":  time.Since(s.startTime).String(),
	}

	deps := make(map[string]interface{})

	if database := db.Global(); database != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := database.Ping(ctx); err != nil {
			deps["database"] = map[string]interface{}{"status": "unhealthy", "error": err.Error()}
			allHealthy = false
		} else {
			deps["database"] = map[string]interface{}{"status": "healthy"}
		}
	} else {
		deps["database"] = map[string]interface{}{"status": "disabled"}
	}

	if s.registry != nil {
		moduleHealth := s.registry.HealthCheck()
		response["modules"] = moduleHealth
		for _, mh := range moduleHealth {
			if !mh.Healthy {
				allHealthy = false
			}
		}
	}

	response["dependencies"] = deps
	response["healthy"] = allHealthy

	if !allHealthy {
		response["status"] = "degraded"
	}

	s.jsonOK(w, response)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIP(r)
	if !s.checkLoginRateLimit(clientIP) {
		AppendEvent(EventAuth, SeverityWarn, "rate limit exceeded", map[string]string{"ip": clientIP})
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
			AppendEvent(EventAuth, SeverityInfo, "login success", map[string]string{"ip": clientIP, "user": req.Username})

			token := s.issueTimedToken(req.Username)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":    true,
				"token":      token,
				"expires_in": 1800,
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
	}

	usernameMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(expectedUsername)) == 1
	var passwordMatch bool
	if s.config.AdminPasswordHash != "" {
		passwordMatch = usernameMatch && bcrypt.CompareHashAndPassword([]byte(s.config.AdminPasswordHash), []byte(req.Password)) == nil
	} else if expectedPassword != "" {
		passwordMatch = subtle.ConstantTimeCompare([]byte(req.Password), []byte(expectedPassword)) == 1
	}

	if usernameMatch && passwordMatch {
		s.clearLoginAttempts(clientIP)

		token := s.issueTimedToken(req.Username)
		AppendEvent(EventAuth, SeverityInfo, "login success", map[string]string{"ip": clientIP, "user": req.Username})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"token":      token,
			"expires_in": 1800,
			"user": map[string]string{
				"username": req.Username,
				"role":     "admin",
			},
		})
		return
	}

	AppendEvent(EventAuth, SeverityWarn, "login failed", map[string]string{"ip": clientIP, "user": req.Username})
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

func isTrustedProxy(ip string) bool {
	trusted := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range trusted {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func (s *Server) getClientIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !isTrustedProxy(remoteIP) {
		return remoteIP
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" && !isTrustedProxy(ip) {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return remoteIP
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
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

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	resp := map[string]interface{}{
		"api": map[string]interface{}{
			"listen_addr": s.config.ListenAddr,
			"cors":        s.config.EnableCORS,
		},
	}

	if s.registry != nil {
		if module, ok := s.registry.Get("config.provider"); ok {
			if cfgProvider, ok := module.(*config2.Provider); ok {
				cfg := cfgProvider.GetConfig()
				resp["stealth_mode"] = cfg.StealthMode
				resp["public_url"] = cfg.Server.PublicURL
			}
		}
	}

	s.jsonOK(w, resp)
}

func (s *Server) handleTrafficStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
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

	InboundTags []string `json:"inboundTags,omitempty"`
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
const signingSecretFile = "/etc/whispera/signing.key"
const tokenTTL = 30 * time.Minute

func loadOrCreateSessionToken() string {
	data, err := os.ReadFile(sessionTokenFile)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			return token
		}
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Error("failed to generate session token: %v", err)
		return base64.StdEncoding.EncodeToString([]byte("fallback-token"))
	}
	token := base64.StdEncoding.EncodeToString(tokenBytes)
	_ = os.WriteFile(sessionTokenFile, []byte(token), 0600)
	return token
}

func loadOrCreateSigningSecret() []byte {
	data, err := os.ReadFile(signingSecretFile)
	if err == nil && len(data) >= 32 {
		return data[:32]
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	os.WriteFile(signingSecretFile, secret, 0600)
	return secret
}

func (s *Server) issueTimedToken(username string) string {
	expiry := time.Now().Add(tokenTTL).Unix()
	nonce := make([]byte, 8)
	rand.Read(nonce)
	payload := fmt.Sprintf("%s:%d:%s", username, expiry, base64.RawURLEncoding.EncodeToString(nonce))
	sig := computeHMAC(s.signingSecret, payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (s *Server) validateTimedToken(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}

	s.revokedTokensMu.Lock()
	if _, revoked := s.revokedTokens[token]; revoked {
		s.revokedTokensMu.Unlock()
		return false
	}
	s.revokedTokensMu.Unlock()

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	payload := string(payloadBytes)
	expectedSig := computeHMAC(s.signingSecret, payload)
	if !hmacEqual(sigBytes, expectedSig) {
		return false
	}

	fields := strings.SplitN(payload, ":", 3)
	if len(fields) < 2 {
		return false
	}
	var expiry int64
	fmt.Sscanf(fields[1], "%d", &expiry)
	if time.Now().Unix() > expiry {
		return false
	}

	return true
}

func (s *Server) revokeToken(token string) {
	s.revokedTokensMu.Lock()
	s.revokedTokens[token] = time.Now()
	s.revokedTokensMu.Unlock()
}

func (s *Server) cleanupRevokedTokens() {
	s.revokedTokensMu.Lock()
	cutoff := time.Now().Add(-tokenTTL)
	for t, revokedAt := range s.revokedTokens {
		if revokedAt.Before(cutoff) {
			delete(s.revokedTokens, t)
		}
	}
	s.revokedTokensMu.Unlock()
}

func computeHMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := authHeader[7:]
		s.revokeToken(token)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (s *Server) handleLoginV2(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIP(r)
	if !s.checkLoginRateLimit(clientIP) {
		s.jsonError(w, http.StatusTooManyRequests, "Too many login attempts")
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

	var userID string
	var role auth.Role
	authenticated := false

	if database := db.Global(); database != nil {
		user, err := database.AuthenticateUser(r.Context(), req.Username, req.Password)
		if err == nil {
			userID = user.ID.String()
			if user.IsAdmin {
				role = auth.RoleAdmin
			} else {
				role = auth.RoleUser
			}
			authenticated = true
		}
	}

	if !authenticated {
		expectedUsername := s.config.AdminUsername
		expectedPassword := s.config.AdminPassword
		if expectedUsername == "" {
			expectedUsername = "admin"
		}
		if expectedPassword != "" {
			uMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(expectedUsername)) == 1
			pMatch := subtle.ConstantTimeCompare([]byte(req.Password), []byte(expectedPassword)) == 1
			if uMatch && pMatch {
				userID = "admin"
				role = auth.RoleAdmin
				authenticated = true
			}
		}
	}

	if !authenticated {
		s.jsonError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	s.clearLoginAttempts(clientIP)

	deviceID := r.Header.Get("X-Device-ID")
	accessToken, refreshToken, err := s.jwtManager.IssueTokenPair(userID, role, deviceID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to issue tokens")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int(auth.AccessTokenTTL.Seconds()),
		"token_type":    "Bearer",
		"user": map[string]interface{}{
			"id":   userID,
			"role": string(role),
		},
	})
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	accessToken, refreshToken, err := s.jwtManager.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		s.jsonError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int(auth.AccessTokenTTL.Seconds()),
		"token_type":    "Bearer",
	})
}

func (s *Server) handleLogoutV2(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := authHeader[7:]
		s.jwtManager.RevokeAccessToken(token)
	}

	var req struct {
		RefreshToken string `json:"refresh_token,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.RefreshToken != "" {
		s.jwtManager.RevokeRefreshToken(req.RefreshToken)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
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
		log.Error("failed to marshal users: %v", err)
		return
	}
	if err := os.WriteFile(userDataFile, data, 0600); err != nil {
		log.Error("failed to save users: %v", err)
	}
}

func loadUsers() {
	data, err := os.ReadFile(userDataFile)
	if err != nil {
		return
	}
	var p userPersist
	if err := json.Unmarshal(data, &p); err != nil {
		log.Error("failed to load users: %v", err)
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

func generateKeyID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) IsKeyRevoked(keyID string) bool {
	if keyID == "" {
		return false
	}
	s.revokedKeysMu.RLock()
	_, revoked := s.revokedKeys[keyID]
	s.revokedKeysMu.RUnlock()
	return revoked
}

func (s *Server) loadRevokedKeys() {
	data, err := os.ReadFile("/etc/whispera/revoked_keys.json")
	if err != nil {
		return
	}
	s.revokedKeysMu.Lock()
	_ = json.Unmarshal(data, &s.revokedKeys)
	s.revokedKeysMu.Unlock()
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
	if !s.requireAdmin(w, r) {
		return
	}
	module, err := s.getConfigProvider()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	type ConfigProvider interface {
		GetConfig() *config2.ServerConfig
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
	if !s.requireAdmin(w, r) {
		return
	}
	module, err := s.getConfigProvider()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	type ConfigUpdater interface {
		Update(func(*config2.ServerConfig)) error
	}

	provider, ok := module.(ConfigUpdater)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "config provider does not support updates")
		return
	}

	var req config2.OutboundConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if req.Tag == "" {
		req.Tag = fmt.Sprintf("outbound_%d", time.Now().UnixNano())
	}

	err = provider.Update(func(cfg *config2.ServerConfig) {
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

	s.jsonCreated(w, map[string]interface{}{
		"success":  true,
		"outbound": req,
	})
}

func (s *Server) handleDeleteOutbound(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	module, err := s.getConfigProvider()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	type ConfigUpdater interface {
		Update(func(*config2.ServerConfig)) error
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

	err = provider.Update(func(cfg *config2.ServerConfig) {
		newOutbounds := make([]config2.OutboundConfig, 0, len(cfg.Outbounds))
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
