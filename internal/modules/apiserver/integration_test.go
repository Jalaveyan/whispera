package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"whispera/internal/auth"
	"whispera/internal/core/base"
	"whispera/internal/modules/bridgepool"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	secret := []byte("test-signing-secret-32-bytes!!!!!")
	bridgeReg := bridgepool.NewRegistry("")
	s := &Server{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		config:         &Config{
			Enabled:       true,
			ListenAddr:    ":0",
			EnableCORS:    true,
			AdminUsername: "admin",
			AdminPassword: "testpass123",
		},
		mux:            http.NewServeMux(),
		handlers:       make(map[string]http.HandlerFunc),
		mfaManager:     auth.NewMFAManager(),
		jwtManager:     auth.NewJWTManager(secret),
		bridgePool:     bridgeReg,
		bridgeHandler:  bridgepool.NewAPIHandler(bridgeReg),
		loginAttempts:  make(map[string][]time.Time),
		sessionToken:   "static-test-session-token",
		signingSecret:  secret,
		revokedTokens:  make(map[string]time.Time),
		revokedKeys:    make(map[string]time.Time),
		activeConns:    make(map[string]int32),
		maxConnsPerIP:  50,
		apiRateBuckets: make(map[string]*apiRateBucket),
		apiRateClean:   time.Now(),
		startTime:      time.Now(),
	}
	s.registerDefaultRoutes()
	return s
}

func doRequest(handler http.Handler, method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, path, bodyReader)
	if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func parseJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON response: %v\nbody: %s", err, rec.Body.String())
	}
	return result
}

func TestHealthEndpoint(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/health", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	result := parseJSON(t, rec)
	if result["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", result["status"])
	}
}

func TestLoginV1_Success(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	body := map[string]string{"username": "admin", "password": "testpass123"}
	rec := doRequest(handler, "POST", "/api/login", body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	result := parseJSON(t, rec)
	if result["success"] != true {
		t.Errorf("expected success=true, got %v", result["success"])
	}
	if result["token"] == nil || result["token"] == "" {
		t.Error("expected non-empty token")
	}
	if result["expires_in"] == nil {
		t.Error("expected expires_in field")
	}

	user, ok := result["user"].(map[string]interface{})
	if !ok {
		t.Fatal("expected user object in response")
	}
	if user["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", user["role"])
	}
}

func TestLoginV1_InvalidPassword(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	body := map[string]string{"username": "admin", "password": "wrongpass"}
	rec := doRequest(handler, "POST", "/api/login", body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginV1_InvalidUsername(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	body := map[string]string{"username": "notadmin", "password": "testpass123"}
	rec := doRequest(handler, "POST", "/api/login", body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginV1_RateLimit(t *testing.T) {
	s := newTestServer(t)
	s.config.LoginRateLimit = 3
	handler := s.buildHandler()

	body := map[string]string{"username": "admin", "password": "wrongpass"}
	for i := 0; i < 3; i++ {
		doRequest(handler, "POST", "/api/login", body, "")
	}

	rec := doRequest(handler, "POST", "/api/login", body, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after rate limit, got %d", rec.Code)
	}
}

func TestLoginV2_Success(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	body := map[string]string{"username": "admin", "password": "testpass123"}
	rec := doRequest(handler, "POST", "/api/v2/auth/login", body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	result := parseJSON(t, rec)
	if result["success"] != true {
		t.Errorf("expected success=true")
	}
	if result["access_token"] == nil || result["access_token"] == "" {
		t.Error("expected non-empty access_token")
	}
	if result["refresh_token"] == nil || result["refresh_token"] == "" {
		t.Error("expected non-empty refresh_token")
	}
	if result["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", result["token_type"])
	}
}

func TestLoginV2_InvalidCredentials(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	body := map[string]string{"username": "admin", "password": "wrong"}
	rec := doRequest(handler, "POST", "/api/v2/auth/login", body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestTokenRefresh(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	loginBody := map[string]string{"username": "admin", "password": "testpass123"}
	loginRec := doRequest(handler, "POST", "/api/v2/auth/login", loginBody, "")
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRec.Code)
	}

	loginResult := parseJSON(t, loginRec)
	refreshToken := loginResult["refresh_token"].(string)

	refreshBody := map[string]string{"refresh_token": refreshToken}
	rec := doRequest(handler, "POST", "/api/v2/auth/refresh", refreshBody, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	result := parseJSON(t, rec)
	if result["access_token"] == nil || result["access_token"] == "" {
		t.Error("expected new access_token after refresh")
	}
}

func TestTokenRefresh_InvalidToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	body := map[string]string{"refresh_token": "invalid-token"}
	rec := doRequest(handler, "POST", "/api/v2/auth/refresh", body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/status", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/status", nil, "bogus-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with invalid token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_SessionToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/status", nil, "static-test-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with session token, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_TimedToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	token := s.issueTimedToken("admin")

	rec := doRequest(handler, "GET", "/api/v1/status", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with timed token, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_JWTToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	accessToken, _, err := s.jwtManager.IssueTokenPair("admin", auth.RoleAdmin, "test-device")
	if err != nil {
		t.Fatal(err)
	}

	rec := doRequest(handler, "GET", "/api/v1/status", nil, accessToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with JWT, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_PublicEndpoints(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/health", nil, "")
	if rec.Code == http.StatusUnauthorized {
		t.Error("GET /api/v1/health should not require auth")
	}

	loginBody := map[string]string{"username": "admin", "password": "testpass123"}
	rec = doRequest(handler, "POST", "/api/login", loginBody, "")
	if rec.Code == http.StatusUnauthorized {
		result := parseJSON(t, rec)
		if result["error"] == "unauthorized" || result["error"] == "session expired" {
			t.Error("POST /api/login should not require auth middleware")
		}
	}

	rec = doRequest(handler, "POST", "/api/v2/auth/login", loginBody, "")
	if rec.Code == http.StatusUnauthorized {
		result := parseJSON(t, rec)
		if result["error"] == "unauthorized" || result["error"] == "session expired" {
			t.Error("POST /api/v2/auth/login should not require auth middleware")
		}
	}
}

func TestLogout_RevokesToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	loginBody := map[string]string{"username": "admin", "password": "testpass123"}
	loginRec := doRequest(handler, "POST", "/api/login", loginBody, "")
	loginResult := parseJSON(t, loginRec)
	token := loginResult["token"].(string)

	rec := doRequest(handler, "GET", "/api/v1/status", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("token should work before logout, got %d", rec.Code)
	}

	logoutRec := doRequest(handler, "POST", "/api/logout", nil, token)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", logoutRec.Code)
	}

	rec = doRequest(handler, "GET", "/api/v1/status", nil, token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("token should be revoked after logout, got %d", rec.Code)
	}
}

func TestLogoutV2_RevokesJWT(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	loginBody := map[string]string{"username": "admin", "password": "testpass123"}
	loginRec := doRequest(handler, "POST", "/api/v2/auth/login", loginBody, "")
	loginResult := parseJSON(t, loginRec)
	accessToken := loginResult["access_token"].(string)
	refreshToken := loginResult["refresh_token"].(string)

	rec := doRequest(handler, "GET", "/api/v1/status", nil, accessToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("JWT should work before logout, got %d", rec.Code)
	}

	logoutBody := map[string]string{"refresh_token": refreshToken}
	logoutRec := doRequest(handler, "POST", "/api/v2/auth/logout", logoutBody, accessToken)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("v2 logout failed: %d", logoutRec.Code)
	}

	rec = doRequest(handler, "GET", "/api/v1/status", nil, accessToken)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("JWT should be revoked after v2 logout, got %d", rec.Code)
	}
}

func TestStatusEndpoint(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/status", nil, s.sessionToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	result := parseJSON(t, rec)
	if result["version"] != ModuleVersion {
		t.Errorf("expected version=%s, got %v", ModuleVersion, result["version"])
	}
}

func TestGetConfig(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/config", nil, s.sessionToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	result := parseJSON(t, rec)
	api, ok := result["api"].(map[string]interface{})
	if !ok {
		t.Fatal("expected api object")
	}
	if api["cors"] != true {
		t.Errorf("expected cors=true, got %v", api["cors"])
	}
}

func TestFullAuthFlow_V1(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	loginBody := map[string]string{"username": "admin", "password": "testpass123"}
	loginRec := doRequest(handler, "POST", "/api/login", loginBody, "")
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRec.Code)
	}
	loginResult := parseJSON(t, loginRec)
	token := loginResult["token"].(string)

	statusRec := doRequest(handler, "GET", "/api/v1/status", nil, token)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status with token failed: %d", statusRec.Code)
	}

	configRec := doRequest(handler, "GET", "/api/v1/config", nil, token)
	if configRec.Code != http.StatusOK {
		t.Fatalf("config with token failed: %d", configRec.Code)
	}

	logoutRec := doRequest(handler, "POST", "/api/logout", nil, token)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", logoutRec.Code)
	}

	afterLogoutRec := doRequest(handler, "GET", "/api/v1/status", nil, token)
	if afterLogoutRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", afterLogoutRec.Code)
	}
}

func TestFullAuthFlow_V2(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	loginBody := map[string]string{"username": "admin", "password": "testpass123"}
	loginRec := doRequest(handler, "POST", "/api/v2/auth/login", loginBody, "")
	if loginRec.Code != http.StatusOK {
		t.Fatalf("v2 login failed: %d", loginRec.Code)
	}
	loginResult := parseJSON(t, loginRec)
	accessToken := loginResult["access_token"].(string)
	refreshToken := loginResult["refresh_token"].(string)

	statusRec := doRequest(handler, "GET", "/api/v1/status", nil, accessToken)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status failed: %d", statusRec.Code)
	}

	refreshBody := map[string]string{"refresh_token": refreshToken}
	refreshRec := doRequest(handler, "POST", "/api/v2/auth/refresh", refreshBody, "")
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d", refreshRec.Code)
	}
	refreshResult := parseJSON(t, refreshRec)
	newAccessToken := refreshResult["access_token"].(string)

	statusRec2 := doRequest(handler, "GET", "/api/v1/status", nil, newAccessToken)
	if statusRec2.Code != http.StatusOK {
		t.Fatalf("status with refreshed token failed: %d", statusRec2.Code)
	}

	logoutBody := map[string]string{"refresh_token": refreshToken}
	logoutRec := doRequest(handler, "POST", "/api/v2/auth/logout", logoutBody, newAccessToken)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("v2 logout failed: %d", logoutRec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/health", nil, "")

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
	}

	for header, expected := range expectedHeaders {
		got := rec.Header().Get(header)
		if got != expected {
			t.Errorf("expected %s=%s, got %q", header, expected, got)
		}
	}
}

func TestCORS_Preflight(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	req, _ := http.NewRequestWithContext(context.Background(), "OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://127.0.0.1:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("expected 200/204 for preflight, got %d", rec.Code)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	bigBody := make([]byte, 2<<20)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/login", bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("oversized body should not succeed")
	}
}

func TestConcurrentRequests(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	var wg sync.WaitGroup
	errors := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := doRequest(handler, "GET", "/api/v1/health", nil, "")
			if rec.Code != http.StatusOK {
				errors <- &httpError{code: rec.Code}
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent request failed: %v", err)
	}
}

type httpError struct{ code int }

func (e *httpError) Error() string { return http.StatusText(e.code) }

func TestRootEndpoint(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	result := parseJSON(t, rec)
	if result["name"] != "Whispera API" {
		t.Errorf("expected name=Whispera API, got %v", result["name"])
	}
	if result["status"] != "running" {
		t.Errorf("expected status=running, got %v", result["status"])
	}
}

func TestLoginV1_EmptyBody(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/login", bytes.NewReader([]byte("")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", rec.Code)
	}
}

func TestLoginV1_MalformedJSON(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/login", bytes.NewReader([]byte("{bad json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d", rec.Code)
	}
}

func TestTimedToken_Validation(t *testing.T) {
	s := newTestServer(t)

	token := s.issueTimedToken("admin")
	if !s.validateTimedToken(token) {
		t.Error("freshly issued token should be valid")
	}

	if s.validateTimedToken("garbage.token") {
		t.Error("garbage token should be invalid")
	}

	if s.validateTimedToken("") {
		t.Error("empty token should be invalid")
	}

	s.revokeToken(token)
	if s.validateTimedToken(token) {
		t.Error("revoked token should be invalid")
	}
}

func TestConnLimitMiddleware(t *testing.T) {
	s := newTestServer(t)
	s.maxConnsPerIP = 2

	block := make(chan struct{})
	s.Handle("GET /api/v1/slow", func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	})
	handler := s.buildHandler()

	var wg sync.WaitGroup
	results := make([]int, 3)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rec := doRequest(handler, "GET", "/api/v1/slow", nil, s.sessionToken)
			results[idx] = rec.Code
		}(i)
	}

	time.Sleep(50 * time.Millisecond)

	wg.Add(1)
	go func() {
		defer wg.Done()
		rec := doRequest(handler, "GET", "/api/v1/slow", nil, s.sessionToken)
		results[2] = rec.Code
	}()

	time.Sleep(50 * time.Millisecond)
	close(block)
	wg.Wait()
}

func TestBridgeRegister_BypassesJWTAuth(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	body := map[string]interface{}{
		"address":    "10.0.0.1:8443",
		"type":       "operator",
		"public_key": "dGVzdA==",
	}
	rec := doRequest(handler, "POST", "/api/bridge-register", body, "")
	body2 := rec.Body.String()
	if rec.Code == http.StatusUnauthorized && (strings.Contains(body2, `"unauthorized"`) || strings.Contains(body2, `"session expired"`)) {
		t.Fatal("bridge-register should bypass JWT auth middleware")
	}
}

func TestBridgeHeartbeat_BypassesJWTAuth(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	body := map[string]interface{}{"bridge_id": "test-id"}
	rec := doRequest(handler, "POST", "/api/bridge-heartbeat", body, "")
	body2 := rec.Body.String()
	if rec.Code == http.StatusUnauthorized && (strings.Contains(body2, `"unauthorized"`) || strings.Contains(body2, `"session expired"`)) {
		t.Fatal("bridge-heartbeat should bypass JWT auth middleware")
	}
}

func TestProtectedEndpoints_RequireAuth(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/status"},
		{"GET", "/api/v1/modules"},
		{"GET", "/api/v1/config"},
		{"GET", "/api/v1/stats"},
		{"GET", "/api/v1/sessions"},
		{"GET", "/api/users"},
		{"GET", "/api/inbounds"},
		{"GET", "/api/outbounds"},
		{"GET", "/api/bridge-list"},
		{"GET", "/api/subscriptions"},
		{"GET", "/api/stats"},
		{"GET", "/api/logs"},
	}

	for _, ep := range endpoints {
		rec := doRequest(handler, ep.method, ep.path, nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s should require auth, got %d", ep.method, ep.path, rec.Code)
		}
	}
}

func TestTrafficStats(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/stats/traffic", nil, s.sessionToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	result := parseJSON(t, rec)
	if _, ok := result["total_download"]; !ok {
		t.Error("expected total_download field")
	}
	if _, ok := result["total_upload"]; !ok {
		t.Error("expected total_upload field")
	}
}
