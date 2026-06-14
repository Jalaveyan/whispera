package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleUser     Role = "user"
	RoleBridge   Role = "bridge"
)

const (
	AccessTokenTTL  = 30 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour
)

type Claims struct {
	Sub      string `json:"sub"`
	Role     Role   `json:"role"`
	DeviceID string `json:"did,omitempty"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Jti      string `json:"jti"`
	Type     string `json:"typ"`
}

func (c *Claims) IsExpired() bool {
	return time.Now().Unix() > c.Exp
}

func (c *Claims) HasRole(required Role) bool {
	if c.Role == RoleAdmin {
		return true
	}
	if c.Role == RoleOperator && (required == RoleOperator || required == RoleUser) {
		return true
	}
	return c.Role == required
}

type JWTManager struct {
	mu            sync.RWMutex
	signingKey    []byte
	revokedJTIs   map[string]time.Time
	refreshTokens map[string]*refreshEntry
}

type refreshEntry struct {
	userID   string
	role     Role
	deviceID string
	exp      time.Time
}

func NewJWTManager(signingKey []byte) *JWTManager {
	m := &JWTManager{
		signingKey:    signingKey,
		revokedJTIs:   make(map[string]time.Time),
		refreshTokens: make(map[string]*refreshEntry),
	}
	go m.cleanupLoop()
	return m
}

func (m *JWTManager) IssueAccessToken(userID string, role Role, deviceID string) (string, error) {
	jti := generateJTI()
	claims := &Claims{
		Sub:      userID,
		Role:     role,
		DeviceID: deviceID,
		Exp:      time.Now().Add(AccessTokenTTL).Unix(),
		Iat:      time.Now().Unix(),
		Jti:      jti,
		Type:     "access",
	}
	return m.encode(claims)
}

func (m *JWTManager) IssueRefreshToken(userID string, role Role, deviceID string) (string, error) {
	token := generateJTI() + generateJTI()
	m.mu.Lock()
	m.refreshTokens[token] = &refreshEntry{
		userID:   userID,
		role:     role,
		deviceID: deviceID,
		exp:      time.Now().Add(RefreshTokenTTL),
	}
	m.mu.Unlock()
	return token, nil
}

func (m *JWTManager) IssueTokenPair(userID string, role Role, deviceID string) (accessToken, refreshToken string, err error) {
	accessToken, err = m.IssueAccessToken(userID, role, deviceID)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = m.IssueRefreshToken(userID, role, deviceID)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func (m *JWTManager) RefreshAccessToken(refreshToken string) (newAccess, newRefresh string, err error) {
	m.mu.Lock()
	entry, exists := m.refreshTokens[refreshToken]
	if !exists {
		m.mu.Unlock()
		return "", "", fmt.Errorf("invalid refresh token")
	}
	if time.Now().After(entry.exp) {
		delete(m.refreshTokens, refreshToken)
		m.mu.Unlock()
		return "", "", fmt.Errorf("refresh token expired")
	}
	userID := entry.userID
	role := entry.role
	deviceID := entry.deviceID
	delete(m.refreshTokens, refreshToken)
	m.mu.Unlock()

	return m.IssueTokenPair(userID, role, deviceID)
}

func (m *JWTManager) ValidateAccessToken(tokenStr string) (*Claims, error) {
	claims, err := m.decode(tokenStr)

	if err != nil {
		return nil, err
	}

	if claims.Type != "access" {
		return nil, fmt.Errorf("not an access token")
	}
	if claims.IsExpired() {
		return nil, fmt.Errorf("token expired")
	}

	_, revoked := m.revokedJTIs[claims.Jti]

	if revoked {
		return nil, fmt.Errorf("token revoked")
	}
	return claims, nil
}

func (m *JWTManager) RevokeAccessToken(tokenStr string) {

	claims, err := m.decode(tokenStr)

	if err != nil {
		return
	}

	m.mu.Lock()
	m.revokedJTIs[claims.Jti] = time.Unix(claims.Exp, 0)
	m.mu.Unlock()
}

func (m *JWTManager) RevokeRefreshToken(refreshToken string) {
	m.mu.Lock()
	delete(m.refreshTokens, refreshToken)
	m.mu.Unlock()
}

func (m *JWTManager) RevokeAllUserTokens(userID string) {
	m.mu.Lock()
	for k, v := range m.refreshTokens {
		if v.userID == userID {
			delete(m.refreshTokens, k)
		}
	}
	m.mu.Unlock()
}

func (m *JWTManager) encode(claims *Claims) (string, error) {

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)

	if err != nil {
		return "", err
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sigInput := header + "." + payloadB64
	sig := m.sign([]byte(sigInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return sigInput + "." + sigB64, nil
}

func (m *JWTManager) decode(tokenStr string) (*Claims, error) {
	parts := strings.SplitN(tokenStr, ".", 3)

	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	sigInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])

	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding")
	}
	expected := m.sign([]byte(sigInput))

	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return nil, fmt.Errorf("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])

	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding")
	}

	var claims Claims

	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid claims")
	}
	return &claims, nil
}

func (m *JWTManager) sign(data []byte) []byte {
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write(data)
	return mac.Sum(nil)
}

func (m *JWTManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)

	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		for jti, exp := range m.revokedJTIs {
			if now.After(exp) {
				delete(m.revokedJTIs, jti)
			}
		}
		for k, v := range m.refreshTokens {
			if now.After(v.exp) {
				delete(m.refreshTokens, k)
			}
		}
	}
}

func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var Permissions = map[Role][]string{
	RoleAdmin:    {"*"},
	RoleOperator: {"bridges.*", "users.read", "stats.*", "config.read", "sessions.*"},
	RoleUser:     {"profile.*", "bridges.list", "bridges.connect"},
	RoleBridge:   {"bridge.heartbeat", "bridge.register", "bridge.metrics"},
}

func HasPermission(role Role, perm string) bool {
	perms, ok := Permissions[role]

	if !ok {
		return false
	}

	for _, p := range perms {

		if p == "*" {
			return true
		}

		if p == perm {
			return true
		}

		if strings.HasSuffix(p, ".*") {

			prefix := strings.TrimSuffix(p, ".*")

			if strings.HasPrefix(perm, prefix+".") {
				return true
			}
		}
	}
	return false
}
