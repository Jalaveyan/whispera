package apiserver

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"whispera/internal/auth"
	"whispera/internal/db"
)

func (s *Server) registerUserV2Routes() {
	s.Handle("GET /api/v2/users", s.handleListUsersV2)
	s.Handle("POST /api/v2/users", s.handleCreateUserV2)
	s.Handle("GET /api/v2/users/{id}", s.handleGetUserV2)
	s.Handle("PUT /api/v2/users/{id}", s.handleUpdateUserV2)
	s.Handle("DELETE /api/v2/users/{id}", s.handleDeleteUserV2)

	s.Handle("POST /api/v2/users/{id}/link-key", s.handleLinkPublicKeyV2)
	s.Handle("GET /api/v2/users/{id}/sessions", s.handleUserSessionsV2)
	s.Handle("GET /api/v2/users/{id}/stats", s.handleUserStatsV2)
	s.Handle("POST /api/v2/auth/register", s.handleUserRegisterV2)
	s.Handle("POST /api/v2/users/login", s.handleUserLoginV2)
}

func (s *Server) handleListUsersV2(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 50
	}

	users, err := database.ListUsers(r.Context(), limit, offset)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to list users: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"users": users,
		"count": len(users),
	})
}

func (s *Server) handleCreateUserV2(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	var req struct {
		Email             string  `json:"email"`
		Password          string  `json:"password"`
		TrafficLimit      int64   `json:"traffic_limit"`
		ValidUntil        *string `json:"valid_until"`
		ObfsProfile       string  `json:"obfs_profile"`
		MarionetteProfile string  `json:"marionette_profile"`
		RussianService    string  `json:"russian_service"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		s.jsonError(w, http.StatusBadRequest, "Email and password required")
		return
	}

	var validUntilTime *time.Time
	if req.ValidUntil != nil && *req.ValidUntil != "" {
		t, err := time.Parse("2006-01-02", *req.ValidUntil)
		if err != nil {
			t, err = time.Parse(time.RFC3339, *req.ValidUntil)
			if err == nil {
				validUntilTime = &t
			}
		} else {
			t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
			validUntilTime = &t
		}
	}

	keys, err := generateX25519Keys()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to generate keys: "+err.Error())
		return
	}

	user, err := database.CreateUser(r.Context(), req.Email, req.Password, req.TrafficLimit, validUntilTime, req.ObfsProfile, req.MarionetteProfile, req.RussianService, keys.PublicKey, keys.PrivateKey)
	if err != nil {
		if err == db.ErrUserExists {
			s.jsonError(w, http.StatusConflict, "User already exists")
			return
		}
		s.jsonError(w, http.StatusInternalServerError, "Failed to create user: "+err.Error())
		return
	}

	s.jsonCreated(w, map[string]interface{}{
		"success": true,
		"user":    user,
	})
}

func (s *Server) handleGetUserV2(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v2/users/")
	if id == "" {
		s.jsonError(w, http.StatusBadRequest, "User ID required")
		return
	}

	user, err := database.GetUserByEmail(r.Context(), id)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "User not found")
		return
	}

	s.jsonOK(w, user)
}

func (s *Server) handleUpdateUserV2(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/v2/users/")
	if idStr == "" {
		s.jsonError(w, http.StatusBadRequest, "User ID required")
		return
	}

	userID, err := uuid.Parse(idStr)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid User ID")
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" {
		s.jsonError(w, http.StatusBadRequest, "Email is required")
		return
	}

	err = database.UpdateUser(r.Context(), userID, req.Email, req.Password)
	if err != nil {
		if err == db.ErrUserNotFound {
			s.jsonError(w, http.StatusNotFound, "User not found")
			return
		}
		if err == db.ErrUserExists {
			s.jsonError(w, http.StatusConflict, "Email already taken")
			return
		}
		s.jsonError(w, http.StatusInternalServerError, "Failed to update user: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"message": "User updated successfully",
	})
}

func (s *Server) handleDeleteUserV2(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		idStr = strings.TrimPrefix(r.URL.Path, "/api/v2/users/")
	}
	if idStr == "" {
		s.jsonError(w, http.StatusBadRequest, "User ID required")
		return
	}

	userID, err := uuid.Parse(idStr)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid User ID")
		return
	}

	if err := database.DeleteUser(r.Context(), userID); err != nil {
		if err == db.ErrUserNotFound {
			s.jsonError(w, http.StatusNotFound, "User not found")
			return
		}
		s.jsonError(w, http.StatusInternalServerError, "Failed to delete user: "+err.Error())
		return
	}

	s.jsonNoContent(w)
}

func (s *Server) handleLinkPublicKeyV2(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	var req struct {
		PublicKey string `json:"public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.PublicKey == "" {
		s.jsonError(w, http.StatusBadRequest, "Public key is required")
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		idStr = strings.TrimPrefix(r.URL.Path, "/api/v2/users/")
		idStr = strings.TrimSuffix(idStr, "/link-key")
	}

	userID, err := uuid.Parse(idStr)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid User ID")
		return
	}

	if err := database.SetUserPublicKey(r.Context(), userID, req.PublicKey); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to link public key: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"message": "Public key linked successfully",
	})
}

func (s *Server) handleUserSessionsV2(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		idStr = strings.TrimPrefix(r.URL.Path, "/api/v2/users/")
		idStr = strings.TrimSuffix(idStr, "/sessions")
	}

	userID, err := uuid.Parse(idStr)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid User ID")
		return
	}

	sessions, err := database.GetUserSessions(r.Context(), userID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to get sessions: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

func (s *Server) handleUserStatsV2(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		idStr = strings.TrimPrefix(r.URL.Path, "/api/v2/users/")
		idStr = strings.TrimSuffix(idStr, "/stats")
	}

	userID, err := uuid.Parse(idStr)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid User ID")
		return
	}

	stats, err := database.GetUserTotalStats(r.Context(), userID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to get stats: "+err.Error())
		return
	}

	s.jsonOK(w, stats)
}

func (s *Server) handleUserRegisterV2(w http.ResponseWriter, r *http.Request) {
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		s.jsonError(w, http.StatusBadRequest, "Email and password required")
		return
	}

	if len(req.Password) < 8 {
		s.jsonError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	keys, err := generateX25519Keys()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to generate keys: "+err.Error())
		return
	}

	user, err := database.CreateUser(r.Context(), req.Email, req.Password, 0, nil, "http2", "browser", "vk", keys.PublicKey, keys.PrivateKey)
	if err != nil {
		if err == db.ErrUserExists {
			s.jsonError(w, http.StatusConflict, "User already exists")
			return
		}
		s.jsonError(w, http.StatusInternalServerError, "Registration failed")
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"user_id": user.ID,
		"message": "Registration successful",
	})
}

func (s *Server) handleUserLoginV2(w http.ResponseWriter, r *http.Request) {
	database := db.Global()
	if database == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "Database not configured")
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, err := database.AuthenticateUser(r.Context(), req.Email, req.Password)
	if err != nil {
		switch err {
		case db.ErrUserNotFound, db.ErrInvalidPassword:
			s.jsonError(w, http.StatusUnauthorized, "Invalid email or password")
		case db.ErrUserInactive:
			s.jsonError(w, http.StatusForbidden, "Account is inactive")
		default:
			s.jsonError(w, http.StatusInternalServerError, "Login failed")
		}
		return
	}

	role := auth.RoleUser
	if user.IsAdmin {
		role = auth.RoleAdmin
	}
	accessToken, _, err := s.jwtManager.IssueTokenPair(user.ID.String(), role, "")
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Token generation failed")
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"user_id": user.ID,
		"email":   user.Email,
		"plan":    user.PlanName,
		"token":   accessToken,
	})
}
