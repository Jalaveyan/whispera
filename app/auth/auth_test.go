package auth

import (
	"testing"
	"time"
)

func TestJWTManagerIssueAndValidate(t *testing.T) {
	mgr := NewJWTManager([]byte("test-secret-key-for-jwt-testing!"))

	access, refresh, err := mgr.IssueTokenPair("user-1", RoleUser, "device-1")
	if err != nil {
		t.Fatalf("IssueTokenPair failed: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected non-empty tokens")
	}

	claims, err := mgr.ValidateAccessToken(access)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}
	if claims.Sub != "user-1" {
		t.Errorf("expected user-1, got %s", claims.Sub)
	}
	if claims.Role != RoleUser {
		t.Errorf("expected %s, got %s", RoleUser, claims.Role)
	}
	if claims.DeviceID != "device-1" {
		t.Errorf("expected device-1, got %s", claims.DeviceID)
	}
	if claims.Type != "access" {
		t.Errorf("expected access, got %s", claims.Type)
	}
}

func TestJWTManagerRefreshToken(t *testing.T) {
	mgr := NewJWTManager([]byte("test-secret-key-for-jwt-testing!"))

	_, refresh, err := mgr.IssueTokenPair("user-1", RoleAdmin, "device-1")
	if err != nil {
		t.Fatalf("IssueTokenPair failed: %v", err)
	}

	newAccess, newRefresh, err := mgr.RefreshAccessToken(refresh)
	if err != nil {
		t.Fatalf("RefreshAccessToken failed: %v", err)
	}
	if newAccess == "" || newRefresh == "" {
		t.Fatal("expected non-empty refreshed tokens")
	}

	claims, err := mgr.ValidateAccessToken(newAccess)
	if err != nil {
		t.Fatalf("validate new access failed: %v", err)
	}
	if claims.Sub != "user-1" {
		t.Errorf("expected user-1, got %s", claims.Sub)
	}

	_, _, err = mgr.RefreshAccessToken(refresh)
	if err == nil {
		t.Error("expected error reusing old refresh token")
	}
}

func TestJWTManagerRevoke(t *testing.T) {
	mgr := NewJWTManager([]byte("test-secret-key-for-jwt-testing!"))

	access, _, err := mgr.IssueTokenPair("user-1", RoleUser, "device-1")
	if err != nil {
		t.Fatalf("IssueTokenPair failed: %v", err)
	}

	mgr.RevokeAccessToken(access)

	_, err = mgr.ValidateAccessToken(access)
	if err == nil {
		t.Error("expected error for revoked token")
	}
}

func TestHasPermission(t *testing.T) {
	if !HasPermission(RoleAdmin, "anything.at.all") {
		t.Error("admin should have wildcard permission")
	}

	if !HasPermission(RoleOperator, "stats.read") {
		t.Error("operator should have stats.* permission")
	}

	if HasPermission(RoleUser, "stats.read") {
		t.Error("user should not have stats.read")
	}
}

func TestTokenTTL(t *testing.T) {
	if AccessTokenTTL != 30*time.Minute {
		t.Errorf("expected 30m access TTL, got %v", AccessTokenTTL)
	}
	if RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("expected 7d refresh TTL, got %v", RefreshTokenTTL)
	}
}
