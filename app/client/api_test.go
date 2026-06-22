package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleAuthReturnsSocksCreds(t *testing.T) {
	origUser, origPass := socksUser, socksPass
	socksUser, socksPass = "testuser", "testpass"
	defer func() { socksUser, socksPass = origUser, origPass }()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth", nil)
	w := httptest.NewRecorder()

	handleAuth(w, req)

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["username"] != "testuser" || body["password"] != "testpass" {
		t.Errorf("handleAuth() = %v, want username=testuser password=testpass", body)
	}
}

func TestHandleConnectionsEmptyPool(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/connections", nil)
	w := httptest.NewRecorder()

	handleConnections(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var views []entryView
	if err := json.NewDecoder(w.Body).Decode(&views); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func TestHandleConnectionActionUnknownID(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/connections/does-not-exist/close", nil)
	w := httptest.NewRecorder()

	handleConnectionAction(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleConnectionActionBadPath(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/connections/onlyid", nil)
	w := httptest.NewRecorder()

	handleConnectionAction(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleConnCloseDisablesEntry(t *testing.T) {
	entry := &TransportEntry{ID: pool.NextID(), Status: connStatusConnected, Enabled: true}
	pool.Add(entry)

	w := httptest.NewRecorder()
	handleConnClose(w, entry)

	entry.mu.Lock()
	enabled, status := entry.Enabled, entry.Status
	entry.mu.Unlock()

	if enabled {
		t.Error("handleConnClose() left entry.Enabled = true, want false")
	}
	if status != connStatusDisconnected {
		t.Errorf("handleConnClose() entry.Status = %v, want %v", status, connStatusDisconnected)
	}
}

func TestHandleRegionGet(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/region", nil)
	w := httptest.NewRecorder()

	handleRegion(w, req)

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := body["region"]; !ok {
		t.Errorf("handleRegion() response missing \"region\" key: %v", body)
	}
}
