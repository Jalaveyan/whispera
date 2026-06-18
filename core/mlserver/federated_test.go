package mlserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newTestServer(t *testing.T) (*MLServer, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{
		ListenAddr: ":0",
		DataDir:    filepath.Join(dir, "data"),
		ModelDir:   filepath.Join(dir, "models"),
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)
	return srv, ts
}

func mustGet(t *testing.T, url string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest %s: %v", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	return body
}

func mustPost(t *testing.T, url string, payload interface{}) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	if payload != nil {
		_ = json.NewEncoder(buf).Encode(payload)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, buf)
	if err != nil {
		t.Fatalf("NewRequest %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s: status %d body=%s", url, resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	return body
}

func TestFederatedRoundTrip(t *testing.T) {
	srv, ts := newTestServer(t)

	feedbacks := []struct {
		Transport string  `json:"transport"`
		Success   bool    `json:"success"`
		LatencyMs float64 `json:"latency_ms"`
	}{
		{"stealth-http", true, 120.0},
		{"stealth-http", true, 90.0},
		{"stealth-http", false, 5000.0},
		{"vkwebrtc", true, 200.0},
	}
	for i, f := range feedbacks {
		mustPost(t, ts.URL+"/feedback/connection", f)
		_ = i
	}
	if got := len(srv.transportStats); got != 2 {
		t.Fatalf("transportStats want 2, got %d", got)
	}

	exportBody := mustGet(t, ts.URL+"/federated/export")
	var exp struct {
		Transports map[string]TransportStats `json:"transports"`
		Model      interface{}               `json:"model"`
		Ts         int64                     `json:"ts"`
	}
	if err := json.Unmarshal(exportBody, &exp); err != nil {
		t.Fatalf("export decode: %v body=%s", err, exportBody)
	}
	if _, ok := exp.Transports["stealth-http"]; !ok {
		t.Fatalf("export: stealth-http missing, body=%s", exportBody)
	}
	if exp.Transports["stealth-http"].Total != 3 {
		t.Errorf("stealth-http.Total = %d want 3", exp.Transports["stealth-http"].Total)
	}
	if exp.Transports["stealth-http"].Fail != 1 {
		t.Errorf("stealth-http.Fail = %d want 1", exp.Transports["stealth-http"].Fail)
	}

	remote := map[string]*TransportStats{
		"stealth-http": {Success: 100, Fail: 0, Total: 100, TotalLatency: 5000, Count: 100},
	}
	mustPost(t, ts.URL+"/federated/import", map[string]interface{}{"transports": remote})

	srv.feedbackMu.Lock()
	avgSuccess := srv.transportStats["stealth-http"].Success
	srv.feedbackMu.Unlock()
	if avgSuccess != 51 {
		t.Errorf("after federated import: stealth-http.Success = %d want 51", avgSuccess)
	}

	lossesBody := mustGet(t, ts.URL+"/federated/losses")
	var lossesResp struct {
		LocalLosses map[string]float64 `json:"local_losses"`
	}
	if err := json.Unmarshal(lossesBody, &lossesResp); err != nil {
		t.Fatalf("losses decode: %v body=%s", err, lossesBody)
	}
	if _, ok := lossesResp.LocalLosses["stealth-http"]; !ok {
		t.Fatalf("losses: stealth-http missing, body=%s", lossesBody)
	}
	if lossesResp.LocalLosses["stealth-http"] <= 0 {
		t.Errorf("stealth-http loss = %v should be > 0", lossesResp.LocalLosses["stealth-http"])
	}
}

func TestFederatedStatusEmpty(t *testing.T) {
	_, ts := newTestServer(t)
	body := mustGet(t, ts.URL+"/federated/status")
	var resp struct {
		Engine     string      `json:"engine"`
		Stats      interface{} `json:"stats"`
		Transports int         `json:"transports"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("status decode: %v body=%s", err, body)
	}
	if resp.Engine == "" {
		t.Errorf("engine name empty, body=%s", body)
	}
	if resp.Transports != 0 {
		t.Errorf("transports want 0, got %d", resp.Transports)
	}
}
