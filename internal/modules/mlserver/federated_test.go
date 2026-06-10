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

// newTestServer РїРѕРґРЅРёРјР°РµС‚ MLServer Р±РµР· СЃРµС‚Рё РЅР° in-memory mux Рё РІРѕР·РІСЂР°С‰Р°РµС‚
// httptest.Server РґР»СЏ СѓРґРѕР±РЅС‹С… HTTP-РІС‹Р·РѕРІРѕРІ. Р‘РµР· TLS Рё Р±РµР· auth-token.
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
	// New() СѓР¶Рµ РІС‹Р·С‹РІР°РµС‚ registerRoutes(); РїРѕРІС‚РѕСЂРЅС‹Р№ РІС‹Р·РѕРІ РїР°РЅРєРЅРµС‚ РЅР° ServeMux dup.
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

// РџРѕР»РЅС‹Р№ happy-path:
//   feedback Г— N в†’ /federated/export (РІРёРґРёС‚ stats) в†’ /federated/import
//   (СѓСЃСЂРµРґРЅРёР») в†’ /federated/losses (РІРёРґРёС‚ loss).
// Р•СЃР»Рё РєР°РєРѕР№-С‚Рѕ РёР· endpoints РІРѕР·РІСЂР°С‰Р°РµС‚ РїСѓСЃС‚РѕС‚Сѓ/РѕС€РёР±РєСѓ вЂ” СЃС‚Р°РЅРѕРІРёС‚СЃСЏ РїРѕРЅСЏС‚РЅРѕ
// РєР°РєРѕР№ РёРјРµРЅРЅРѕ СЃР»РѕРјР°РЅ Рё user СЃСЂР°Р·Сѓ РІРёРґРёС‚ СЌС‚РѕС‚ С‚РµСЃС‚ РІ CI.
func TestFederatedRoundTrip(t *testing.T) {
	srv, ts := newTestServer(t)

	// 1. РџРѕРґСЃС‹РїР°РµРј feedback РґР»СЏ РґРІСѓС… transport'РѕРІ.
	feedbacks := []struct {
		Transport  string  `json:"transport"`
		Success    bool    `json:"success"`
		LatencyMs  float64 `json:"latency_ms"`
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

	// 2. Export вЂ” РґРѕР»Р¶РµРЅ СЃРѕРґРµСЂР¶Р°С‚СЊ РѕР±Рµ transport'Р°.
	exportBody := mustGet(t, ts.URL+"/federated/export")
	var exp struct {
		Transports map[string]TransportStats `json:"transports"`
		Model      interface{}                `json:"model"`
		Ts         int64                      `json:"ts"`
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

	// 3. Import вЂ” РѕС‚РґР°С‘Рј 'remote' РїРѕР»РѕРІРёРЅСѓ. РџРѕСЃР»Рµ import local РґРѕР»Р¶РµРЅ СѓСЃСЂРµРґРЅРёС‚СЊ.
	remote := map[string]*TransportStats{
		"stealth-http": {Success: 100, Fail: 0, Total: 100, TotalLatency: 5000, Count: 100},
	}
	mustPost(t, ts.URL+"/federated/import", map[string]interface{}{"transports": remote})

	srv.feedbackMu.Lock()
	avgSuccess := srv.transportStats["stealth-http"].Success
	srv.feedbackMu.Unlock()
	// local Success Р±С‹Р»Рѕ 2, remote 100 в†’ avg = 51.
	if avgSuccess != 51 {
		t.Errorf("after federated import: stealth-http.Success = %d want 51", avgSuccess)
	}

	// 4. Losses вЂ” РґР»СЏ stealth-http РґРѕР»Р¶РЅРѕ Р±С‹С‚СЊ >0 (1 fail РёР· 3).
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
