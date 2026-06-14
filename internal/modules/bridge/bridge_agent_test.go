package bridge

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultAgentConfig(t *testing.T) {
	cfg := DefaultAgentConfig()
	if cfg.HeartbeatInterval != 30*time.Second {
		t.Errorf("expected 30s heartbeat, got %v", cfg.HeartbeatInterval)
	}
	if cfg.MetricsInterval != 60*time.Second {
		t.Errorf("expected 60s metrics, got %v", cfg.MetricsInterval)
	}
	if cfg.ConfigPollInterval != 5*time.Minute {
		t.Errorf("expected 5m config poll, got %v", cfg.ConfigPollInterval)
	}
}

func TestAgentConnectionTracking(t *testing.T) {
	agent := NewAgent(&AgentConfig{
		HeartbeatInterval:  1 * time.Hour,
		MetricsInterval:    1 * time.Hour,
		ConfigPollInterval: 1 * time.Hour,
	})

	agent.AddConnection()
	agent.AddConnection()
	agent.AddConnection()
	agent.RemoveConnection()

	conns := atomic.LoadInt64(&agent.connections)
	if conns != 2 {
		t.Errorf("expected 2 connections, got %d", conns)
	}
}

func TestAgentBytesTracking(t *testing.T) {
	agent := NewAgent(&AgentConfig{
		HeartbeatInterval:  1 * time.Hour,
		MetricsInterval:    1 * time.Hour,
		ConfigPollInterval: 1 * time.Hour,
	})

	agent.AddBytesIn(1024)
	agent.AddBytesIn(2048)
	agent.AddBytesOut(512)

	in := atomic.LoadInt64(&agent.bytesIn)
	out := atomic.LoadInt64(&agent.bytesOut)

	if in != 3072 {
		t.Errorf("expected 3072 bytes in, got %d", in)
	}
	if out != 512 {
		t.Errorf("expected 512 bytes out, got %d", out)
	}
}

func TestAgentCollectMetrics(t *testing.T) {
	agent := NewAgent(&AgentConfig{
		HeartbeatInterval:  1 * time.Hour,
		MetricsInterval:    1 * time.Hour,
		ConfigPollInterval: 1 * time.Hour,
	})

	agent.AddConnection()
	agent.AddBytesIn(1000)
	agent.AddBytesOut(500)

	metrics := agent.collectMetrics()
	if metrics.Connections != 1 {
		t.Errorf("expected 1 connection, got %d", metrics.Connections)
	}
	if metrics.BytesIn != 1000 {
		t.Errorf("expected 1000 bytes in, got %d", metrics.BytesIn)
	}
	if metrics.Goroutines <= 0 {
		t.Error("expected positive goroutine count")
	}
	if metrics.Uptime < 0 {
		t.Error("expected non-negative uptime")
	}
}

func TestAgentHeartbeat(t *testing.T) {
	var received bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/bridge-heartbeat" {
			received = true
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			if body["id"] != "test-bridge" {
				t.Errorf("expected bridge id 'test-bridge', got %v", body["id"])
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		}
	}))
	defer server.Close()

	agent := NewAgent(&AgentConfig{
		BridgeID:           "test-bridge",
		UpstreamServer:     server.Listener.Addr().String(),
		HeartbeatInterval:  1 * time.Hour,
		MetricsInterval:    1 * time.Hour,
		ConfigPollInterval: 1 * time.Hour,
	})
	agent.client = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	agent.sendHeartbeat()
	if !received {
		t.Error("heartbeat not received by server")
	}
}

func TestAgentConfigUpdateCallback(t *testing.T) {
	var callbackCalled bool
	var callbackConfig map[string]interface{}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":        true,
			"has_update":     true,
			"config_version": "v2",
			"config":         map[string]interface{}{"key": "value"},
		})
	}))
	defer server.Close()

	agent := NewAgent(&AgentConfig{
		BridgeID:           "test",
		UpstreamServer:     server.Listener.Addr().String(),
		HeartbeatInterval:  1 * time.Hour,
		MetricsInterval:    1 * time.Hour,
		ConfigPollInterval: 1 * time.Hour,
	})
	agent.client = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	agent.OnConfigUpdate(func(cfg map[string]interface{}) {
		callbackCalled = true
		callbackConfig = cfg
	})

	agent.pollConfig()

	if !callbackCalled {
		t.Error("config update callback not called")
	}
	if callbackConfig["key"] != "value" {
		t.Errorf("unexpected config: %v", callbackConfig)
	}
	if agent.configVersion != "v2" {
		t.Errorf("expected config version v2, got %s", agent.configVersion)
	}
}

func TestAgentStartStop(t *testing.T) {
	agent := NewAgent(&AgentConfig{
		BridgeID:           "test",
		UpstreamServer:     "127.0.0.1:1",
		HeartbeatInterval:  100 * time.Millisecond,
		MetricsInterval:    100 * time.Millisecond,
		ConfigPollInterval: 100 * time.Millisecond,
	})
	agent.Start()
	time.Sleep(50 * time.Millisecond)
	agent.Stop()
}
