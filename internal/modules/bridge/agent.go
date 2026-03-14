package bridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type AgentConfig struct {
	BridgeID          string        `yaml:"bridge_id"`
	UpstreamServer    string        `yaml:"upstream_server"`
	RegistrationToken string        `yaml:"registration_token"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	MetricsInterval   time.Duration `yaml:"metrics_interval"`
	ConfigPollInterval time.Duration `yaml:"config_poll_interval"`
}

func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		HeartbeatInterval:  30 * time.Second,
		MetricsInterval:    60 * time.Second,
		ConfigPollInterval: 5 * time.Minute,
	}
}

type AgentMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryMB     uint64  `json:"memory_mb"`
	MemoryPercent float64 `json:"memory_percent"`
	Goroutines   int     `json:"goroutines"`
	Connections  int64   `json:"connections"`
	BytesIn      int64   `json:"bytes_in"`
	BytesOut     int64   `json:"bytes_out"`
	Uptime       int64   `json:"uptime_seconds"`
	BandwidthIn  int64   `json:"bandwidth_in_bps"`
	BandwidthOut int64   `json:"bandwidth_out_bps"`
}

type Agent struct {
	config  *AgentConfig
	client  *http.Client
	startAt time.Time
	stopCh  chan struct{}
	wg      sync.WaitGroup

	connections int64
	bytesIn     int64
	bytesOut    int64
	prevIn      int64
	prevOut     int64
	bwIn        int64
	bwOut       int64

	configVersion string

	onConfigUpdate func(map[string]interface{})
	onAlert        func(alertType, message string)
}

func NewAgent(cfg *AgentConfig) *Agent {
	if cfg == nil {
		cfg = DefaultAgentConfig()
	}
	return &Agent{
		config:  cfg,
		client:  &http.Client{Timeout: 15 * time.Second},
		startAt: time.Now(),
		stopCh:  make(chan struct{}),
	}
}

func (a *Agent) OnConfigUpdate(fn func(map[string]interface{})) { a.onConfigUpdate = fn }
func (a *Agent) OnAlert(fn func(string, string))                { a.onAlert = fn }

func (a *Agent) AddConnection()    { atomic.AddInt64(&a.connections, 1) }
func (a *Agent) RemoveConnection() { atomic.AddInt64(&a.connections, -1) }
func (a *Agent) AddBytesIn(n int64)  { atomic.AddInt64(&a.bytesIn, n) }
func (a *Agent) AddBytesOut(n int64) { atomic.AddInt64(&a.bytesOut, n) }

func (a *Agent) Start() {
	a.wg.Add(3)
	go a.heartbeatLoop()
	go a.metricsLoop()
	go a.configPollLoop()
	log.Printf("Bridge agent started (id=%s)", a.config.BridgeID)
}

func (a *Agent) Stop() {
	close(a.stopCh)
	a.wg.Wait()
	log.Printf("Bridge agent stopped")
}

func (a *Agent) heartbeatLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.config.HeartbeatInterval)
	defer ticker.Stop()

	a.sendHeartbeat()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.sendHeartbeat()
		}
	}
}

func (a *Agent) metricsLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.config.MetricsInterval)
	defer ticker.Stop()

	bwTicker := time.NewTicker(10 * time.Second)
	defer bwTicker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-bwTicker.C:
			curIn := atomic.LoadInt64(&a.bytesIn)
			curOut := atomic.LoadInt64(&a.bytesOut)
			atomic.StoreInt64(&a.bwIn, (curIn-a.prevIn)*8/10)
			atomic.StoreInt64(&a.bwOut, (curOut-a.prevOut)*8/10)
			a.prevIn = curIn
			a.prevOut = curOut
		case <-ticker.C:
			a.sendMetrics()
		}
	}
}

func (a *Agent) configPollLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.config.ConfigPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.pollConfig()
		}
	}
}

func (a *Agent) collectMetrics() *AgentMetrics {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	return &AgentMetrics{
		MemoryMB:     ms.Alloc / 1024 / 1024,
		Goroutines:   runtime.NumGoroutine(),
		Connections:  atomic.LoadInt64(&a.connections),
		BytesIn:      atomic.LoadInt64(&a.bytesIn),
		BytesOut:     atomic.LoadInt64(&a.bytesOut),
		Uptime:       int64(time.Since(a.startAt).Seconds()),
		BandwidthIn:  atomic.LoadInt64(&a.bwIn),
		BandwidthOut: atomic.LoadInt64(&a.bwOut),
	}
}

func (a *Agent) sendHeartbeat() {
	metrics := a.collectMetrics()
	body := map[string]interface{}{
		"id":             a.config.BridgeID,
		"token":          a.config.RegistrationToken,
		"load":           metrics.CPUPercent,
		"current_users":  metrics.Connections,
		"version":        getVersion(),
		"uptime":         metrics.Uptime,
		"bandwidth_in":   metrics.BandwidthIn,
		"bandwidth_out":  metrics.BandwidthOut,
		"config_version": a.configVersion,
	}

	resp, err := a.post("/api/bridge-heartbeat", body)
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		if a.onAlert != nil {
			a.onAlert("heartbeat_failed", err.Error())
		}
		return
	}

	var result struct {
		Success      bool     `json:"success"`
		SSHKeys      []string `json:"ssh_keys"`
		ConfigVersion string  `json:"config_version"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
}

func (a *Agent) sendMetrics() {
	metrics := a.collectMetrics()
	body := map[string]interface{}{
		"bridge_id": a.config.BridgeID,
		"token":     a.config.RegistrationToken,
		"metrics":   metrics,
		"timestamp": time.Now().Unix(),
	}
	resp, err := a.post("/api/bridge-metrics", body)
	if err != nil {
		log.Printf("Metrics send failed: %v", err)
		return
	}
	resp.Body.Close()
}

func (a *Agent) pollConfig() {
	body := map[string]interface{}{
		"bridge_id":      a.config.BridgeID,
		"token":          a.config.RegistrationToken,
		"config_version": a.configVersion,
	}
	resp, err := a.post("/api/bridge-config-poll", body)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Success       bool                   `json:"success"`
		HasUpdate     bool                   `json:"has_update"`
		ConfigVersion string                 `json:"config_version"`
		Config        map[string]interface{} `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	if result.HasUpdate && result.Config != nil {
		a.configVersion = result.ConfigVersion
		if a.onConfigUpdate != nil {
			a.onConfigUpdate(result.Config)
		}
		log.Printf("Config updated to version %s", result.ConfigVersion)
	}
}

func (a *Agent) post(path string, body interface{}) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://%s%s", a.config.UpstreamServer, path)
	resp, err := a.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		url = fmt.Sprintf("http://%s%s", a.config.UpstreamServer, path)
		resp, err = a.client.Post(url, "application/json", bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
	}

	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func getVersion() string {
	data, err := os.ReadFile("/etc/whispera/version")
	if err != nil {
		return "unknown"
	}
	return string(bytes.TrimSpace(data))
}
