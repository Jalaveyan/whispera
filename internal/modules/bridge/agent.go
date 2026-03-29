package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/ml/gnet"
)

type AgentConfig struct {
	BridgeID           string        `yaml:"bridge_id"`
	UpstreamServer     string        `yaml:"upstream_server"`
	RegistrationToken  string        `yaml:"registration_token"`
	HeartbeatInterval  time.Duration `yaml:"heartbeat_interval"`
	MetricsInterval    time.Duration `yaml:"metrics_interval"`
	ConfigPollInterval time.Duration `yaml:"config_poll_interval"`

	MLServerURL        string        `yaml:"ml_server_url"`
	MLSyncInterval     time.Duration `yaml:"ml_sync_interval"`

	SelfAddress string `yaml:"self_address"`
	ClusterListenAddr string `yaml:"cluster_listen_addr"`
	PeerAddresses []string `yaml:"peer_addresses"`
}

func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		HeartbeatInterval:  30 * time.Second,
		MetricsInterval:    60 * time.Second,
		ConfigPollInterval: 5 * time.Minute,
		MLSyncInterval:     10 * time.Minute,
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

const (
	miniInputSize      = 16
	miniHiddenSize     = 24
	miniTrafficClasses = 5
	miniDPIClasses     = 4
	miniTransportOut   = 8
)

type mlPrediction struct {
	ClassID    int     `json:"class_id"`
	Confidence float64 `json:"confidence"`
	DPIType    int     `json:"dpi_type"`
}

type mlRecommendation struct {
	Transport  string  `json:"transport"`
	Confidence float64 `json:"confidence"`
}

type peerBridge struct {
	ID      string
	Address string
	Latency int
	Alive   bool
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

	mlToken      string
	mlClient     *http.Client
	trafficNet   *gnet.GorgoniaNet
	dpiNet       *gnet.GorgoniaNet
	transportNet *gnet.GorgoniaNet
	mlMu       sync.RWMutex
	mlReady    int32

	trafficSamples []trafficSample
	sampleMu       sync.Mutex
	maxSamples     int

	peerMu      sync.RWMutex
	peers       []*peerBridge
	masterID    string
	masterAddr  string
	masterTerm  uint64
	electedAt   time.Time

	onConfigUpdate func(map[string]interface{})
	onAlert        func(alertType, message string)
}

type trafficSample struct {
	Features []float64 `json:"features"`
	ClassID  int       `json:"class_id"`
	DPIType  int       `json:"dpi_type"`
	TS       int64     `json:"ts"`
}

func NewAgent(cfg *AgentConfig) *Agent {
	if cfg == nil {
		cfg = DefaultAgentConfig()
	}
	a := &Agent{
		config:  cfg,
		client:  &http.Client{Timeout: 15 * time.Second},
		mlClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		startAt:    time.Now(),
		stopCh:     make(chan struct{}),
		maxSamples: 500,
	}
	a.initMiniNets()
	return a
}

func (a *Agent) OnConfigUpdate(fn func(map[string]interface{})) { a.onConfigUpdate = fn }
func (a *Agent) OnAlert(fn func(string, string))                { a.onAlert = fn }

func (a *Agent) AddConnection()    { atomic.AddInt64(&a.connections, 1) }
func (a *Agent) RemoveConnection() { atomic.AddInt64(&a.connections, -1) }
func (a *Agent) AddBytesIn(n int64)  { atomic.AddInt64(&a.bytesIn, n) }
func (a *Agent) AddBytesOut(n int64) { atomic.AddInt64(&a.bytesOut, n) }

func (a *Agent) Start() {
	if len(a.config.PeerAddresses) > 0 {
		a.peerMu.Lock()
		for _, addr := range a.config.PeerAddresses {
			a.peers = append(a.peers, &peerBridge{ID: addr, Address: addr})
		}
		a.peerMu.Unlock()
	}

	a.wg.Add(4)
	go a.heartbeatLoop()
	go a.metricsLoop()
	go a.configPollLoop()
	go a.peerElectionLoop()

	if a.config.MLServerURL != "" {
		a.wg.Add(1)
		go a.mlSyncLoop()
	}

	if a.config.ClusterListenAddr != "" {
		go a.serveClusterHTTP(a.config.ClusterListenAddr)
	}

	log.Printf("Bridge agent started (id=%s)", a.config.BridgeID)
}

func (a *Agent) Stop() {
	close(a.stopCh)
	a.wg.Wait()
	log.Printf("Bridge agent stopped")
}

func (a *Agent) SendAlert(alertType, message string) {
	body := map[string]interface{}{
		"bridge_id":  a.config.BridgeID,
		"token":      a.config.RegistrationToken,
		"alert_type": alertType,
		"message":    message,
		"timestamp":  fmt.Sprintf("%d", time.Now().Unix()),
	}
	resp, err := a.post("/api/bridge-alert", body)
	if err != nil {
		log.Printf("Alert send failed (%s): %v", alertType, err)
		return
	}
	resp.Body.Close()
}

func (a *Agent) initMiniNets() {
	a.trafficNet = gnet.New([]int{miniInputSize, miniHiddenSize, miniTrafficClasses})
	a.dpiNet = gnet.New([]int{miniInputSize, miniHiddenSize, miniDPIClasses})
	a.transportNet = gnet.New([]int{miniInputSize, miniHiddenSize, miniTransportOut})
	atomic.StoreInt32(&a.mlReady, 1)
}

func softmax(x []float64) []float64 {
	maxVal := x[0]
	for _, v := range x[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	out := make([]float64, len(x))
	sum := 0.0
	for i, v := range x {
		out[i] = math.Exp(v - maxVal)
		sum += out[i]
	}
	if sum > 0 {
		for i := range out {
			out[i] /= sum
		}
	}
	return out
}

func argmax(x []float64) (int, float64) {
	best := 0
	bestVal := x[0]
	for i, v := range x[1:] {
		if v > bestVal {
			bestVal = v
			best = i + 1
		}
	}
	return best, bestVal
}

func (a *Agent) ExtractFeatures(data []byte) []float64 {
	f := make([]float64, miniInputSize)
	if len(data) == 0 {
		return f
	}

	f[0] = float64(len(data)) / 1500.0

	entropy := 0.0
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			entropy -= p * math.Log2(p)
		}
	}
	f[1] = entropy / 8.0

	printable := 0
	for _, b := range data {
		if b >= 32 && b <= 126 {
			printable++
		}
	}
	f[2] = float64(printable) / n

	if len(data) >= 3 {
		f[3] = float64(data[0]) / 255.0
		f[4] = float64(data[1]) / 255.0
		f[5] = float64(data[2]) / 255.0
	}

	if len(data) >= 2 && data[0] == 0x16 && data[1] == 0x03 {
		f[6] = 1.0
	}
	if len(data) >= 4 && string(data[:4]) == "HTTP" {
		f[7] = 1.0
	}
	if len(data) >= 4 && string(data[:4]) == "GET " {
		f[7] = 0.8
	}
	if len(data) >= 5 && string(data[:5]) == "POST " {
		f[7] = 0.9
	}
	if len(data) >= 4 && string(data[:4]) == "SSH-" {
		f[8] = 1.0
	}
	if len(data) >= 2 && data[0] == 0x00 && data[1] <= 64 {
		f[9] = 1.0
	}

	var sum, sumSq float64
	limit := len(data)
	if limit > 256 {
		limit = 256
	}
	for _, b := range data[:limit] {
		v := float64(b)
		sum += v
		sumSq += v * v
	}
	mean := sum / float64(limit)
	variance := sumSq/float64(limit) - mean*mean
	f[10] = mean / 255.0
	f[11] = math.Sqrt(math.Abs(variance)) / 128.0

	chiSq := 0.0
	expected := n / 256.0
	for _, c := range freq {
		diff := float64(c) - expected
		chiSq += diff * diff / expected
	}
	f[12] = math.Min(chiSq/1000.0, 1.0)

	uniq := 0
	for _, c := range freq {
		if c > 0 {
			uniq++
		}
	}
	f[13] = float64(uniq) / 256.0

	runs := 1
	if len(data) > 1 {
		for i := 1; i < len(data) && i < 256; i++ {
			if data[i] != data[i-1] {
				runs++
			}
		}
	}
	f[14] = float64(runs) / float64(limit)

	zeros := 0
	for _, b := range data {
		if b == 0 {
			zeros++
		}
	}
	f[15] = float64(zeros) / n

	return f
}

func (a *Agent) ClassifyTraffic(data []byte) *mlPrediction {
	if atomic.LoadInt32(&a.mlReady) == 0 {
		return nil
	}
	features := a.ExtractFeatures(data)
	a.mlMu.RLock()
	rawTraffic := a.trafficNet.Forward(features)
	rawDPI := a.dpiNet.Forward(features)
	a.mlMu.RUnlock()

	probs := softmax(rawTraffic)
	classID, confidence := argmax(probs)

	dpiProbs := softmax(rawDPI)
	dpiType, _ := argmax(dpiProbs)

	a.recordSample(features, classID, dpiType)

	return &mlPrediction{
		ClassID:    classID,
		Confidence: confidence,
		DPIType:    dpiType,
	}
}

func (a *Agent) RecommendTransport() *mlRecommendation {
	if atomic.LoadInt32(&a.mlReady) == 0 {
		return nil
	}

	features := make([]float64, miniInputSize)
	metrics := a.collectMetrics()
	features[0] = float64(metrics.Connections) / 100.0
	features[1] = float64(metrics.BandwidthIn) / 1e9
	features[2] = float64(metrics.BandwidthOut) / 1e9
	features[3] = float64(metrics.MemoryMB) / 1024.0
	features[4] = float64(metrics.Goroutines) / 1000.0
	features[5] = float64(metrics.Uptime) / 86400.0

	a.sampleMu.Lock()
	nSamples := len(a.trafficSamples)
	var avgDPI float64
	if nSamples > 0 {
		last := a.trafficSamples
		if len(last) > 20 {
			last = last[len(last)-20:]
		}
		for _, s := range last {
			avgDPI += float64(s.DPIType)
		}
		avgDPI /= float64(len(last))
	}
	a.sampleMu.Unlock()
	features[6] = avgDPI / 4.0
	features[7] = float64(nSamples) / float64(a.maxSamples)

	a.mlMu.RLock()
	raw := a.transportNet.Forward(features)
	a.mlMu.RUnlock()

	probs := softmax(raw)
	idx, confidence := argmax(probs)

	transports := []string{"tcp", "tls", "grpc", "http2", "noise_ik", "dtls", "vkwebrtc", "mirage"}
	transport := "tcp"
	if idx < len(transports) {
		transport = transports[idx]
	}

	return &mlRecommendation{
		Transport:  transport,
		Confidence: confidence,
	}
}

func (a *Agent) recordSample(features []float64, classID, dpiType int) {
	a.sampleMu.Lock()
	defer a.sampleMu.Unlock()
	if len(a.trafficSamples) >= a.maxSamples {
		a.trafficSamples = a.trafficSamples[1:]
	}
	a.trafficSamples = append(a.trafficSamples, trafficSample{
		Features: features,
		ClassID:  classID,
		DPIType:  dpiType,
		TS:       time.Now().Unix(),
	})
}

func (a *Agent) mlSyncLoop() {
	defer a.wg.Done()

	a.fetchMLToken()
	a.syncMLWeights()

	interval := a.config.MLSyncInterval
	if interval == 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.syncMLWeights()
			a.uploadSamples()
		}
	}
}

func (a *Agent) fetchMLToken() {
	body := map[string]interface{}{
		"bridge_id": a.config.BridgeID,
		"token":     a.config.RegistrationToken,
	}

	resp, err := a.post("/api/ml/config", body)
	if err != nil {
		log.Printf("ML token fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Token     string `json:"token"`
		ServerURL string `json:"server_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	a.mlMu.Lock()
	a.mlToken = result.Token
	if result.ServerURL != "" {
		a.config.MLServerURL = result.ServerURL
	}
	a.mlMu.Unlock()

	log.Printf("ML token acquired from upstream")
}

func (a *Agent) mlPost(path string, body interface{}) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	a.mlMu.RLock()
	mlURL := a.config.MLServerURL
	token := a.mlToken
	a.mlMu.RUnlock()

	if mlURL == "" {
		return nil, fmt.Errorf("ML server URL not configured")
	}

	url := fmt.Sprintf("https://%s%s", mlURL, path)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.mlClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ML HTTPS request failed: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		a.fetchMLToken()
		return nil, fmt.Errorf("ML 401 unauthorized, token refreshed")
	}

	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("ML HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func (a *Agent) mlGet(path string) (*http.Response, error) {
	a.mlMu.RLock()
	mlURL := a.config.MLServerURL
	token := a.mlToken
	a.mlMu.RUnlock()

	if mlURL == "" {
		return nil, fmt.Errorf("ML server URL not configured")
	}

	url := fmt.Sprintf("https://%s%s", mlURL, path)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.mlClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ML HTTPS request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("ML HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func (a *Agent) syncMLWeights() {
	resp, err := a.mlGet("/federated/download")
	if err != nil {
		log.Printf("ML weights sync failed: %v", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Deltas []struct {
			Traffic   []gnet.LayerDef `json:"traffic"`
			DPI       []gnet.LayerDef `json:"dpi"`
			Transport []gnet.LayerDef `json:"transport"`
		} `json:"deltas"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	if len(result.Deltas) == 0 {
		return
	}

	a.mlMu.Lock()
	defer a.mlMu.Unlock()
	delta := result.Deltas[len(result.Deltas)-1]
	if len(delta.Traffic) > 0 {
		a.trafficNet.LoadWeights(delta.Traffic)
	}
	if len(delta.DPI) > 0 {
		a.dpiNet.LoadWeights(delta.DPI)
	}
	if len(delta.Transport) > 0 {
		a.transportNet.LoadWeights(delta.Transport)
	}
	log.Printf("ML weights synced from server")
}

func (a *Agent) uploadSamples() {
	a.sampleMu.Lock()
	if len(a.trafficSamples) == 0 {
		a.sampleMu.Unlock()
		return
	}
	samples := make([]trafficSample, len(a.trafficSamples))
	copy(samples, a.trafficSamples)
	a.trafficSamples = a.trafficSamples[:0]
	a.sampleMu.Unlock()

	body := map[string]interface{}{
		"bridge_id": a.config.BridgeID,
		"samples":   samples,
		"ts":        time.Now().Unix(),
	}
	resp, err := a.mlPost("/federated/upload", body)
	if err != nil {
		a.sampleMu.Lock()
		a.trafficSamples = append(samples, a.trafficSamples...)
		if len(a.trafficSamples) > a.maxSamples {
			a.trafficSamples = a.trafficSamples[:a.maxSamples]
		}
		a.sampleMu.Unlock()
		return
	}
	resp.Body.Close()
	log.Printf("ML samples uploaded: %d", len(samples))
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

	var mlInfo map[string]interface{}
	if rec := a.RecommendTransport(); rec != nil {
		mlInfo = map[string]interface{}{
			"recommended_transport": rec.Transport,
			"confidence":            rec.Confidence,
			"samples_collected":     len(a.trafficSamples),
			"ml_ready":              atomic.LoadInt32(&a.mlReady) == 1,
		}
	}

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
		"ml":             mlInfo,
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
		Success       bool     `json:"success"`
		SSHKeys       []string `json:"ssh_keys"`
		ConfigVersion string   `json:"config_version"`
		MLServerURL   string   `json:"ml_server_url"`
		MLToken       string   `json:"ml_token"`
		Peers         []struct {
			ID      string `json:"id"`
			Address string `json:"address"`
		} `json:"peers"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()

	if result.MLServerURL != "" {
		a.mlMu.Lock()
		a.config.MLServerURL = result.MLServerURL
		a.mlMu.Unlock()
	}
	if result.MLToken != "" {
		a.mlMu.Lock()
		a.mlToken = result.MLToken
		a.mlMu.Unlock()
	}
	if len(result.Peers) > 0 {
		a.peerMu.Lock()
		known := make(map[string]*peerBridge, len(a.peers))
		for _, p := range a.peers {
			known[p.Address] = p
		}
		updated := make([]*peerBridge, 0, len(result.Peers))
		for _, rp := range result.Peers {
			if rp.Address == a.config.SelfAddress {
				continue
			}
			if existing, ok := known[rp.Address]; ok {
				existing.ID = rp.ID
				updated = append(updated, existing)
			} else {
				updated = append(updated, &peerBridge{ID: rp.ID, Address: rp.Address})
			}
		}
		a.peers = updated
		a.peerMu.Unlock()
	}
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
	req1, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))
	req1.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req1)
	if err != nil {
		return nil, fmt.Errorf("HTTPS request failed (HTTP fallback disabled): %w", err)
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

func (a *Agent) peerElectionLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.pingPeers()
			a.runPeerElection()
		}
	}
}

func (a *Agent) pingPeers() {
	a.peerMu.RLock()
	peers := make([]*peerBridge, len(a.peers))
	copy(peers, a.peers)
	a.peerMu.RUnlock()

	if len(peers) == 0 {
		return
	}

	type result struct {
		peer    *peerBridge
		latency int
		alive   bool
	}
	ch := make(chan result, len(peers))
	for _, p := range peers {
		go func(pb *peerBridge) {
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "GET", "http://"+pb.Address+"/cluster/ping", nil)
			if err != nil {
				ch <- result{peer: pb, alive: false}
				return
			}
			resp, err := a.client.Do(req)
			if err != nil {
				ch <- result{peer: pb, alive: false}
				return
			}
			resp.Body.Close()
			ch <- result{peer: pb, latency: int(time.Since(start).Milliseconds()), alive: resp.StatusCode < 500}
		}(p)
	}

	for range peers {
		r := <-ch
		a.peerMu.Lock()
		r.peer.Alive = r.alive
		if r.alive {
			r.peer.Latency = r.latency
		}
		a.peerMu.Unlock()
	}
}

func (a *Agent) runPeerElection() {
	type candidate struct {
		id      string
		address string
		latency int
	}

	candidates := []candidate{{
		id:      a.config.BridgeID,
		address: a.config.SelfAddress,
		latency: 0,
	}}

	a.peerMu.RLock()
	for _, p := range a.peers {
		if p.Alive {
			candidates = append(candidates, candidate{
				id:      p.ID,
				address: p.Address,
				latency: p.Latency,
			})
		}
	}
	a.peerMu.RUnlock()

	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0; j-- {
			ci, cj := candidates[j], candidates[j-1]
			if ci.latency < cj.latency || (ci.latency == cj.latency && ci.id < cj.id) {
				candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
			}
		}
	}

	elected := candidates[0]
	a.peerMu.Lock()
	if a.masterID != elected.id {
		a.masterTerm++
		a.electedAt = time.Now()
		log.Printf("Peer election: new master %s @ %s (term %d)", elected.id, elected.address, a.masterTerm)
	}
	a.masterID = elected.id
	a.masterAddr = elected.address
	a.peerMu.Unlock()
}

type ClusterMasterStatus struct {
	MasterID      string    `json:"master_id"`
	MasterAddress string    `json:"master_address"`
	Term          uint64    `json:"term"`
	ElectedAt     time.Time `json:"elected_at"`
	SelfID        string    `json:"self_id"`
}

func (a *Agent) clusterMasterStatus() ClusterMasterStatus {
	a.peerMu.RLock()
	defer a.peerMu.RUnlock()
	return ClusterMasterStatus{
		MasterID:      a.masterID,
		MasterAddress: a.masterAddr,
		Term:          a.masterTerm,
		ElectedAt:     a.electedAt,
		SelfID:        a.config.BridgeID,
	}
}

func (a *Agent) serveClusterHTTP(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/master", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(a.clusterMasterStatus())
	})
	mux.HandleFunc("/cluster/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"alive":true}`, a.config.BridgeID)
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("Bridge cluster HTTP listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Cluster HTTP server error: %v", err)
	}
}
