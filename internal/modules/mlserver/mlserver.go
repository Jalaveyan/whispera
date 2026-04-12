package mlserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/obfuscation/ml"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "mlserver"
	ModuleVersion = "2.0.0"
)

var log = logger.Module("mlserver")

type MLServer struct {
	*base.Module
	engine     *ml.NativeMLEngine
	httpServer *http.Server
	mux        *http.ServeMux
	listenAddr string
	tlsCert    string
	tlsKey     string
	token      string
	dataDir    string

	feedbackMu     sync.Mutex
	transportStats map[string]*TransportStats
	fedDir         string

	adversarial *evasion.AdversarialEngine

	logLines []string
	logMu    sync.Mutex
	maxLogs  int
}

type TransportStats struct {
	Success      int64   `json:"success"`
	Fail         int64   `json:"fail"`
	Total        int64   `json:"total"`
	TotalLatency float64 `json:"total_latency"`
	Count        int64   `json:"count"`
}

type Config struct {
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`
	TLSCert    string `yaml:"tls_cert" json:"tls_cert"`
	TLSKey     string `yaml:"tls_key" json:"tls_key"`
	Token      string `yaml:"token" json:"token"`
	DataDir    string `yaml:"data_dir" json:"data_dir"`
	ModelDir   string `yaml:"model_dir" json:"model_dir"`
}

func New(cfg interface{}) (*MLServer, error) {
	var conf Config
	if c, ok := cfg.(*Config); ok && c != nil {
		conf = *c
	}
	conf.ListenAddr = strings.TrimPrefix(conf.ListenAddr, "https://")
	conf.ListenAddr = strings.TrimPrefix(conf.ListenAddr, "http://")
	if conf.ListenAddr == "" {
		conf.ListenAddr = ":8000"
	}
	if conf.DataDir == "" {
		conf.DataDir = "./ml_data"
	}
	if conf.ModelDir == "" {
		conf.ModelDir = "./ml_models"
	}

	os.MkdirAll(conf.DataDir, 0700)

	s := &MLServer{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		engine:         ml.GetNativeEngine(),
		mux:            http.NewServeMux(),
		listenAddr:     conf.ListenAddr,
		tlsCert:        conf.TLSCert,
		tlsKey:         conf.TLSKey,
		token:          conf.Token,
		dataDir:        conf.DataDir,
		transportStats: make(map[string]*TransportStats),
		fedDir:         filepath.Join(conf.DataDir, "federated"),
		adversarial:    evasion.NewAdversarialEngine(),
		maxLogs:        1000,
	}

	if s.engine == nil {
		s.engine = ml.NewNativeMLEngine(conf.ModelDir)
	}

	os.MkdirAll(s.fedDir, 0700)
	s.registerRoutes()
	return s, nil
}

func (s *MLServer) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	return s.Module.Init(ctx, cfg)
}

func (s *MLServer) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	s.httpServer = &http.Server{
		Handler:      s.authMiddleware(s.mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("ml server listen: %w", err)
	}

	if s.tlsCert != "" && s.tlsKey != "" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
		if err != nil {
			return fmt.Errorf("ml server tls load failed: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		tlsLn := tls.NewListener(ln, tlsCfg)
		go func() {
			serveErr := s.httpServer.Serve(tlsLn)
			if serveErr != nil && serveErr != http.ErrServerClosed {
				log.Printf("ml server error: %v", serveErr)
			}
		}()
		s.addLogf("ML server started on %s (HTTPS, native Go MLP engine)", s.listenAddr)
		log.Printf("ML server started on %s (HTTPS)", s.listenAddr)
	} else {
		go func() {
			serveErr := s.httpServer.Serve(ln)
			if serveErr != nil && serveErr != http.ErrServerClosed {
				log.Printf("ml server error: %v", serveErr)
			}
		}()
		s.addLogf("ML server started on %s (HTTP, native Go MLP engine)", s.listenAddr)
		log.Printf("ML server started on %s (HTTP)", s.listenAddr)
	}
	s.SetHealthy(true, "ml server running")
	return nil
}

func (s *MLServer) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
	}
	return s.Module.Stop()
}

func (s *MLServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if s.token != "" {
			auth := r.Header.Get("Authorization")
			if auth != "" {
				parts := strings.SplitN(auth, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") && parts[1] == s.token {
					next.ServeHTTP(w, r)
					return
				}
			}
			if r.URL.Path != "/health" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *MLServer) registerRoutes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /logs", s.handleLogs)
	s.mux.HandleFunc("POST /logs/clear", s.handleLogsClear)
	s.mux.HandleFunc("GET /models/status", s.handleModelsStatus)
	s.mux.HandleFunc("POST /models/load", s.handleModelsLoad)
	s.mux.HandleFunc("GET /self-learning/status", s.handleSelfLearningStatus)
	s.mux.HandleFunc("POST /predict/traffic", s.handlePredictTraffic)
	s.mux.HandleFunc("POST /rank/bridges", s.handleRankBridges)
	s.mux.HandleFunc("POST /network/analyze", s.handleNetworkAnalyze)
	s.mux.HandleFunc("POST /recommend/transport", s.handleRecommendTransport)
	s.mux.HandleFunc("POST /feedback/connection", s.handleFeedbackConnection)
	s.mux.HandleFunc("GET /feedback/stats", s.handleFeedbackStats)
	s.mux.HandleFunc("POST /train/start", s.handleTrainStart)
	s.mux.HandleFunc("POST /train/stop", s.handleTrainStop)
	s.mux.HandleFunc("GET /train/status", s.handleTrainStatus)
	s.mux.HandleFunc("GET /scan", s.handleScan)
	s.mux.HandleFunc("GET /federated/export", s.handleFedExport)
	s.mux.HandleFunc("POST /federated/import", s.handleFedImport)
	s.mux.HandleFunc("GET /federated/status", s.handleFedStatus)
	s.mux.HandleFunc("GET /federated/losses", s.handleFedLosses)
	s.mux.HandleFunc("POST /federated/upload", s.handleFedUpload)
	s.mux.HandleFunc("GET /federated/download", s.handleFedDownload)
	s.mux.HandleFunc("GET /federated/dataset", s.handleFedDatasetExport)
	s.mux.HandleFunc("GET /federated/dataset/stats", s.handleFedDatasetStats)
	s.mux.HandleFunc("GET /datasets", s.handleDatasetsList)
	s.mux.HandleFunc("POST /datasets/capture", s.handleDatasetsCapture)
	s.mux.HandleFunc("POST /datasets/upload", s.handleDatasetsUpload)
	s.mux.HandleFunc("POST /datasets/exchange", s.handleDatasetsExchange)
	s.mux.HandleFunc("GET /adversarial/status", s.handleAdversarialStatus)
	s.mux.HandleFunc("POST /adversarial/evolve", s.handleAdversarialEvolve)
	s.mux.HandleFunc("POST /adversarial/feedback", s.handleAdversarialFeedback)

	s.mux.HandleFunc("GET /tspu/stats", s.handleTSPUStats)
	s.mux.HandleFunc("POST /tspu/rst", s.handleTSPURST)
	s.mux.HandleFunc("POST /tspu/bandwidth", s.handleTSPUBandwidth)
}

func (s *MLServer) jsonReply(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *MLServer) addLogf(format string, args ...interface{}) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	s.logMu.Lock()
	s.logLines = append(s.logLines, line)
	if len(s.logLines) > s.maxLogs {
		s.logLines = s.logLines[len(s.logLines)-s.maxLogs:]
	}
	s.logMu.Unlock()
}

func (s *MLServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonReply(w, map[string]interface{}{
		"status":  "ok",
		"engine":  "native_mlp_go",
		"version": ModuleVersion,
	})
}

func (s *MLServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	n := 150
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			n = parsed
		}
	}
	s.logMu.Lock()
	lines := s.logLines
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]string, len(lines))
	copy(out, lines)
	s.logMu.Unlock()
	s.jsonReply(w, map[string]interface{}{"lines": out})
}

func (s *MLServer) handleLogsClear(w http.ResponseWriter, r *http.Request) {
	s.logMu.Lock()
	s.logLines = s.logLines[:0]
	s.logMu.Unlock()
	s.jsonReply(w, map[string]string{"status": "ok"})
}

func (s *MLServer) handleModelsStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.engine.GetStats()
	samples, _ := stats["samples"].(int64)
	retrains, _ := stats["retrains"].(int64)
	accuracy, _ := stats["accuracy"].(float64)
	isTrained := samples > 0 || retrains > 0 || accuracy > 0
	lastTrained, _ := stats["last_trained"].(int64)
	lastUpdated := time.Unix(lastTrained, 0).Format(time.RFC3339)
	if lastTrained == 0 {
		lastUpdated = ""
	}
	s.jsonReply(w, map[string]interface{}{
		"models": []map[string]interface{}{
			{
				"model_name":   "traffic_classifier",
				"is_trained":   isTrained,
				"accuracy":     accuracy,
				"last_updated": lastUpdated,
				"parameters":   stats["parameters"],
			},
		},
		"engine": "native_mlp_go",
		"stats":  stats,
	})
}

func (s *MLServer) handleModelsLoad(w http.ResponseWriter, r *http.Request) {
	s.addLogf("model reload requested")
	s.jsonReply(w, map[string]string{"status": "loaded"})
}

func (s *MLServer) handleSelfLearningStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.engine.GetStats()
	s.jsonReply(w, map[string]interface{}{
		"samples_collected": stats["samples"],
		"predictions_made":  stats["predictions"],
		"accuracy":          stats["accuracy"],
		"model":             stats["model"],
	})
}

func (s *MLServer) handlePredictTraffic(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data      []byte `json:"data"`
		Protocol  string `json:"protocol"`
		Direction string `json:"direction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	resp := s.engine.Predict(req.Data, req.Protocol, req.Direction)
	s.jsonReply(w, resp)
}

func (s *MLServer) handleRankBridges(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var bridges []map[string]interface{}
	if err := json.Unmarshal(body, &bridges); err != nil {
		var wrapped struct {
			Bridges []map[string]interface{} `json:"bridges"`
		}
		if err2 := json.Unmarshal(body, &wrapped); err2 != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		bridges = wrapped.Bridges
	}

	ranked := s.engine.RankBridges(bridges)

	for i := range ranked {
		if sc, ok := ranked[i]["score"].(float64); ok {
			ranked[i]["ml_score"] = sc
		}
		if rs, ok := ranked[i]["reason"].(string); ok {
			ranked[i]["ml_reason"] = rs
		}
	}

	s.jsonReply(w, ranked)
}

func (s *MLServer) handleNetworkAnalyze(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.Port == 0 {
		req.Port = 443
	}

	s.addLogf("network analysis: %s:%d", req.Host, req.Port)

	targets := []struct {
		host string
		port int
	}{
		{req.Host, req.Port},
		{"1.1.1.1", 443},
		{"8.8.8.8", 443},
		{"google.com", 443},
		{"cloudflare.com", 443},
	}

	type probeResult struct {
		reachable bool
		rtt       time.Duration
	}
	results := make([]probeResult, len(targets))

	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, host string, port int) {
			defer wg.Done()
			start := time.Now()
			conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil {
				results[idx] = probeResult{reachable: true, rtt: time.Since(start)}
				conn.Close()
			}
		}(i, t.host, t.port)
	}
	wg.Wait()

	reachable := 0
	var totalRTT time.Duration
	rttCount := 0
	for _, r := range results {
		if r.reachable {
			reachable++
			totalRTT += r.rtt
			rttCount++
		}
	}

	var avgRTT *float64
	if rttCount > 0 {
		v := float64(totalRTT.Milliseconds()) / float64(rttCount)
		avgRTT = &v
	}

	dpiRisk := "low"
	if !results[0].reachable {
		dpiRisk = "critical"
	} else if reachable < 3 {
		dpiRisk = "high"
	} else if avgRTT != nil && *avgRTT > 500 {
		dpiRisk = "medium"
	}

	resp := map[string]interface{}{
		"dpi_risk":              dpiRisk,
		"avg_rtt_ms":            avgRTT,
		"reachable":             reachable,
		"total_probed":          len(targets),
		"recommended_transport": "tcp",
		"recommended_reason":    "direct connection available",
	}

	switch dpiRisk {
	case "critical":
		resp["recommended_transport"] = "vkwebrtc"
		resp["recommended_reason"] = "target unreachable, use WebRTC relay"
	case "high":
		resp["recommended_transport"] = "mirage"
		resp["recommended_reason"] = "significant blocking detected, use SNI bypass"
	case "medium":
		resp["recommended_transport"] = "meek"
		resp["recommended_reason"] = "some throttling detected, use domain fronting"
	}

	s.addLogf("analysis: dpi=%s reachable=%d/%d", dpiRisk, reachable, len(targets))
	s.jsonReply(w, resp)
}

func (s *MLServer) handleRecommendTransport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerHost string `json:"server_host"`
		ServerPort int    `json:"server_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.ServerPort == 0 {
		req.ServerPort = 8443
	}

	probeTargets := []struct {
		host string
		port int
	}{
		{req.ServerHost, req.ServerPort},
		{"1.1.1.1", 443},
		{"8.8.8.8", 443},
		{req.ServerHost, 80},
	}

	rttData := make([]float64, len(probeTargets))
	for i, t := range probeTargets {
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", net.JoinHostPort(t.host, strconv.Itoa(t.port)))
		if err != nil {
			rttData[i] = 9999
		} else {
			rttData[i] = float64(time.Since(start).Milliseconds())
			conn.Close()
		}
	}

	successRates := make(map[string]float64)
	latencies := make(map[string]float64)
	stats := s.engine.GetTransportStats()
	for name, v := range stats {
		if m, ok := v.(map[string]interface{}); ok {
			if rate, ok := m["rate"].(float64); ok {
				successRates[name] = rate
			}
			if avg, ok := m["avg_latency_ms"].(float64); ok {
				latencies[name] = avg
			}
		}
	}

	mlpTransport := s.engine.RecommendTransport(rttData, successRates, latencies)

	dpiRisk := "low"
	reachable := 0
	for _, rtt := range rttData {
		if rtt < 5000 {
			reachable++
		}
	}
	if reachable == 0 {
		dpiRisk = "critical"
	} else if rttData[0] > 5000 && reachable > 1 {
		dpiRisk = "high"
	} else if rttData[0] > 1000 {
		dpiRisk = "medium"
	}

	transport := mlpTransport
	confidence := 0.85
	reason := fmt.Sprintf("ML neural network selected based on %d probes, %d transport stats", len(rttData), len(stats))
	usedRL := false
	tspuDetected := false

	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		tType, tConf := tspuDet.DetectTSPU()
		if tType != ml.DPITypeNone && tConf > 0.5 {
			tspuDetected = true
			dpiRisk = "tspu"
			countermeasure := ml.TSPUCountermeasure(tType)
			if countermeasure != "" {
				transport = countermeasure
				confidence = tConf
				reason = fmt.Sprintf("TSPU detected (type=%d, conf=%.2f) -> countermeasure: %s",
					tType, tConf, countermeasure)
			}
		}
	}

	if rlAgent := s.engine.RLAgent(); rlAgent != nil {
		var rttArr [4]float64
		for i := 0; i < 4 && i < len(rttData); i++ {
			rttArr[i] = rttData[i]
		}
		var totalSuccess, totalFail float64
		for _, v := range stats {
			if m, ok := v.(map[string]interface{}); ok {
				if s, ok := m["success"].(int64); ok {
					totalSuccess += float64(s)
				}
				if f, ok := m["fail"].(int64); ok {
					totalFail += float64(f)
				}
			}
		}
		total := totalSuccess + totalFail
		succRate := 0.5
		failRate := 0.5
		if total > 0 {
			succRate = totalSuccess / total
			failRate = totalFail / total
		}
		blockRisk := s.engine.PredictBlockRisk(mlpTransport)
		dpiDetected := dpiRisk == "high" || dpiRisk == "critical"
		hour := time.Now().Hour()

		state := rlAgent.EncodeState(rttArr, succRate, failRate, dpiDetected, 0, hour, blockRisk)
		rlTransport, _, explored := rlAgent.SelectTransport(state)

		rlStats := rlAgent.Stats()
		bufSize, _ := rlStats["buffer_size"].(int)
		if bufSize > ml.RLBatchSize*4 && !explored && !tspuDetected {
			transport = rlTransport
			confidence = 0.90
			reason = fmt.Sprintf("RL-DQN selected (buffer=%d, eps=%.3f)", bufSize, rlStats["epsilon"])
			usedRL = true
		}
	}

	if len(stats) == 0 && !usedRL && !tspuDetected {
		confidence = 0.6
		reason = "ML selected (no historical feedback yet)"
	}

	s.jsonReply(w, map[string]interface{}{
		"dpi_risk":      dpiRisk,
		"transport":     transport,
		"options":       "",
		"description":   reason,
		"confidence":    confidence,
		"used_rl":       usedRL,
		"tspu_detected": tspuDetected,
	})
}

func (s *MLServer) handleFeedbackConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transport string  `json:"transport"`
		Success   bool    `json:"success"`
		Latency   float64 `json:"latency_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	s.feedbackMu.Lock()
	ts, ok := s.transportStats[req.Transport]
	if !ok {
		ts = &TransportStats{}
		s.transportStats[req.Transport] = ts
	}
	ts.Total++
	if req.Success {
		ts.Success++
	} else {
		ts.Fail++
	}
	ts.TotalLatency += req.Latency
	ts.Count++
	s.feedbackMu.Unlock()

	s.engine.RecordBlockEvent(req.Transport, req.Success)
	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		if !req.Success && req.Latency < float64(ml.TSPURSTThresholdMs) {
			tspuDet.RecordRST("", time.Duration(req.Latency)*time.Millisecond)
		}
	}

	if rlAgent := s.engine.RLAgent(); rlAgent != nil {
		reward := ml.ComputeReward(req.Success, req.Latency)
		actionIdx := rlAgent.TransportIndex(req.Transport)
		if actionIdx >= 0 {
			state := make([]float64, ml.RLStateSize)
			rlAgent.RecordExperience(state, actionIdx, reward, state, !req.Success)
		}
	}

	s.addLogf("feedback: %s success=%v latency=%.0fms", req.Transport, req.Success, req.Latency)
	s.jsonReply(w, map[string]string{"status": "ok"})
}

func (s *MLServer) handleFeedbackStats(w http.ResponseWriter, r *http.Request) {
	s.feedbackMu.Lock()
	stats := make(map[string]*TransportStats)
	for k, v := range s.transportStats {
		cp := *v
		stats[k] = &cp
	}
	s.feedbackMu.Unlock()
	s.jsonReply(w, stats)
}

func (s *MLServer) handleTSPUStats(w http.ResponseWriter, r *http.Request) {
	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		tType, tConf := tspuDet.DetectTSPU()
		stats := tspuDet.Stats()
		stats["detected_type"] = tType
		stats["detected_confidence"] = tConf
		if tType != ml.DPITypeNone {
			stats["countermeasure"] = ml.TSPUCountermeasure(tType)
		}
		s.jsonReply(w, stats)
	} else {
		s.jsonReply(w, map[string]string{"status": "tspu_detector_not_initialized"})
	}
}

func (s *MLServer) handleTSPURST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SNI       string  `json:"sni"`
		TimeToRST float64 `json:"time_to_rst_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		tspuDet.RecordRST(req.SNI, time.Duration(req.TimeToRST)*time.Millisecond)
	}
	s.addLogf("tspu_rst: sni=%s time=%.1fms", req.SNI, req.TimeToRST)
	s.jsonReply(w, map[string]string{"status": "ok"})
}

func (s *MLServer) handleTSPUBandwidth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transport   string  `json:"transport"`
		BytesPerSec float64 `json:"bytes_per_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		tspuDet.RecordBandwidth(req.Transport, req.BytesPerSec)
	}
	s.jsonReply(w, map[string]string{"status": "ok"})
}

func (s *MLServer) handleTrainStart(w http.ResponseWriter, r *http.Request) {
	if s.engine.IsTraining() {
		s.jsonReply(w, map[string]string{"status": "already_running"})
		return
	}

	epochs := 50
	if v := r.URL.Query().Get("epochs"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			epochs = n
		}
	}

	go func() {
		s.addLogf("training started (%d epochs)", epochs)
		samples, acc := s.engine.Train(epochs)
		s.addLogf("training done: %d samples, accuracy=%.4f", samples, acc)
	}()

	s.jsonReply(w, map[string]string{"status": "started"})
}

func (s *MLServer) handleTrainStop(w http.ResponseWriter, r *http.Request) {
	s.engine.StopTraining()
	s.addLogf("training stop requested")
	s.jsonReply(w, map[string]string{"status": "stopping"})
}

func (s *MLServer) handleTrainStatus(w http.ResponseWriter, r *http.Request) {
	running, epoch, total, loss := s.engine.TrainingStatus()
	if math.IsNaN(loss) || math.IsInf(loss, 0) {
		loss = 0
	}
	s.jsonReply(w, map[string]interface{}{
		"running":      running,
		"epoch":        epoch,
		"total_epochs": total,
		"loss":         loss,
	})
}

func (s *MLServer) handleScan(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}

	ports := map[int]string{
		22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 993: "IMAPS",
		1080: "SOCKS", 1194: "OpenVPN", 3128: "Proxy", 5222: "XMPP",
		8080: "HTTP-Alt", 8443: "Whispera", 9050: "Tor", 4443: "HTTPS-Alt",
		51820: "WireGuard",
	}

	type scanResult struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Open    bool   `json:"open"`
		Service string `json:"service"`
		Latency int    `json:"latency"`
	}

	var results []scanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for port, svc := range ports {
		wg.Add(1)
		go func(p int, service string) {
			defer wg.Done()
			start := time.Now()
			conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
			elapsed := time.Since(start)
			open := err == nil
			var lat int
			if open {
				conn.Close()
				lat = int(elapsed.Milliseconds())
				if lat == 0 {
					lat = 1
				}
			}
			mu.Lock()
			results = append(results, scanResult{
				Host: host, Port: p, Open: open, Service: service, Latency: lat,
			})
			mu.Unlock()
		}(port, svc)
	}
	wg.Wait()

	s.addLogf("scan %s: %d ports checked", host, len(ports))
	s.jsonReply(w, map[string]interface{}{"results": results})
}

func (s *MLServer) handleFedExport(w http.ResponseWriter, r *http.Request) {
	s.feedbackMu.Lock()
	stats := make(map[string]*TransportStats)
	for k, v := range s.transportStats {
		cp := *v
		stats[k] = &cp
	}
	s.feedbackMu.Unlock()

	engineStats := s.engine.GetStats()

	s.jsonReply(w, map[string]interface{}{
		"transports": stats,
		"model":      engineStats,
		"ts":         time.Now().Unix(),
	})
}

func (s *MLServer) handleFedImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transports map[string]*TransportStats `json:"transports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	s.feedbackMu.Lock()
	for name, remote := range req.Transports {
		if local, ok := s.transportStats[name]; ok {
			local.Success = (local.Success + remote.Success) / 2
			local.Fail = (local.Fail + remote.Fail) / 2
			local.Total = local.Success + local.Fail
		} else {
			cp := *remote
			s.transportStats[name] = &cp
		}
	}
	s.feedbackMu.Unlock()

	s.addLogf("federated import applied")
	s.jsonReply(w, map[string]string{"status": "applied"})
}

func (s *MLServer) handleFedStatus(w http.ResponseWriter, r *http.Request) {
	s.jsonReply(w, map[string]interface{}{
		"engine":    "native_mlp_go",
		"stats":     s.engine.GetStats(),
		"transports": len(s.transportStats),
	})
}

func (s *MLServer) handleFedLosses(w http.ResponseWriter, r *http.Request) {
	s.feedbackMu.Lock()
	losses := make(map[string]float64)
	for name, ts := range s.transportStats {
		if ts.Total > 0 {
			failRate := float64(ts.Fail) / float64(ts.Total)
			avgLat := 0.0
			if ts.Count > 0 {
				avgLat = ts.TotalLatency / float64(ts.Count)
			}
			losses[name] = failRate*0.7 + min64f(avgLat/5000, 1.0)*0.3
		}
	}
	s.feedbackMu.Unlock()
	s.jsonReply(w, map[string]interface{}{"local_losses": losses})
}

func (s *MLServer) handleFedUpload(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	fname := fmt.Sprintf("delta_%d.json", time.Now().UnixNano())
	os.WriteFile(filepath.Join(s.fedDir, fname), body, 0600)

	var upload struct {
		Samples []json.RawMessage `json:"samples"`
		Count   int               `json:"count"`
	}
	if json.Unmarshal(body, &upload) == nil && len(upload.Samples) > 0 {
		s.appendToDataset(upload.Samples)
		s.addLogf("federated upload: %s — %d samples appended to dataset (total: %d)",
			fname, len(upload.Samples), s.datasetSampleCount())
	} else {
		s.addLogf("federated delta uploaded: %s (%d bytes, no samples field)", fname, len(body))
	}

	s.jsonReply(w, map[string]string{"status": "ok"})
}

func (s *MLServer) appendToDataset(samples []json.RawMessage) {
	dsPath := filepath.Join(s.fedDir, "aggregated_dataset.jsonl")
	f, err := os.OpenFile(dsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	for _, sample := range samples {
		f.Write(sample)
		f.Write([]byte("\n"))
	}
}

func (s *MLServer) datasetSampleCount() int {
	dsPath := filepath.Join(s.fedDir, "aggregated_dataset.jsonl")
	data, err := os.ReadFile(dsPath)
	if err != nil {
		return 0
	}
	count := 0
	for _, b := range data {
		if b == '\n' {
			count++
		}
	}
	return count
}

func (s *MLServer) handleFedDownload(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(s.fedDir)
	deltas := make([]map[string]interface{}, 0)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			data, err := os.ReadFile(filepath.Join(s.fedDir, e.Name()))
			if err == nil {
				var d map[string]interface{}
				if json.Unmarshal(data, &d) == nil {
					deltas = append(deltas, d)
				}
			}
		}
	}
	s.jsonReply(w, map[string]interface{}{"deltas": deltas, "count": len(deltas)})
}

func (s *MLServer) handleFedDatasetExport(w http.ResponseWriter, r *http.Request) {
	dsPath := filepath.Join(s.fedDir, "aggregated_dataset.jsonl")
	info, err := os.Stat(dsPath)
	if err != nil {
		s.jsonReply(w, map[string]interface{}{"error": "no dataset yet", "samples": 0})
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", "attachment; filename=whispera_ml_dataset.jsonl")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	http.ServeFile(w, r, dsPath)
}

func (s *MLServer) handleFedDatasetStats(w http.ResponseWriter, r *http.Request) {
	dsPath := filepath.Join(s.fedDir, "aggregated_dataset.jsonl")
	info, err := os.Stat(dsPath)
	if err != nil {
		s.jsonReply(w, map[string]interface{}{
			"samples": 0, "size_bytes": 0, "clients": 0,
		})
		return
	}

	entries, _ := os.ReadDir(s.fedDir)
	deltaCount := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "delta_") {
			deltaCount++
		}
	}

	s.jsonReply(w, map[string]interface{}{
		"samples":      s.datasetSampleCount(),
		"size_bytes":   info.Size(),
		"size_mb":      float64(info.Size()) / (1024 * 1024),
		"uploads":      deltaCount,
		"last_modified": info.ModTime().UTC().Format(time.RFC3339),
	})
}

func (s *MLServer) handleDatasetsList(w http.ResponseWriter, r *http.Request) {
	dsDir := filepath.Join(s.dataDir, "datasets")
	os.MkdirAll(dsDir, 0700)

	entries, _ := os.ReadDir(dsDir)
	var datasets []map[string]interface{}
	for _, e := range entries {
		if !e.IsDir() {
			info, _ := e.Info()
			if info != nil {
				datasets = append(datasets, map[string]interface{}{
					"name":     e.Name(),
					"size":     info.Size(),
					"modified": info.ModTime().Unix(),
				})
			}
		}
	}
	s.jsonReply(w, map[string]interface{}{"datasets": datasets})
}

func (s *MLServer) handleDatasetsCapture(w http.ResponseWriter, r *http.Request) {
	dsDir := filepath.Join(s.dataDir, "datasets")
	os.MkdirAll(dsDir, 0700)

	name := fmt.Sprintf("capture_%d.jsonl", time.Now().Unix())
	fpath := filepath.Join(dsDir, name)

	s.feedbackMu.Lock()
	stats := make(map[string]*TransportStats)
	for k, v := range s.transportStats {
		cp := *v
		stats[k] = &cp
	}
	s.feedbackMu.Unlock()

	data, _ := json.Marshal(map[string]interface{}{
		"ts":         time.Now().Unix(),
		"transports": stats,
		"model":      s.engine.GetStats(),
	})
	os.WriteFile(fpath, data, 0600)

	s.addLogf("dataset captured: %s", name)
	s.jsonReply(w, map[string]interface{}{"status": "ok", "name": name})
}

func (s *MLServer) handleDatasetsUpload(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil || len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	dsDir := filepath.Join(s.dataDir, "datasets")
	os.MkdirAll(dsDir, 0700)

	name := r.Header.Get("X-Dataset-Name")
	if name == "" {
		name = fmt.Sprintf("upload_%d.jsonl", time.Now().Unix())
	}
	name = filepath.Base(name)
	os.WriteFile(filepath.Join(dsDir, name), body, 0600)
	s.addLogf("dataset uploaded: %s (%d bytes)", name, len(body))
	s.jsonReply(w, map[string]interface{}{"status": "ok", "name": name, "size": len(body)})
}

func (s *MLServer) handleDatasetsExchange(w http.ResponseWriter, r *http.Request) {
	s.jsonReply(w, map[string]interface{}{
		"status": "exchange requires peer_url, use Python server for P2P",
	})
}

func min64f(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func (s *MLServer) handleAdversarialStatus(w http.ResponseWriter, r *http.Request) {
	if s.adversarial == nil {
		http.Error(w, "adversarial engine not initialized", http.StatusServiceUnavailable)
		return
	}
	s.jsonReply(w, s.adversarial.GetStats())
}

func (s *MLServer) handleAdversarialEvolve(w http.ResponseWriter, r *http.Request) {
	if s.adversarial == nil {
		http.Error(w, "adversarial engine not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Data []byte `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if len(req.Data) == 0 {
		req.Data = make([]byte, 256)
	}
	perturbed := s.adversarial.Apply(req.Data)
	s.addLogf("adversarial evolve: input=%d output=%d", len(req.Data), len(perturbed))
	s.jsonReply(w, map[string]interface{}{
		"input_size":  len(req.Data),
		"output_size": len(perturbed),
		"stats":       s.adversarial.GetStats(),
	})
}

func (s *MLServer) handleAdversarialFeedback(w http.ResponseWriter, r *http.Request) {
	if s.adversarial == nil {
		http.Error(w, "adversarial engine not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Detected bool    `json:"detected"`
		Data     []byte  `json:"data"`
		Strategy int     `json:"strategy"`
		Intensity float64 `json:"intensity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	me := evasion.NewMLEvasion()
	features := me.CalculateMLFeatures(req.Data)
	var fArr [16]float64
	for i := 0; i < 16 && i < len(features); i++ {
		fArr[i] = features[i]
	}
	s.adversarial.RecordFeedback(req.Detected, req.Strategy, req.Intensity, fArr)
	s.addLogf("adversarial feedback: detected=%v strategy=%d", req.Detected, req.Strategy)
	s.jsonReply(w, map[string]interface{}{"status": "ok"})
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	return New(cfg)
}
