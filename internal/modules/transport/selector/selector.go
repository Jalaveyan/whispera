package selector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "transport.selector"
	ModuleVersion = "1.0.0"
)

type SelectionMode string

const (
	ModeAuto   SelectionMode = "auto"
	ModeManual SelectionMode = "manual"
)

type NetworkContext struct {
	DestinationAddr string
	Latency         time.Duration
	Bandwidth       float64
	PacketLoss      float64
	IsBlocked       map[interfaces.TransportType]bool
	ThreatLevel     int
	StealthRequired bool
}

type TransportMetrics struct {
	Type        interfaces.TransportType
	Latency     time.Duration
	Bandwidth   float64
	PacketLoss  float64
	Connections int64
	Errors      int64
	LastUsed    time.Time
	Score       float64
}

type Config struct {
	DefaultTransport  interfaces.TransportType
	Mode              SelectionMode
	MLWeight          float64
	LatencyWeight     float64
	BandwidthWeight   float64
	StealthWeight     float64
	ReliabilityWeight float64
}

func DefaultConfig() *Config {
	return &Config{
		DefaultTransport:  interfaces.TransportUDP,
		Mode:              ModeAuto,
		MLWeight:          0.5,
		LatencyWeight:     0.25,
		BandwidthWeight:   0.25,
		StealthWeight:     0.25,
		ReliabilityWeight: 0.25,
	}
}

func (c *Config) Validate() error {
	totalWeight := c.LatencyWeight + c.BandwidthWeight + c.StealthWeight + c.ReliabilityWeight
	if totalWeight <= 0 {
		c.LatencyWeight = 0.25
		c.BandwidthWeight = 0.25
		c.StealthWeight = 0.25
		c.ReliabilityWeight = 0.25
	}
	if c.MLWeight < 0 || c.MLWeight > 1 {
		c.MLWeight = 0.5
	}
	return nil
}

// mlRecommendResponse mirrors JSON returned by POST /recommend/transport
type mlRecommendResponse struct {
	Transport string `json:"transport"`   // имя транспорта
	DPIRisk   string `json:"dpi_risk"`    // "low"/"medium"/"high"/"critical"
	Options   string `json:"options"`
}

var dpiRiskScore = map[string]float64{
	"low":      0.1,
	"medium":   0.4,
	"high":     0.7,
	"critical": 1.0,
}

type Selector struct {
	*base.Module
	config     *Config
	mu         sync.RWMutex
	transports map[interfaces.TransportType]interfaces.Transport
	metrics    map[interfaces.TransportType]*TransportMetrics
	preferred  interfaces.TransportType
	mlEnabled  bool
	mlHTTP     *http.Client
	mlBaseURL  string

	selections uint64
	mlUsed     uint64
	manualUsed uint64
}

func New(cfg *Config) (*Selector, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	mlURL := os.Getenv("WHISPERA_ML_SERVER")
	if mlURL == "" {
		mlURL = "http://127.0.0.1:8000"
	}

	s := &Selector{
		Module:     base.NewModule(ModuleName, ModuleVersion, nil),
		config:     cfg,
		transports: make(map[interfaces.TransportType]interfaces.Transport),
		metrics:    make(map[interfaces.TransportType]*TransportMetrics),
		preferred:  cfg.DefaultTransport,
		mlEnabled:  cfg.Mode == ModeAuto,
		mlBaseURL:  mlURL,
		mlHTTP: &http.Client{
			Timeout: 2 * time.Second,
		},
	}

	return s, nil
}

func (s *Selector) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if selectorCfg, ok := cfg.(*Config); ok {
		s.config = selectorCfg
	}

	return nil
}

func (s *Selector) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	s.mu.Lock()
	for t := range s.transports {
		if _, exists := s.metrics[t]; !exists {
			s.metrics[t] = &TransportMetrics{
				Type:     t,
				LastUsed: time.Now(),
			}
		}
	}
	s.mu.Unlock()

	go s.metricsLoop()

	s.SetHealthy(true, fmt.Sprintf("mode=%s, default=%s", s.config.Mode, s.config.DefaultTransport))
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"mode":      s.config.Mode,
		"default":   s.config.DefaultTransport,
		"ml_weight": s.config.MLWeight,
	})

	return nil
}

func (s *Selector) Stop() error {
	s.PublishEvent(events.EventTypeModuleStopped, nil)
	return s.Module.Stop()
}

func (s *Selector) RegisterTransport(t interfaces.Transport) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	transportType := t.Type()
	s.transports[transportType] = t
	s.metrics[transportType] = &TransportMetrics{
		Type:     transportType,
		LastUsed: time.Now(),
	}

	return nil
}

func (s *Selector) SetMode(mode SelectionMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Mode = mode
	s.mlEnabled = mode == ModeAuto
}

func (s *Selector) SetPreferred(t interfaces.TransportType) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.transports[t]; !exists {
		return fmt.Errorf("transport %s not registered", t)
	}

	s.preferred = t
	return nil
}

func (s *Selector) Select(ctx *NetworkContext) (interfaces.Transport, error) {
	atomic.AddUint64(&s.selections, 1)

	s.mu.RLock()
	mode := s.config.Mode
	preferred := s.preferred
	s.mu.RUnlock()

	if mode == ModeManual {
		atomic.AddUint64(&s.manualUsed, 1)
		return s.getTransport(preferred)
	}

	atomic.AddUint64(&s.mlUsed, 1)
	return s.autoSelect(ctx)
}

// queryMLTransport спрашивает ML-сервер какой транспорт использовать.
// Возвращает ("", "") при любой ошибке — вызывающий код использует статический скоринг.
func (s *Selector) queryMLTransport(dest string) (transport string, dpiRisk string) {
	body, _ := json.Marshal(map[string]interface{}{
		"server_host": dest,
		"server_port": 443,
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.mlBaseURL+"/recommend/transport", bytes.NewReader(body))
	if err != nil {
		return "", ""
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.mlHTTP.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	var r mlRecommendResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", ""
	}
	return r.Transport, r.DPIRisk
}

// reportConnectionResult отправляет результат соединения в ML-сервер
// (fire-and-forget в горутине, не блокирует путь данных).
func (s *Selector) reportConnectionResult(t interfaces.TransportType, success bool, latency time.Duration) {
	if !s.mlEnabled {
		return
	}
	go func() {
		body, _ := json.Marshal(map[string]interface{}{
			"transport":  string(t),
			"success":    success,
			"latency_ms": float64(latency.Milliseconds()),
		})
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "POST", s.mlBaseURL+"/feedback/connection",
			bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.mlHTTP.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
}

func (s *Selector) autoSelect(ctx *NetworkContext) (interfaces.Transport, error) {
	var mlRecommended interfaces.TransportType

	if s.mlEnabled && ctx != nil && ctx.DestinationAddr != "" {
		host, _, _ := net.SplitHostPort(ctx.DestinationAddr)
		if host == "" {
			host = ctx.DestinationAddr
		}
		rec, dpiRisk := s.queryMLTransport(host)
		if rec != "" {
			mlRecommended = interfaces.TransportType(rec)
		}
		// Применяем DPI риск из ML к NetworkContext если он не задан явно
		if dpiRisk != "" {
			if score, ok := dpiRiskScore[dpiRisk]; ok && ctx.ThreatLevel == 0 {
				ctx.ThreatLevel = int(score * 10) // 0.7 → 7, 1.0 → 10
			}
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var bestTransport interfaces.TransportType
	var bestScore float64 = -1

	for t, metrics := range s.metrics {
		if ctx != nil && ctx.IsBlocked[t] {
			continue
		}
		if _, exists := s.transports[t]; !exists {
			continue
		}

		score := s.calculateScore(t, metrics, ctx)

		// Буст рекомендованного ML транспорта
		if t == mlRecommended && s.config.MLWeight > 0 {
			score += s.config.MLWeight
		}

		if score > bestScore {
			bestScore = score
			bestTransport = t
		}
	}

	if bestScore < 0 {
		return nil, fmt.Errorf("no suitable transport available")
	}

	if m, exists := s.metrics[bestTransport]; exists {
		m.LastUsed = time.Now()
	}

	return s.transports[bestTransport], nil
}

func (s *Selector) calculateScore(t interfaces.TransportType, m *TransportMetrics, ctx *NetworkContext) float64 {
	var score float64

	stealthScores := map[interfaces.TransportType]float64{
		interfaces.TransportUDP:       0.3,
		interfaces.TransportTCP:       0.6,
		interfaces.TransportQUIC:      0.7,
		interfaces.TransportH2C:       0.8,
		interfaces.TransportWebSocket: 0.8,
		interfaces.TransportXHTTP:     0.9,
		interfaces.TransportVKVideo:   0.95,
		interfaces.TransportOKWebRTC:  0.95,
		interfaces.TransportVKBot:     0.97,
		interfaces.TransportTGBot:     0.97,
		interfaces.TransportCDNWorker: 0.98,
		interfaces.TransportVKWebRTC:  0.99,
		interfaces.TransportYaTelemost: 0.99,
	}

	latencyScores := map[interfaces.TransportType]float64{
		interfaces.TransportUDP:       1.0,
		interfaces.TransportQUIC:      0.9,
		interfaces.TransportTCP:       0.7,
		interfaces.TransportWebSocket: 0.6,
		interfaces.TransportH2C:       0.75,
		interfaces.TransportXHTTP:     0.5,
		interfaces.TransportVKWebRTC:  0.6,
		interfaces.TransportYaTelemost: 0.55,
		interfaces.TransportOKWebRTC:  0.6,
		interfaces.TransportCDNWorker: 0.65,
		interfaces.TransportVKBot:     0.3,
		interfaces.TransportTGBot:     0.3,
		interfaces.TransportVKVideo:   0.5,
	}

	bandwidthScores := map[interfaces.TransportType]float64{
		interfaces.TransportUDP:       1.0,
		interfaces.TransportQUIC:      0.95,
		interfaces.TransportTCP:       0.85,
		interfaces.TransportWebSocket: 0.75,
		interfaces.TransportH2C:       0.8,
		interfaces.TransportXHTTP:     0.7,
		interfaces.TransportVKWebRTC:  0.7,
		interfaces.TransportYaTelemost: 0.65,
		interfaces.TransportOKWebRTC:  0.7,
		interfaces.TransportCDNWorker: 0.75,
		interfaces.TransportVKBot:     0.15,
		interfaces.TransportTGBot:     0.15,
		interfaces.TransportVKVideo:   0.6,
	}

	reliabilityScores := map[interfaces.TransportType]float64{
		interfaces.TransportTCP:       1.0,
		interfaces.TransportQUIC:      0.95,
		interfaces.TransportWebSocket: 0.9,
		interfaces.TransportH2C:       0.95,
		interfaces.TransportXHTTP:     0.85,
		interfaces.TransportUDP:       0.7,
		interfaces.TransportCDNWorker: 0.95,
		interfaces.TransportVKWebRTC:  0.85,
		interfaces.TransportYaTelemost: 0.8,
		interfaces.TransportOKWebRTC:  0.85,
		interfaces.TransportVKBot:     0.9,
		interfaces.TransportTGBot:     0.9,
		interfaces.TransportVKVideo:   0.8,
	}

	stealth := stealthScores[t]
	latency := latencyScores[t]
	bandwidth := bandwidthScores[t]
	reliability := reliabilityScores[t]

	if ctx != nil {
		if ctx.StealthRequired {
			stealth *= 1.5
		}
		if ctx.ThreatLevel > 7 {
			stealth *= 2.0
		}
	}

	if m.Latency > 0 {
		latencyPenalty := float64(m.Latency.Milliseconds()) / 1000.0
		if latencyPenalty > 1 {
			latencyPenalty = 1
		}
		latency *= (1 - latencyPenalty*0.5)
	}

	if m.PacketLoss > 0 {
		reliability *= (1 - m.PacketLoss)
	}

	if m.Bandwidth > 0 {
		bwNorm := m.Bandwidth / (100 * 1024 * 1024)
		if bwNorm > 1 {
			bwNorm = 1
		}
		bandwidth *= bwNorm
	}

	score = s.config.StealthWeight*stealth +
		s.config.LatencyWeight*latency +
		s.config.BandwidthWeight*bandwidth +
		s.config.ReliabilityWeight*reliability

	m.Score = score
	return score
}

func (s *Selector) getTransport(t interfaces.TransportType) (interfaces.Transport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	transport, exists := s.transports[t]
	if !exists {
		return nil, fmt.Errorf("transport %s not registered", t)
	}

	return transport, nil
}

func (s *Selector) GetTransport(t interfaces.TransportType) (interfaces.Transport, error) {
	return s.getTransport(t)
}

func (s *Selector) Dial(ctx context.Context, addr string, netCtx *NetworkContext) (net.Conn, error) {
	transport, err := s.Select(netCtx)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	conn, dialErr := transport.Dial(ctx, addr)
	s.reportConnectionResult(transport.Type(), dialErr == nil, time.Since(start))
	return conn, dialErr
}

func (s *Selector) UpdateMetrics(t interfaces.TransportType, latency time.Duration, bandwidth float64, packetLoss float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if m, exists := s.metrics[t]; exists {
		m.Latency = latency
		m.Bandwidth = bandwidth
		m.PacketLoss = packetLoss
	}
}

func (s *Selector) metricsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for s.IsRunning() {
		<-ticker.C
		s.collectMetrics()
	}
}

func (s *Selector) collectMetrics() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for t, transport := range s.transports {
		health := transport.HealthCheck()
		if m, exists := s.metrics[t]; exists {
			if conns, ok := health.Details["active_conns"].(int64); ok {
				m.Connections = conns
			}
			if errors, ok := health.Details["accept_errors"].(uint64); ok {
				m.Errors = int64(errors)
			}
		}
	}
}

func (s *Selector) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()

	s.mu.RLock()
	status.Details["mode"] = s.config.Mode
	status.Details["preferred"] = s.preferred
	status.Details["transport_count"] = len(s.transports)
	status.Details["selections"] = atomic.LoadUint64(&s.selections)
	status.Details["ml_used"] = atomic.LoadUint64(&s.mlUsed)
	status.Details["manual_used"] = atomic.LoadUint64(&s.manualUsed)
	s.mu.RUnlock()

	return status
}

func (s *Selector) GetMetrics() map[interfaces.TransportType]*TransportMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[interfaces.TransportType]*TransportMetrics)
	for t, m := range s.metrics {
		copy := *m
		result[t] = &copy
	}
	return result
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
