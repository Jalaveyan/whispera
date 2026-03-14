package metricscollector

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/metrics"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "metrics.collector"
	ModuleVersion = "1.0.0"
)

type MetricType int

const (
	MetricTypeCounter MetricType = iota
	MetricTypeGauge
	MetricTypeHistogram
)

type Config struct {
	Enabled       bool
	ListenAddr    string
	Path          string
	EnableRuntime bool
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:       true,
		ListenAddr:    ":9091",
		Path:          "/metrics",
		EnableRuntime: true,
	}
}

func (c *Config) Validate() error {
	if c.Path == "" {
		c.Path = "/metrics"
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":9091"
	}
	return nil
}

type metricDef struct {
	Name       string
	Help       string
	Type       MetricType
	LabelNames []string
}

type Collector struct {
	*base.Module
	config *Config
	defsMu      sync.RWMutex
	definitions map[string]*metricDef

	countersMu sync.RWMutex
	counters   map[string]map[string]float64

	gaugesMu sync.RWMutex
	gauges   map[string]map[string]float64

	histogramsMu sync.RWMutex
	histograms   map[string]*histogram

	server *http.Server
}

type histogram struct {
	buckets map[float64]uint64
	count   uint64
	sum     float64
}

func New(cfg *Config) (*Collector, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	c := &Collector{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		config:      cfg,
		definitions: make(map[string]*metricDef),
		counters:    make(map[string]map[string]float64),
		gauges:      make(map[string]map[string]float64),
		histograms:  make(map[string]*histogram),
	}

	c.registerDefaultMetrics()

	return c, nil
}

func (c *Collector) registerDefaultMetrics() {
	c.RegisterCounter("whispera_packets_received_total", "Total packets received", []string{"transport"})
	c.RegisterCounter("whispera_packets_sent_total", "Total packets sent", []string{"transport"})
	c.RegisterCounter("whispera_packets_dropped_total", "Total packets dropped", []string{"reason"})
	c.RegisterCounter("whispera_bytes_received_total", "Total bytes received", []string{"transport"})
	c.RegisterCounter("whispera_bytes_sent_total", "Total bytes sent", []string{"transport"})
	c.RegisterGauge("whispera_sessions_active", "Number of active sessions", nil)
	c.RegisterCounter("whispera_sessions_created_total", "Total sessions created", nil)
	c.RegisterCounter("whispera_handshakes_total", "Total handshakes", []string{"status"})
	c.RegisterCounter("whispera_errors_total", "Total errors", []string{"module", "type"})
}

func (c *Collector) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := c.Module.Init(ctx, cfg); err != nil {
		return err
	}
	if metricsCfg, ok := cfg.(*Config); ok {
		c.config = metricsCfg
	}
	return nil
}

func (c *Collector) Start() error {
	if err := c.Module.Start(); err != nil {
		return err
	}

	if c.config.Enabled {
		mux := http.NewServeMux()
		mux.HandleFunc(c.config.Path, c.handleMetrics)
		mux.HandleFunc("/health", c.handleHealth)

		c.server = &http.Server{
			Addr:    c.config.ListenAddr,
			Handler: mux,
		}

		go func() {
			if err := c.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				c.SetHealthy(false, fmt.Sprintf("HTTP server error: %v", err))
			}
		}()
	}

	c.SetHealthy(true, fmt.Sprintf("metrics collector running on %s", c.config.ListenAddr))
	c.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": c.config.ListenAddr,
	})

	return nil
}

func (c *Collector) Stop() error {
	if c.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.server.Shutdown(ctx)
	}
	c.PublishEvent(events.EventTypeModuleStopped, nil)
	return c.Module.Stop()
}

func (c *Collector) Increment(name string, labels map[string]string) {
	c.Add(name, 1, labels)
}
func (c *Collector) Add(name string, value float64, labels map[string]string) {
	c.countersMu.Lock()
	defer c.countersMu.Unlock()

	if c.counters[name] == nil {
		c.counters[name] = make(map[string]float64)
	}
	key := labelsToKey(labels)
	c.counters[name][key] += value
}

func (c *Collector) Observe(name string, value float64, labels map[string]string) {
	c.histogramsMu.Lock()
	defer c.histogramsMu.Unlock()

	h := c.histograms[name]
	if h == nil {
		return
	}
	h.count++
	h.sum += value
	for bucket := range h.buckets {
		if value <= bucket {
			h.buckets[bucket]++
		}
	}
}

func (c *Collector) Set(name string, value float64, labels map[string]string) {
	c.gaugesMu.Lock()
	defer c.gaugesMu.Unlock()

	if c.gauges[name] == nil {
		c.gauges[name] = make(map[string]float64)
	}
	key := labelsToKey(labels)
	c.gauges[name][key] = value
}

func (c *Collector) RegisterCounter(name, help string, labelNames []string) error {
	c.defsMu.Lock()
	defer c.defsMu.Unlock()
	c.definitions[name] = &metricDef{Name: name, Help: help, Type: MetricTypeCounter, LabelNames: labelNames}
	return nil
}

func (c *Collector) RegisterGauge(name, help string, labelNames []string) error {
	c.defsMu.Lock()
	defer c.defsMu.Unlock()
	c.definitions[name] = &metricDef{Name: name, Help: help, Type: MetricTypeGauge, LabelNames: labelNames}
	return nil
}

func (c *Collector) RegisterHistogram(name, help string, labelNames []string, buckets []float64) error {
	c.defsMu.Lock()
	defer c.defsMu.Unlock()
	c.definitions[name] = &metricDef{Name: name, Help: help, Type: MetricTypeHistogram, LabelNames: labelNames}

	c.histogramsMu.Lock()
	c.histograms[name] = &histogram{buckets: make(map[float64]uint64)}
	for _, b := range buckets {
		c.histograms[name].buckets[b] = 0
	}
	c.histogramsMu.Unlock()
	return nil
}

func (c *Collector) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	c.writeGlobalMetrics(w)

	c.defsMu.RLock()
	defs := make(map[string]*metricDef, len(c.definitions))
	for k, v := range c.definitions {
		defs[k] = v
	}
	c.defsMu.RUnlock()

	c.countersMu.RLock()
	for name, values := range c.counters {
		if def, ok := defs[name]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n", name, def.Help)
			fmt.Fprintf(w, "# TYPE %s counter\n", name)
		}
		for labels, value := range values {
			if labels != "" {
				fmt.Fprintf(w, "%s{%s} %g\n", name, labels, value)
			} else {
				fmt.Fprintf(w, "%s %g\n", name, value)
			}
		}
	}
	c.countersMu.RUnlock()

	c.gaugesMu.RLock()
	for name, values := range c.gauges {
		if def, ok := defs[name]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n", name, def.Help)
			fmt.Fprintf(w, "# TYPE %s gauge\n", name)
		}
		for labels, value := range values {
			if labels != "" {
				fmt.Fprintf(w, "%s{%s} %g\n", name, labels, value)
			} else {
				fmt.Fprintf(w, "%s %g\n", name, value)
			}
		}
	}
	c.gaugesMu.RUnlock()

	c.histogramsMu.RLock()
	for name, h := range c.histograms {
		if def, ok := defs[name]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n", name, def.Help)
			fmt.Fprintf(w, "# TYPE %s histogram\n", name)
		}
		for bucket, count := range h.buckets {
			fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, bucket, count)
		}
		fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, h.count)
		fmt.Fprintf(w, "%s_sum %g\n", name, h.sum)
		fmt.Fprintf(w, "%s_count %d\n", name, h.count)
	}
	c.histogramsMu.RUnlock()
}

func (c *Collector) writeGlobalMetrics(w http.ResponseWriter) {
	fmt.Fprintf(w, "# HELP whispera_global_packets_rx Total packets received (global)\n")
	fmt.Fprintf(w, "# TYPE whispera_global_packets_rx counter\n")
	fmt.Fprintf(w, "whispera_global_packets_rx %d\n", metrics.PacketsRx.Value())
	fmt.Fprintf(w, "# HELP whispera_global_packets_tx Total packets sent (global)\n")
	fmt.Fprintf(w, "# TYPE whispera_global_packets_tx counter\n")
	fmt.Fprintf(w, "whispera_global_packets_tx %d\n", metrics.PacketsTx.Value())
	fmt.Fprintf(w, "# HELP whispera_global_bytes_rx Total bytes received (global)\n")
	fmt.Fprintf(w, "# TYPE whispera_global_bytes_rx counter\n")
	fmt.Fprintf(w, "whispera_global_bytes_rx %d\n", metrics.BytesRx.Value())
	fmt.Fprintf(w, "# HELP whispera_global_bytes_tx Total bytes sent (global)\n")
	fmt.Fprintf(w, "# TYPE whispera_global_bytes_tx counter\n")
	fmt.Fprintf(w, "whispera_global_bytes_tx %d\n", metrics.BytesTx.Value())
	fmt.Fprintf(w, "# HELP whispera_xhttp_streams_created Total XHTTP streams created\n")
	fmt.Fprintf(w, "# TYPE whispera_xhttp_streams_created counter\n")
	fmt.Fprintf(w, "whispera_xhttp_streams_created %d\n", metrics.XHTTPStreamsCreated.Value())
	fmt.Fprintf(w, "# HELP whispera_xhttp_sessions_active Active XHTTP sessions\n")
	fmt.Fprintf(w, "# TYPE whispera_xhttp_sessions_active gauge\n")
	fmt.Fprintf(w, "whispera_xhttp_sessions_active %d\n", metrics.XHTTPSessionsActive.Value())
}

func (c *Collector) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := c.HealthCheck()
	if status.Healthy {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "UNHEALTHY\n")
	}
}

func (c *Collector) HealthCheck() interfaces.HealthStatus {
	status := c.Module.HealthCheck()
	c.defsMu.RLock()
	status.Details["registered_metrics"] = len(c.definitions)
	c.defsMu.RUnlock()
	status.Details["listen_addr"] = c.config.ListenAddr
	return status
}

func labelsToKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	var result string
	first := true
	for k, v := range labels {
		if !first {
			result += ","
		}
		result += fmt.Sprintf("%s=\"%s\"", k, v)
		first = false
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
