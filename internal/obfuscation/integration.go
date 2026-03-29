package obfuscation

import (
	"sync"
	"time"
	"whispera/internal/obfuscation/core/types"
	ftepkg "whispera/internal/obfuscation/fte"
	marionettepkg "whispera/internal/obfuscation/marionette"
	mlpkg "whispera/internal/obfuscation/ml"
)

const (
	statusActive   = "active"
	statusInactive = "inactive"
)

type MLConfig struct {
	BatchSize              int
	MaxConcurrentWorkers   int
	CircuitBreakerLimit    int
	CircuitBreakerCooldown time.Duration
	DefaultSampleRate      int
	StableSampleRate       int
	UnstableSampleRate     int
	BatchFlushTimeout      time.Duration
	MinPacketSize          int
}

func DefaultMLConfig() *MLConfig {
	return &MLConfig{
		BatchSize:              10,
		MaxConcurrentWorkers:   2,
		CircuitBreakerLimit:    5,
		CircuitBreakerCooldown: 60 * time.Second,
		DefaultSampleRate:      10,
		StableSampleRate:       20,
		UnstableSampleRate:     5,
		BatchFlushTimeout:      100 * time.Millisecond,
		MinPacketSize:          64,
	}
}

type Metrics struct {
	PacketsProcessed    uint64
	PacketsSkipped      uint64
	MLProcessed         uint64
	MLSkipped           uint64
	MLErrors            uint64
	CircuitBreakerTrips uint64
	BatchesProcessed    uint64
	CurrentSampleRate   int
	NetworkStable       bool
}

var batchPool = sync.Pool{
	New: func() interface{} {
		return make([][]byte, 0, 10)
	},
}

var _ = &batchPool

type IntegrationManager struct {
	mu sync.RWMutex

	marionette *marionettepkg.Marionette
	adapter    *marionettepkg.MarionetteAdapter
	mlSystem   *mlpkg.UnifiedMLSystem
	fte        *ftepkg.FTE
	mlEnabled  bool
	fteEnabled bool
	config     *MLConfig

	mlFailures      int
	mlDisabledUntil time.Time

	packetTimings []time.Time
	sampleRate    int
	packetCounter int
	networkStable bool

	packetBatch    [][]byte
	lastBatchFlush time.Time

	mlSemaphore chan struct{}

	metrics Metrics
}

func NewIntegrationManager() *IntegrationManager {
	adapter := marionettepkg.NewMarionetteAdapter()
	mlSystem := mlpkg.NewUnifiedMLSystem()
	fte := ftepkg.NewFTE()
	cfg := DefaultMLConfig()

	im := &IntegrationManager{
		marionette:    adapter.GetCore(),
		adapter:       adapter,
		mlSystem:      mlSystem,
		fte:           fte,
		mlEnabled:     true,
		fteEnabled:    true,
		config:        cfg,
		sampleRate:    cfg.DefaultSampleRate,
		packetBatch:   make([][]byte, 0, cfg.BatchSize),
		packetTimings: make([]time.Time, 0, 20),
		mlSemaphore:   make(chan struct{}, cfg.MaxConcurrentWorkers),
	}
	if eng := mlpkg.GetNativeEngine(); eng != nil {
		eng.SetOnDPIProfile(func(profile string) {
			_ = im.adapter.SetActiveProfile(profile)
		})
	}
	return im
}

func NewIntegrationManagerWithOptions(enableML, enableFTE bool) *IntegrationManager {
	adapter := marionettepkg.NewMarionetteAdapter()
	cfg := DefaultMLConfig()

	im := &IntegrationManager{
		marionette:    adapter.GetCore(),
		adapter:       adapter,
		mlEnabled:     enableML,
		fteEnabled:    enableFTE,
		config:        cfg,
		sampleRate:    cfg.DefaultSampleRate,
		packetBatch:   make([][]byte, 0, cfg.BatchSize),
		packetTimings: make([]time.Time, 0, 20),
		mlSemaphore:   make(chan struct{}, cfg.MaxConcurrentWorkers),
	}

	if enableML {
		im.mlSystem = mlpkg.NewUnifiedMLSystem()
		if eng := mlpkg.GetNativeEngine(); eng != nil {
			eng.SetOnDPIProfile(func(profile string) {
				_ = im.adapter.SetActiveProfile(profile)
			})
		}
	}
	if enableFTE {
		im.fte = ftepkg.NewFTE()
	}

	return im
}

func (im *IntegrationManager) ProcessTraffic(data []byte, direction string) ([]byte, time.Duration, error) {
	if im.fteEnabled && im.fte != nil {
		transformed, err := im.fte.Transform(data)
		if err == nil && transformed != nil && len(transformed) > 0 {
			data = transformed
		}
	}

	processed, delay, err := im.adapter.ProcessPacket(data, direction)
	if err != nil {
		return data, 0, err
	}

	if im.mlEnabled && im.mlSystem != nil && len(processed) >= im.config.MinPacketSize {
		im.mu.RLock()
		disabled := time.Now().Before(im.mlDisabledUntil)
		im.mu.RUnlock()

		if !disabled {
			context := &types.UnifiedTrafficContext{
				Direction: direction,
				Protocol:  "auto",
				Size:      len(processed),
				Timestamp: time.Now(),
			}

			mlProcessed, mlErr := im.mlSystem.ProcessTraffic(processed, context)
			if mlErr != nil {
				im.mu.Lock()
				im.mlFailures++
				im.metrics.MLErrors++
				if im.mlFailures >= im.config.CircuitBreakerLimit {
					im.mlDisabledUntil = time.Now().Add(im.config.CircuitBreakerCooldown)
					im.mlFailures = 0
					im.metrics.CircuitBreakerTrips++
				}
				im.mu.Unlock()
			} else if mlProcessed != nil && len(mlProcessed) > 0 {
				processed = mlProcessed
				im.mu.Lock()
				im.metrics.MLProcessed++
				im.mlFailures = 0
				im.mu.Unlock()
			}
		} else {
			im.mu.Lock()
			im.metrics.MLSkipped++
			im.mu.Unlock()
		}
	}

	im.mu.Lock()
	im.metrics.PacketsProcessed++
	im.mu.Unlock()

	return processed, delay, nil
}

func (im *IntegrationManager) updateNetworkStabilityLocked() {
	if len(im.packetTimings) < 5 {
		return
	}

	var total int64
	for i := 1; i < len(im.packetTimings); i++ {
		total += im.packetTimings[i].Sub(im.packetTimings[i-1]).Milliseconds()
	}
	avg := total / int64(len(im.packetTimings)-1)

	var variance int64
	for i := 1; i < len(im.packetTimings); i++ {
		diff := im.packetTimings[i].Sub(im.packetTimings[i-1]).Milliseconds() - avg
		variance += diff * diff
	}
	variance /= int64(len(im.packetTimings) - 1)

	if variance > 10000 {
		im.networkStable = false
		im.sampleRate = im.config.UnstableSampleRate
	} else {
		im.networkStable = true
		im.sampleRate = im.config.StableSampleRate
	}

	im.metrics.CurrentSampleRate = im.sampleRate
	im.metrics.NetworkStable = im.networkStable
}

func (im *IntegrationManager) ProcessTrafficWithML(data []byte, direction string, _ string) ([]byte, time.Duration, error) {
	return im.ProcessTraffic(data, direction)
}

func (im *IntegrationManager) GetMLSystem() *mlpkg.UnifiedMLSystem {
	return im.mlSystem
}

func (im *IntegrationManager) SetConnectionActive(active bool) {
	if im.mlSystem == nil {
		return
	}
	if dc := im.mlSystem.GetDataCollector(); dc != nil {
		dc.SetConnectionActive(active)
	}
	if eng := mlpkg.GetNativeEngine(); eng != nil {
		eng.SetConnectionActive(active)
	}
}

func (im *IntegrationManager) GetMetrics() Metrics {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.metrics
}

func (im *IntegrationManager) GetFTE() *ftepkg.FTE {
	return im.fte
}

func (im *IntegrationManager) GetMarionetteAdapter() *marionettepkg.MarionetteAdapter {
	return im.adapter
}

func (im *IntegrationManager) SetProfile(name string) error {
	return im.adapter.SetActiveProfile(name)
}

func (im *IntegrationManager) SetStrict(strict bool) {
	im.adapter.SetStrict(strict)
}

func (im *IntegrationManager) SetRealityKey(key string) {
	im.adapter.SetRealityKey(key)
}

func (im *IntegrationManager) EnableGrammarRotation(interval time.Duration, bytes uint64, profiles []string) {
	if im.fteEnabled && im.fte != nil {
		im.fte.EnableRotation(interval, bytes, profiles)
	}
}

func (im *IntegrationManager) GetHealthStatus() map[string]interface{} {
	health := make(map[string]interface{})

	health["marionette"] = im.adapter.HealthCheck()

	if im.marionette.GetAdaptiveLearning() != nil {
		health["adaptive_learning"] = statusActive
	} else {
		health["adaptive_learning"] = statusInactive
	}

	if im.marionette.GetEffectivenessMetrics() != nil {
		health["effectiveness_metrics"] = statusActive
	} else {
		health["effectiveness_metrics"] = statusInactive
	}

	systemMetrics := im.adapter.GetSystemMetrics()
	health["system_metrics"] = map[string]interface{}{
		"packets_processed": systemMetrics.PacketsProcessed,
		"ml_predictions":    systemMetrics.MLPredictions,
		"ml_failures":       systemMetrics.MLFailures,
		"average_latency":   time.Duration(systemMetrics.AverageLatency).String(),
		"memory_usage":      systemMetrics.MemoryUsage,
	}

	return health
}

func (im *IntegrationManager) GetAvailableProfiles() []string {
	return im.adapter.GetProfileNames()
}

func (im *IntegrationManager) GetTrafficState() *types.TrafficState {
	return im.adapter.GetState()
}

func (im *IntegrationManager) GetPerformanceMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	systemMetrics := im.adapter.GetSystemMetrics()
	metrics["system"] = map[string]interface{}{
		"packets_processed":     systemMetrics.PacketsProcessed,
		"ml_predictions":        systemMetrics.MLPredictions,
		"ml_failures":           systemMetrics.MLFailures,
		"average_latency":       time.Duration(systemMetrics.AverageLatency).String(),
		"memory_usage":          systemMetrics.MemoryUsage,
		"circuit_breaker_trips": systemMetrics.CircuitBreakerTrips,
	}

	state := im.adapter.GetState()
	metrics["traffic"] = map[string]interface{}{
		"total_packets":       state.TotalPackets,
		"total_bytes":         state.TotalBytes,
		"outbound_packets":    state.OutboundPackets,
		"outbound_bytes":      state.OutboundBytes,
		"inbound_packets":     state.InboundPackets,
		"inbound_bytes":       state.InboundBytes,
		"average_packet_size": state.AveragePacketSize,
		"average_interval":    state.AverageInterval.String(),
		"burst_count":         state.BurstCount,
		"idle_count":          state.IdleCount,
		"session_duration":    state.SessionDuration.String(),
		"current_profile":     state.CurrentProfile,
		"ml_predictions":      state.MLPredictions,
		"ml_failures":         state.MLFailures,
		"evasion_successes":   state.EvasionSuccesses,
		"evasion_failures":    state.EvasionFailures,
	}

	return metrics
}

func (im *IntegrationManager) ResetSystem() error {
	im.adapter = marionettepkg.NewMarionetteAdapter()
	im.marionette = im.adapter.GetCore()

	return nil
}

func (im *IntegrationManager) GetModuleStatus() map[string]string {
	status := make(map[string]string)

	if im.marionette != nil {
		status["marionette"] = "active"
	} else {
		status["marionette"] = "inactive"
	}

	if im.marionette.GetAdaptiveLearning() != nil {
		status["adaptive_learning"] = "active"
	} else {
		status["adaptive_learning"] = "inactive"
	}

	if im.marionette.GetEffectivenessMetrics() != nil {
		status["effectiveness_metrics"] = "active"
	} else {
		status["effectiveness_metrics"] = "inactive"
	}

	return status
}
