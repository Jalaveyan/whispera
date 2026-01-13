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

// MLConfig holds ML processing configuration
type MLConfig struct {
	BatchSize              int           // Packets per batch
	MaxConcurrentWorkers   int           // Max parallel ML workers
	CircuitBreakerLimit    int           // Failures before trip
	CircuitBreakerCooldown time.Duration // Cooldown after trip
	DefaultSampleRate      int           // Default sampling rate
	StableSampleRate       int           // Rate when network stable
	UnstableSampleRate     int           // Rate when network unstable
	BatchFlushTimeout      time.Duration // Max wait for batch
	MinPacketSize          int           // Min size for ML processing
}

// DefaultMLConfig returns production defaults
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
		MinPacketSize:          2048,
	}
}

// Metrics holds observable counters for monitoring
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

// batchPool reuses slice allocations to prevent memory growth
var batchPool = sync.Pool{
	New: func() interface{} {
		return make([][]byte, 0, 10)
	},
}

// prevent unused warning by referencing address (avoid lock copy)
var _ = &batchPool

// IntegrationManager manages integration between modules
type IntegrationManager struct {
	mu sync.RWMutex

	marionette *marionettepkg.Marionette
	adapter    *marionettepkg.MarionetteAdapter
	mlSystem   *mlpkg.UnifiedMLSystem
	fte        *ftepkg.FTE
	mlEnabled  bool
	fteEnabled bool
	config     *MLConfig

	// ML Circuit Breaker
	mlFailures      int
	mlDisabledUntil time.Time

	// Dynamic Sampling
	packetTimings []time.Time
	sampleRate    int
	packetCounter int
	networkStable bool

	// Batch Processing (uses pool)
	packetBatch    [][]byte
	lastBatchFlush time.Time

	// Resource Limits
	mlSemaphore chan struct{}

	// Observability
	metrics Metrics
}

// NewIntegrationManager creates a new integration manager
func NewIntegrationManager() *IntegrationManager {
	adapter := marionettepkg.NewMarionetteAdapter()
	mlSystem := mlpkg.NewUnifiedMLSystem()
	fte := ftepkg.NewFTE()
	cfg := DefaultMLConfig()

	return &IntegrationManager{
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
}

// NewIntegrationManagerWithOptions creates a new integration manager with options
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
	}
	if enableFTE {
		im.fte = ftepkg.NewFTE()
	}

	return im
}

// ProcessTraffic processes traffic through the integrated system
// Order: FTE -> Marionette -> ML (if enabled, with optimization)
func (im *IntegrationManager) ProcessTraffic(data []byte, direction string) ([]byte, time.Duration, error) {
	// Re-enable Encryption (Marionette) but keep dangerous Obfuscation (FTE) optional/disabled for stability
	// This ensures traffic is encrypted (preventing RSTs on cleartext) but avoids corruption from complex FTE rules.

	// Step 1: Marionette (Encryption/Encoding)
	// We skip FTE Transform for now to isolate the "RST" issue to just lack of encryption.
	processed, delay, err := im.adapter.ProcessPacket(data, direction)
	if err != nil {
		return data, 0, err
	}

	// Increment processed counter
	im.mu.Lock()
	im.metrics.PacketsProcessed++
	im.mu.Unlock()

	return processed, delay, nil
}

// updateNetworkStabilityLocked adjusts sampling rate based on packet timing variance
// MUST be called with im.mu held
func (im *IntegrationManager) updateNetworkStabilityLocked() {
	if len(im.packetTimings) < 5 {
		return
	}

	// Calculate variance of inter-packet times
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

	// High variance = unstable network = more sampling
	if variance > 10000 { // >100ms variance
		im.networkStable = false
		im.sampleRate = im.config.UnstableSampleRate
	} else {
		im.networkStable = true
		im.sampleRate = im.config.StableSampleRate
	}

	// Update metrics
	im.metrics.CurrentSampleRate = im.sampleRate
	im.metrics.NetworkStable = im.networkStable
}

// ProcessTrafficWithML processes traffic with explicit ML context
func (im *IntegrationManager) ProcessTrafficWithML(data []byte, direction string, protocol string) ([]byte, time.Duration, error) {
	processed := data

	// Step 1: FTE transformation (if enabled)
	if im.fteEnabled && im.fte != nil {
		transformed, err := im.fte.Transform(processed)
		if err == nil && transformed != nil && len(transformed) > 0 {
			processed = transformed
		}
	}

	// Step 2: Marionette obfuscation
	processed, delay, err := im.adapter.ProcessPacket(processed, direction)
	if err != nil {
		return data, 0, err
	}

	// Step 3: ML processing (if enabled and packet is large enough)
	if im.mlEnabled && im.mlSystem != nil && len(processed) > 2048 {
		// log.Printf("[ML] Processing %d bytes (%s, %s)", len(processed), direction, protocol)
		context := &types.UnifiedTrafficContext{
			Direction: direction,
			Protocol:  protocol,
			Size:      len(processed),
			Timestamp: time.Now(),
		}

		mlProcessed, mlErr := im.mlSystem.ProcessTraffic(processed, context)
		if mlErr == nil && mlProcessed != nil && len(mlProcessed) > 0 {
			processed = mlProcessed
		}
	}

	return processed, delay, err
}

// GetMLSystem returns the ML system instance
func (im *IntegrationManager) GetMLSystem() *mlpkg.UnifiedMLSystem {
	return im.mlSystem
}

// GetMetrics returns a copy of current metrics for monitoring
func (im *IntegrationManager) GetMetrics() Metrics {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.metrics
}

// GetFTE returns the FTE instance
func (im *IntegrationManager) GetFTE() *ftepkg.FTE {
	return im.fte
}

// GetMarionetteAdapter returns the Marionette adapter
func (im *IntegrationManager) GetMarionetteAdapter() *marionettepkg.MarionetteAdapter {
	return im.adapter
}

// SetProfile sets the active traffic profile
func (im *IntegrationManager) SetProfile(name string) error {
	return im.adapter.SetActiveProfile(name)
}

// SetStrict enables or disables strict obfuscation mode
func (im *IntegrationManager) SetStrict(strict bool) {
	im.adapter.SetStrict(strict)
}

// EnableGrammarRotation enables grammar rotation for FTE
func (im *IntegrationManager) EnableGrammarRotation(interval time.Duration, bytes uint64, profiles []string) {
	if im.fteEnabled && im.fte != nil {
		im.fte.EnableRotation(interval, bytes, profiles)
	}
}

// GetHealthStatus returns the health status of all modules
func (im *IntegrationManager) GetHealthStatus() map[string]interface{} {
	health := make(map[string]interface{})

	// Get Marionette health
	health["marionette"] = im.adapter.HealthCheck()

	// Get ML system health
	if im.marionette.GetAdaptiveLearning() != nil {
		health["adaptive_learning"] = statusActive
	} else {
		health["adaptive_learning"] = statusInactive
	}

	// Get effectiveness metrics
	if im.marionette.GetEffectivenessMetrics() != nil {
		health["effectiveness_metrics"] = statusActive
	} else {
		health["effectiveness_metrics"] = statusInactive
	}

	// Get system metrics
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

// GetAvailableProfiles returns all available traffic profiles
func (im *IntegrationManager) GetAvailableProfiles() []string {
	return im.adapter.GetProfileNames()
}

// GetTrafficState returns the current traffic state
func (im *IntegrationManager) GetTrafficState() *types.TrafficState {
	return im.adapter.GetState()
}

// GetPerformanceMetrics returns performance metrics
func (im *IntegrationManager) GetPerformanceMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	// Get system metrics
	systemMetrics := im.adapter.GetSystemMetrics()
	metrics["system"] = map[string]interface{}{
		"packets_processed":     systemMetrics.PacketsProcessed,
		"ml_predictions":        systemMetrics.MLPredictions,
		"ml_failures":           systemMetrics.MLFailures,
		"average_latency":       time.Duration(systemMetrics.AverageLatency).String(),
		"memory_usage":          systemMetrics.MemoryUsage,
		"circuit_breaker_trips": systemMetrics.CircuitBreakerTrips,
	}

	// Get traffic state metrics
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

// ResetSystem resets the system to initial state
func (im *IntegrationManager) ResetSystem() error {
	// Reset Marionette state
	im.adapter = marionettepkg.NewMarionetteAdapter()
	im.marionette = im.adapter.GetCore()

	return nil
}

// GetModuleStatus returns the status of all modules
func (im *IntegrationManager) GetModuleStatus() map[string]string {
	status := make(map[string]string)

	// Check Marionette status
	if im.marionette != nil {
		status["marionette"] = "active"
	} else {
		status["marionette"] = "inactive"
	}

	// Check ML system status
	if im.marionette.GetAdaptiveLearning() != nil {
		status["adaptive_learning"] = "active"
	} else {
		status["adaptive_learning"] = "inactive"
	}

	// Check effectiveness metrics status
	if im.marionette.GetEffectivenessMetrics() != nil {
		status["effectiveness_metrics"] = "active"
	} else {
		status["effectiveness_metrics"] = "inactive"
	}

	return status
}
