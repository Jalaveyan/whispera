// Package obfuscator provides the obfuscation module using the integrated engine
package obfuscator

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/obfuscation"
)

const (
	ModuleName    = "obfuscation.engine"
	ModuleVersion = "2.0.0"
)

// Config holds obfuscator configuration
type Config struct {
	DefaultProfile string
	ThreatLevel    int
	EnableML       bool
	EnableFTE      bool
	WorkerCount    int

	// Anti-reputation evasion (edge-node filtering bypass)
	EnableJitter             bool // Add human-like timing jitter between operations
	EnableResidentialMimicry bool // Mimic residential connection patterns
	ConnectionBurstLimit     int  // Max connections per second (0 = unlimited)
	JitterMinMs              int  // Minimum jitter delay in ms
	JitterMaxMs              int  // Maximum jitter delay in ms
}

// DefaultConfig returns default obfuscator configuration
func DefaultConfig() *Config {
	return &Config{
		DefaultProfile: "default",
		ThreatLevel:    5,
		EnableML:       true,
		EnableFTE:      true,
		WorkerCount:    4,
		// Anti-reputation evasion defaults
		EnableJitter:             true,
		EnableResidentialMimicry: true,
		ConnectionBurstLimit:     10, // Max 10 connections/sec
		JitterMinMs:              50, // 50-300ms human-like delays
		JitterMaxMs:              300,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ThreatLevel < 0 || c.ThreatLevel > 10 {
		c.ThreatLevel = 5
	}
	return nil
}

// Engine implements interfaces.Obfuscator by wrapping internal/obfuscation.IntegrationManager
type Engine struct {
	*base.Module
	config  *Config
	manager *obfuscation.IntegrationManager
	mu      sync.RWMutex

	// Cache current settings
	currentProfile string
	threatLevel    int

	// Anti-reputation state
	jitterRand      *rand.Rand
	lastConnTime    time.Time
	connCountWindow int
	windowStart     time.Time
}

// New creates a new obfuscation engine
func New(cfg *Config) (*Engine, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Initialize the legacy core engine
	// Note: We use NewIntegrationManagerWithOptions to control ML/FTE
	manager := obfuscation.NewIntegrationManagerWithOptions(cfg.EnableML, cfg.EnableFTE)

	e := &Engine{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		config:         cfg,
		manager:        manager,
		currentProfile: cfg.DefaultProfile,
		threatLevel:    cfg.ThreatLevel,
	}

	return e, nil
}

// Init initializes the obfuscator
func (e *Engine) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := e.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if obfsCfg, ok := cfg.(*Config); ok {
		e.config = obfsCfg
		// Re-initialize manager if config changed significantly (optional, keeping simple for now)
	}

	// Apply initial configuration
	if err := e.SetProfile(e.config.DefaultProfile); err != nil {
		// Fallback to default if configured profile fails
		_ = e.SetProfile("default")
	}
	e.SetThreatLevel(e.config.ThreatLevel)

	return nil
}

// Start starts the obfuscator
func (e *Engine) Start() error {
	if err := e.Module.Start(); err != nil {
		return err
	}

	e.SetHealthy(true, fmt.Sprintf("Active Profile: %s, Threat Level: %d", e.currentProfile, e.threatLevel))

	e.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"profile":      e.currentProfile,
		"threat_level": e.threatLevel,
		"ml_enabled":   e.config.EnableML,
		"fte_enabled":  e.config.EnableFTE,
	})

	return nil
}

// Stop stops the obfuscator
func (e *Engine) Stop() error {
	e.PublishEvent(events.EventTypeModuleStopped, nil)
	return e.Module.Stop()
}

// Process obfuscates or deobfuscates data using the IntegrationManager
func (e *Engine) Process(data []byte, direction interfaces.Direction) ([]byte, time.Duration, error) {
	e.UpdateActivity()

	// Anti-reputation: Apply timing jitter for outbound traffic
	var jitterDelay time.Duration
	if direction == interfaces.DirectionOutbound && e.config.EnableJitter {
		jitterDelay = e.calculateJitter()
	}

	// Map Direction type to string expected by IntegrationManager
	dirStr := "outbound"
	if direction == interfaces.DirectionInbound {
		dirStr = "inbound"
	}

	// Delegate to the comprehensive engine
	// The IntegrationManager handles FTE -> Marionette -> ML chain
	processed, delay, err := e.manager.ProcessTraffic(data, dirStr)
	if err != nil {
		return data, 0, err
	}

	// Combine obfuscation delay with anti-reputation jitter
	totalDelay := delay + jitterDelay
	return processed, totalDelay, nil
}

// calculateJitter returns a human-like random delay for anti-reputation evasion
func (e *Engine) calculateJitter() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Initialize random source if needed
	if e.jitterRand == nil {
		e.jitterRand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	// Connection burst limiting
	now := time.Now()
	if e.config.ConnectionBurstLimit > 0 {
		if now.Sub(e.windowStart) > time.Second {
			// Reset window
			e.windowStart = now
			e.connCountWindow = 0
		}
		e.connCountWindow++

		// If exceeding burst limit, add extra delay
		if e.connCountWindow > e.config.ConnectionBurstLimit {
			extraDelay := time.Duration(e.connCountWindow-e.config.ConnectionBurstLimit) * 100 * time.Millisecond
			return extraDelay
		}
	}

	// Calculate human-like jitter
	minMs := e.config.JitterMinMs
	maxMs := e.config.JitterMaxMs
	if minMs <= 0 {
		minMs = 50
	}
	if maxMs <= minMs {
		maxMs = minMs + 250
	}

	// Residential mimicry: occasional longer pauses (simulates user thinking)
	if e.config.EnableResidentialMimicry && e.jitterRand.Float64() < 0.05 {
		// 5% chance of a longer "thinking" pause (500-2000ms)
		return time.Duration(500+e.jitterRand.Intn(1500)) * time.Millisecond
	}

	// Standard jitter
	jitterMs := minMs + e.jitterRand.Intn(maxMs-minMs)
	return time.Duration(jitterMs) * time.Millisecond
}

// SetProfile sets the obfuscation profile
func (e *Engine) SetProfile(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.manager.SetProfile(name); err != nil {
		return err
	}

	e.currentProfile = name
	e.SetHealthy(true, fmt.Sprintf("Profile: %s", name))

	e.PublishEvent("obfuscation.profile_changed", map[string]interface{}{
		"new_profile": name,
	})

	return nil
}

// GetProfile returns the current profile name
func (e *Engine) GetProfile() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentProfile
}

// SetThreatLevel sets the current threat level
func (e *Engine) SetThreatLevel(level int) {
	if level < 0 {
		level = 0
	}
	if level > 10 {
		level = 10
	}

	e.mu.Lock()
	e.threatLevel = level
	e.mu.Unlock()

	// Map threat level logic to the underlying engine
	// Level 8+ maps to "Strict" mode in IntegrationManager
	isStrict := level >= 8
	e.manager.SetStrict(isStrict)

	e.PublishEvent("obfuscation.threat_level_changed", map[string]interface{}{
		"threat_level": level,
		"strict_mode":  isStrict,
	})
}

// GetStats returns obfuscation statistics
func (e *Engine) GetStats() interfaces.ObfuscationStats {
	// Fetch metrics from the manager
	metrics := e.manager.GetPerformanceMetrics()

	// Default values
	var pkts, bytes uint64
	var avgLat time.Duration

	// Safe type assertions from the map[string]interface{} returned by manager
	// Note: IntegrationManager returns generic maps, so we must be defensive
	if sys, ok := metrics["system"].(map[string]interface{}); ok {
		if p, ok := sys["packets_processed"].(uint64); ok {
			pkts = p
		} else if p, ok := sys["packets_processed"].(int64); ok {
			pkts = uint64(p)
		}

		if latStr, ok := sys["average_latency"].(string); ok {
			avgLat, _ = time.ParseDuration(latStr)
		}
	}

	if traffic, ok := metrics["traffic"].(map[string]interface{}); ok {
		if b, ok := traffic["total_bytes"].(int64); ok {
			bytes = uint64(b)
		}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return interfaces.ObfuscationStats{
		PacketsProcessed: pkts,
		BytesProcessed:   bytes,
		AvgProcessTime:   avgLat,
		ProfileName:      e.currentProfile,
		ThreatLevel:      e.threatLevel,
	}
}

// HealthCheck returns health status
func (e *Engine) HealthCheck() interfaces.HealthStatus {
	status := e.Module.HealthCheck()

	// Get deep health status from manager
	internalHealth := e.manager.GetHealthStatus()

	status.Details["profile"] = e.currentProfile
	status.Details["threat_level"] = e.threatLevel
	status.Details["internal_modules"] = internalHealth

	return status
}

// Factory creates obfuscator modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
