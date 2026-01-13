package marionette

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"whispera/internal/obfuscation/behavioral"
	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/obfuscation/core/types"
	mlpkg "whispera/internal/obfuscation/ml"

	utls "github.com/refraction-networking/utls"
)

// Marionette structure now defined locally to allow method attachment
type Marionette struct {
	Rules            []types.ObfuscationRule
	State            *types.TrafficState
	Profiles         map[string]*types.TrafficProfile
	Active           string
	Mutex            sync.RWMutex
	MlSystem         *mlpkg.UnifiedMLSystem
	AdaptiveLearning *AdaptiveLearning
	Effectiveness    *EffectivenessMetrics
	CoverTraffic     []byte
	DynamicManager   *DynamicProfileManagerImpl
	RealAPI          types.RealAPIIntegrationInterface
	AdaptiveManager  types.AdaptiveProfileManager
	CircuitBreaker   *CircuitBreaker
	Metrics          *SystemMetrics
	FallbackMode     bool
	EvasionPool      *EvasionPool
	Profiler         *types.TrafficProfiler
	StateMachine     *types.ProtocolStateMachine
	Rand             *rand.Rand
	Ctx              context.Context
	Cancel           context.CancelFunc
	Wg               sync.WaitGroup

	// uTLS Integration - real browser fingerprints
	UTLSFingerprint string // "chrome", "firefox", "safari", "android", "random"
	UTLSConn        *utls.UConn

	// Behavioral Mimicry - full multi-layer traffic imitation
	BehaviorEngine          *behavioral.BehaviorEngine
	ActiveBehavioralProfile *behavioral.MessengerProfile

	// Artificial Traffic - Chaff Generator
	Chaff *ChaffGenerator
}

// CircuitBreaker alias
type CircuitBreaker = evasion.CircuitBreaker

type AdvancedMimicryProfile struct {
	Enabled            bool   `json:"enabled"`
	MimicryLevel       int    `json:"mimicry_level"`
	TargetService      string `json:"target_service"`
	BehavioralMimicry  bool   `json:"behavioral_mimicry"`
	TimingMimicry      bool   `json:"timing_mimicry"`
	SizeMimicry        bool   `json:"size_mimicry"`
	HeaderMimicry      bool   `json:"header_mimicry"`
	AdaptiveMimicry    bool   `json:"adaptive_mimicry"`
	MLResistance       bool   `json:"ml_resistance"`
	FingerprintEvasion bool   `json:"fingerprint_evasion"`
	StatisticalMasking bool   `json:"statistical_masking"`
}

type WebsiteFingerprintDefenseProfile struct {
	Enabled              bool          `json:"enabled"`
	PaddingStrategy      string        `json:"padding_strategy"`
	TimingObfuscation    bool          `json:"timing_obfuscation"`
	SizeObfuscation      bool          `json:"size_obfuscation"`
	DirectionObfuscation bool          `json:"direction_obfuscation"`
	CoverTraffic         bool          `json:"cover_traffic"`
	CoverProbability     float64       `json:"cover_probability"`
	CoverSize            int           `json:"cover_size"`
	CoverInterval        time.Duration `json:"cover_interval"`
	ObfuscationLevel     int           `json:"obfuscation_level"`
}

type TrafficObfuscationProfile struct {
	Enabled             bool   `json:"enabled"`
	ObfuscationType     string `json:"obfuscation_type"`
	ObfuscationLevel    int    `json:"obfuscation_level"`
	AdaptiveObfuscation bool   `json:"adaptive_obfuscation"`
	StatisticalMasking  bool   `json:"statistical_masking"`
	EntropyAdjustment   bool   `json:"entropy_adjustment"`
	TimingRandomization bool   `json:"timing_randomization"`
	SizeRandomization   bool   `json:"size_randomization"`
	TargetService       string `json:"target_service"`
}

// SystemMetrics alias
type SystemMetrics = types.SystemMetrics
