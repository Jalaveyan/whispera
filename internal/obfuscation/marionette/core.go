package marionette

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"whispera/internal/obfuscation/behavioral"
	"whispera/internal/obfuscation/core/types"
	mlpkg "whispera/internal/obfuscation/ml"
	"whispera/internal/util"

	utls "github.com/refraction-networking/utls"
)

// Marionette core orchestration logic for obfuscation and evasion.

const (
	jsonChars               = "abcdefghijklmnopqrstuvwxyz0123456789{}[]\":,"
	stateHalfOpen           = "half-open"
	profileYandexMarionette = "yandex"
	profileMailruMarionette = "mailru"
	profileRutubeMarionette = "rutube"
	profileOzonMarionette   = "ozon"
)

// Reference constants to silence staticcheck unused warnings
var _ = []interface{}{
	jsonChars,
	stateHalfOpen,
	profileYandexMarionette,
	profileMailruMarionette,
	profileRutubeMarionette,
	profileOzonMarionette,
}

// NewMarionette initializes a new Marionette instance.
func NewMarionette() *Marionette {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Marionette{
		Rand:  rand.New(rand.NewSource(time.Now().UnixNano())),
		Rules: make([]types.ObfuscationRule, 0),
		State: &types.TrafficState{
			MaxHistorySize:  1000,
			LastCleanup:     util.GetGlobalTimeCache().Now(),
			CleanupInterval: 30 * time.Second,
		},
		Profiles:         make(map[string]*types.TrafficProfile),
		MlSystem:         mlpkg.NewUnifiedMLSystem(),
		AdaptiveLearning: NewAdaptiveLearning(),
		Effectiveness:    NewEffectivenessMetrics(),
		AdaptiveManager:  NewAdaptiveProfileManager(),
		CircuitBreaker: &CircuitBreaker{
			State:     "closed",
			Threshold: 5,
			Timeout:   30 * time.Second,
		},
		Metrics: &SystemMetrics{
			LastCleanup: util.GetGlobalTimeCache().Now(),
		},
		FallbackMode: false,
		Profiler:     types.NewTrafficProfiler(),
		StateMachine: types.NewProtocolStateMachine(),
		Ctx:          ctx,
		Cancel:       cancel,
	}
	m.EvasionPool = NewEvasionPool(m, 100)
	m.EvasionPool.Start()
	m.initDynamicProfileManager()
	m.initDefaultProfiles()
	m.initDefaultRules()
	m.initRussianServiceProfiles()
	m.initMobileDeviceProfiles()
	for name, profile := range m.Profiles {
		m.Profiler.RegisterProfile(name, profile)
	}
	return m
}

// SetUTLSConn sets the active uTLS connection for fingerprint extraction
func (m *Marionette) SetUTLSConn(conn *utls.UConn) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.UTLSConn = conn
}

// isTLSHandshake checks if the data is a TLS handshake packet that should NOT be modified
// TLS record: byte 0 = content type (0x16 = handshake, 0x17 = application data)
// If we modify TLS handshake packets, the server will send RST because it can't parse them
func isTLSHandshake(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	contentType := data[0]
	// TLS versions: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2/1.3)
	majorVersion := data[1]
	minorVersion := data[2]

	// Check for TLS handshake (0x16) or change cipher spec (0x14) or alert (0x15)
	isTLSContentType := contentType == 0x16 || contentType == 0x14 || contentType == 0x15
	// Check for valid TLS version
	isValidVersion := majorVersion == 0x03 && (minorVersion >= 0x01 && minorVersion <= 0x04)

	return isTLSContentType && isValidVersion
}

// isTLSApplicationData checks if the data is TLS application data (0x17)
// Application data CAN be obfuscated because it's already encrypted
func isTLSApplicationData(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	return data[0] == 0x17 && data[1] == 0x03 && (data[2] >= 0x01 && data[2] <= 0x04)
}

// ProcessPacket applies obfuscation rules to a packet with ML analysis
// Now integrates with BehaviorEngine for realistic traffic timing
func (m *Marionette) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	m.Mutex.RLock()
	isFallback := m.FallbackMode
	behaviorEngine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if isFallback {
		return data, 0, nil
	}

	// CRITICAL: Never modify TLS handshake packets!
	// This would corrupt the ClientHello/ServerHello and cause RST from the server
	// Only allow obfuscation of TLS application data (which is already encrypted)
	if isTLSHandshake(data) {
		// Track TLS handshakes for statistics but don't modify
		m.Mutex.Lock()
		m.Metrics.PacketsProcessed++
		m.updateStateInProcess(data, direction)
		m.Mutex.Unlock()
		return data, 0, nil
	}

	// Calculate behavioral delay if engine is active
	var behavioralDelay time.Duration
	if behaviorEngine != nil {
		behavioralDelay = behaviorEngine.NextPacketDelay()

		// Transition state machine based on traffic direction
		if direction == "outbound" {
			behaviorEngine.TransitionState()
		}
	}

	// Check if this is TLS application data (can be obfuscated)
	canObfuscate := isTLSApplicationData(data)

	suggested := m.Profiler.SuggestProfile(data)
	if suggested != "" && suggested != m.Active {
		// Log suggestion
	}

	m.StateMachine.Transition("DATA_PACKET")

	m.Mutex.Lock()
	m.updateStateInProcess(data, direction)
	rules := m.Rules
	count := m.State.PacketCount
	m.Metrics.PacketsProcessed++
	m.Mutex.Unlock()

	if count%100 == 0 {
		m.triggerAsyncAnalysis()
	}

	processed := data

	// Only apply obfuscation rules to TLS application data
	if canObfuscate {
		for _, rule := range rules {
			if !rule.Enabled || rule.Priority < 7 {
				continue
			}
			if m.evaluateConditionFast(rule.Condition) {
				actionProcessed, _ := m.applyAction(rule.Action, processed, rule.Parameters)
				processed = actionProcessed
			}
		}
	}

	return processed, behavioralDelay, nil
}

func (m *Marionette) updateStateInProcess(data []byte, direction string) {
	m.State.PacketCount++
	m.State.ByteCount += int64(len(data))
	m.State.Direction = direction

	prevLastPacket := m.State.LastPacket
	now := util.GetGlobalTimeCache().Now()
	m.State.LastPacket = now

	if m.State.PacketCount%10 == 0 {
		if !prevLastPacket.IsZero() {
			interval := now.Sub(prevLastPacket)
			m.appendInterval(interval)
		}
		m.appendPacketSize(len(data))
	}
}

func (m *Marionette) appendInterval(interval time.Duration) {
	m.State.Intervals = append(m.State.Intervals, interval)
	if len(m.State.Intervals) > 50 {
		copy(m.State.Intervals, m.State.Intervals[1:])
		m.State.Intervals = m.State.Intervals[:49]
	}
}

func (m *Marionette) appendPacketSize(size int) {
	m.State.PacketSizes = append(m.State.PacketSizes, size)
	if len(m.State.PacketSizes) > 50 {
		copy(m.State.PacketSizes, m.State.PacketSizes[1:])
		m.State.PacketSizes = m.State.PacketSizes[:49]
	}
}

func (m *Marionette) triggerAsyncAnalysis() {
	go func() {
		m.Mutex.RLock()
		active := m.Active
		profile := m.Profiles[active]
		m.Mutex.RUnlock()

		m.detectDPI()
		if profile != nil {
			m.updateProfileFromRealTraffic(profile, active)
		}
	}()
}

// SetThreatLevel sets the current threat level
func (m *Marionette) SetThreatLevel(level int) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.State.ThreatLevel = level
}

// SetActiveProfile sets the active traffic profile
func (m *Marionette) SetActiveProfile(name string) error {
	m.Mutex.RLock()
	_, exists := m.Profiles[name]
	m.Mutex.RUnlock()

	if !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	m.Mutex.Lock()
	m.Active = name
	m.State.Protocol = name
	m.Mutex.Unlock()
	return nil
}

// GetState returns current traffic state
func (m *Marionette) GetState() *types.TrafficState {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	stateCopy := *m.State
	return &stateCopy
}

// GetProfileNames returns available profile names
func (m *Marionette) GetProfileNames() []string {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	names := make([]string, 0, len(m.Profiles))
	for name := range m.Profiles {
		names = append(names, name)
	}
	return names
}

// AddProfile adds a new profile
func (m *Marionette) AddProfile(name string, config map[string]interface{}) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if _, exists := m.Profiles[name]; exists {
		return fmt.Errorf("profile %s already exists", name)
	}

	profile := m.createProfileFromConfig(name, config)
	m.Profiles[name] = profile
	return nil
}

// RemoveProfile removes a profile
func (m *Marionette) RemoveProfile(name string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if _, exists := m.Profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	if m.Active == name {
		return fmt.Errorf("cannot remove active profile %s", name)
	}

	delete(m.Profiles, name)
	return nil
}

func (m *Marionette) createProfileFromConfig(name string, config map[string]interface{}) *types.TrafficProfile {
	profile := &types.TrafficProfile{
		Name:       name,
		Type:       "custom",
		CreatedAt:  util.GetGlobalTimeCache().Now(),
		LastUsed:   util.GetGlobalTimeCache().Now(),
		Adaptation: types.AdaptationProfile{Enabled: true},
	}

	if profileType, ok := config["type"].(string); ok {
		profile.Type = profileType
	}

	if obfuscation, ok := config["obfuscation"].(map[string]interface{}); ok {
		profile.BehavioralData = make(map[string]interface{})
		profile.BehavioralData["obfuscation"] = obfuscation
	}

	return profile
}

func (m *Marionette) GetActiveProfile() string {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	return m.Active
}

// SetStrict enables or disables strict obfuscation mode
func (m *Marionette) SetStrict(strict bool) {
	// Currently just a placeholder for future strict mode logic
}

// SetUTLSFingerprint sets the browser fingerprint for TLS evasion
// Supported values: "chrome", "firefox", "safari", "android", "random"
func (m *Marionette) SetUTLSFingerprint(fingerprint string) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.UTLSFingerprint = fingerprint
}

// GetUTLSFingerprint returns the current browser fingerprint setting
func (m *Marionette) GetUTLSFingerprint() string {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	if m.UTLSFingerprint == "" {
		return "chrome"
	}
	return m.UTLSFingerprint
}

// --- Marionette Adapter ---

// MarionetteAdapter provides backward compatibility for the old marionette.go interface
type MarionetteAdapter struct {
	m *Marionette
}

// NewMarionetteAdapter creates a new adapter for backward compatibility
func NewMarionetteAdapter() *MarionetteAdapter {
	return &MarionetteAdapter{
		m: NewMarionette(),
	}
}

// ProcessPacket processes a packet through the obfuscation system
func (ma *MarionetteAdapter) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	return ma.m.ProcessPacket(data, direction)
}

// SetThreatLevel sets the threat level (proxying to the underlying Marionette)
func (ma *MarionetteAdapter) SetThreatLevel(level int) {
	ma.m.SetThreatLevel(level)
}

// GetCore returns the underlying Marionette instance
func (ma *MarionetteAdapter) GetCore() *Marionette {
	return ma.m
}

// SetActiveProfile sets the active traffic profile
func (ma *MarionetteAdapter) SetActiveProfile(name string) error {
	return ma.m.SetActiveProfile(name)
}

// GetProfileNames returns available profile names
func (ma *MarionetteAdapter) GetProfileNames() []string {
	return ma.m.GetProfileNames()
}

// GetState returns current traffic state
func (ma *MarionetteAdapter) GetState() *types.TrafficState {
	return ma.m.GetState()
}

// HealthCheck performs health check
func (ma *MarionetteAdapter) HealthCheck() map[string]interface{} {
	return ma.m.HealthCheck()
}

// GetSystemMetrics returns system performance metrics
func (ma *MarionetteAdapter) GetSystemMetrics() *SystemMetrics {
	return ma.m.GetSystemMetrics()
}

// SetStrict enables or disables strict mode
func (ma *MarionetteAdapter) SetStrict(strict bool) {
	ma.m.SetStrict(strict)
}

// AddProfile adds a new profile
func (ma *MarionetteAdapter) AddProfile(name string, config map[string]interface{}) error {
	return ma.m.AddProfile(name, config)
}

// RemoveProfile removes a profile
func (ma *MarionetteAdapter) RemoveProfile(name string) error {
	return ma.m.RemoveProfile(name)
}

// SwitchProfile switches the active profile
func (ma *MarionetteAdapter) SwitchProfile(profile string, reason string) error {
	return ma.m.SwitchProfile(profile, reason)
}

// GetCurrentProfile returns the current profile
func (ma *MarionetteAdapter) GetCurrentProfile() string {
	return ma.m.GetCurrentProfile()
}

// GetProfileSwitchHistory returns profile switch history
func (ma *MarionetteAdapter) GetProfileSwitchHistory() []types.ProfileSwitch {
	return ma.m.GetProfileSwitchHistory()
}

// ApplyProductionDPIEvasion applies DPI evasion for a specific service
func (ma *MarionetteAdapter) ApplyProductionDPIEvasion(data []byte, service string) ([]byte, time.Duration, error) {
	return ma.m.ApplyProductionDPIEvasion(data, service)
}

// StartDynamicManager starts the dynamic profile manager
func (ma *MarionetteAdapter) StartDynamicManager() {
	ma.m.StartDynamicManager()
}

// =============================================================================
// BEHAVIORAL MIMICRY METHODS
// =============================================================================

// SetBehavioralProfile activates a complete messenger behavioral profile
// This enables full multi-layer traffic imitation (TCP, TLS, L7, timing)
// Supports both Android and iOS variants: use "telegram_ios", "vk_ios", etc.
func (m *Marionette) SetBehavioralProfile(profileName string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	var profile *behavioral.MessengerProfile
	var isIOS bool

	switch profileName {
	// Android profiles
	case "telegram":
		profile = behavioral.TelegramProfile()
	case "vk", "vk_messenger":
		profile = behavioral.VKMessengerProfile()
	case "vkvideo", "vk_video":
		profile = behavioral.VKVideoProfile()
	case "instagram":
		profile = behavioral.InstagramProfile()
	case "max", "max_messenger":
		profile = behavioral.MaxMessengerProfile()
	case "wechat":
		profile = behavioral.WeChatProfile()
	case "facebook", "messenger", "fb_messenger":
		profile = behavioral.FacebookMessengerProfile()

	// iOS profiles
	case "telegram_ios":
		profile = behavioral.TelegramIOSProfile()
		isIOS = true
	case "vk_ios", "vk_messenger_ios":
		profile = behavioral.VKMessengerIOSProfile()
		isIOS = true
	case "instagram_ios":
		profile = behavioral.InstagramIOSProfile()
		isIOS = true
	case "facebook_ios", "messenger_ios", "fb_messenger_ios":
		profile = behavioral.FacebookMessengerIOSProfile()
		isIOS = true
	case "wechat_ios":
		profile = behavioral.WeChatIOSProfile()
		isIOS = true

	default:
		return fmt.Errorf("unknown behavioral profile: %s, available: telegram, vk, vkvideo, instagram, max, wechat, facebook (add '_ios' for iOS variant)", profileName)
	}

	m.ActiveBehavioralProfile = profile
	m.BehaviorEngine = behavioral.NewBehaviorEngine(profile)

	// Set matching uTLS fingerprint
	if isIOS {
		m.UTLSFingerprint = "ios"
	} else {
		m.UTLSFingerprint = "android"
	}

	return nil
}

// GetBehavioralDelay returns the next packet delay based on behavioral model
func (m *Marionette) GetBehavioralDelay() time.Duration {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine == nil {
		return 0
	}

	return engine.NextPacketDelay()
}

// GetBehavioralPacketSize returns recommended packet size based on current state
func (m *Marionette) GetBehavioralPacketSize() int {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine == nil {
		return 0
	}

	return engine.NextPacketSize()
}

// TransitionBehavioralState advances the behavioral state machine
func (m *Marionette) TransitionBehavioralState() {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine != nil {
		engine.TransitionState()
	}
}

// GetBehavioralState returns current behavioral state
func (m *Marionette) GetBehavioralState() string {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine == nil {
		return "none"
	}

	return engine.GetCurrentState()
}

// SetBehavioralState manually sets the behavioral state
func (m *Marionette) SetBehavioralState(state string) {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine != nil {
		engine.SetState(state)
	}
}

// GetActiveBehavioralProfile returns the active behavioral profile info
func (m *Marionette) GetActiveBehavioralProfile() string {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	if m.ActiveBehavioralProfile == nil {
		return "none"
	}
	return m.ActiveBehavioralProfile.Name
}
