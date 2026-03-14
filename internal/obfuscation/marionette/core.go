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


const (
	jsonChars               = "abcdefghijklmnopqrstuvwxyz0123456789{}[]\":,"
	stateHalfOpen           = "half-open"
	profileYandexMarionette = "yandex"
	profileMailruMarionette = "mailru"
	profileRutubeMarionette = "rutube"
	profileOzonMarionette   = "ozon"
)

var _ = []interface{}{
	jsonChars,
	stateHalfOpen,
	profileYandexMarionette,
	profileMailruMarionette,
	profileRutubeMarionette,
	profileOzonMarionette,
}

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

	m.Chaff = NewChaffGenerator()
	m.Chaff.Start()

	m.initRussianServiceProfiles()
	m.initMobileDeviceProfiles()
	for name, profile := range m.Profiles {
		m.Profiler.RegisterProfile(name, profile)
	}
	return m
}

func (m *Marionette) SetUTLSConn(conn *utls.UConn) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.UTLSConn = conn
}

func (m *Marionette) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	m.Mutex.RLock()
	isFallback := m.FallbackMode
	behaviorEngine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if isFallback {
		return data, 0, nil
	}

	if direction == "inbound" {
		return m.Deobfuscate(data)
	}


	var behavioralDelay time.Duration
	if behaviorEngine != nil {
		d := behaviorEngine.NextPacketDelay()
		behaviorEngine.TransitionState()
		// Cap the behavioral delay so VPN data throughput is not destroyed.
		// Messenger profiles model human-scale inter-message timing (up to 30s
		// in idle state), which is correct at the session level but kills
		// throughput if applied to every individual VPN packet.  5 ms gives
		// enough jitter to defeat per-packet timing fingerprinting without a
		// significant throughput hit.
		const maxPacketDelay = 5 * time.Millisecond
		if d > maxPacketDelay {
			d = maxPacketDelay
		}
		behavioralDelay = d
	}

	if isLocalDiscovery(data) {
		return nil, 0, nil
	}

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
	canObfuscate := true

	suggested := m.Profiler.SuggestProfile(data)
	if suggested != "" && suggested != m.Active && !m.lockedProfile {
		_ = m.SetActiveProfile(suggested)
	}

	m.StateMachine.Transition("DATA_PACKET")

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

	processed = m.applyMLPipeline(processed, direction)

	return processed, behavioralDelay, nil
}

func (m *Marionette) Deobfuscate(data []byte) ([]byte, time.Duration, error) {
	if len(data) < 5 {
		return data, 0, nil
	}

	if data[0] == 0x17 && data[1] == 0x03 {
		if data[2] >= 0x01 && data[2] <= 0x04 {
			return data[5:], 0, nil
		}
	}


	isTLSRecord := func(b []byte, typ byte) (bool, int) {
		if len(b) < 5 {
			return false, 0
		}
		if b[0] != typ {
			return false, 0
		}
		if b[1] != 0x03 {
			return false, 0
		}
		l := int(b[3])<<8 | int(b[4])
		return true, 5 + l
	}

	if ok, n := isTLSRecord(data, 0x16); ok {
		if len(data) == n {
			return []byte{}, 0, nil
		}
		data = data[n:]

		if ok, n := isTLSRecord(data, 0x14); ok {
			if len(data) == n {
				return []byte{}, 0, nil
			}
			data = data[n:]
		}

		if ok, n := isTLSRecord(data, 0x17); ok {
			if len(data) == n {
				return []byte{}, 0, nil
			}
			return m.Deobfuscate(data[n:])
		}

		if len(data) > 0 {
			return m.Deobfuscate(data)
		}
		return []byte{}, 0, nil
	}


	if len(data) < 16 {
		return data, 0, nil
	}

	prefix := string(data[:8])
	isValidHTTP := false

	switch {
	case len(data) >= 3 && (prefix[:3] == "GET" || prefix[:3] == "PUT"):
		isValidHTTP = true
	case len(data) >= 4 && (prefix[:4] == "POST" || prefix[:4] == "HEAD" || prefix[:4] == "HTTP"):
		isValidHTTP = true
	case len(data) >= 5 && (prefix[:5] == "PATCH" || prefix[:5] == "TRACE"):
		isValidHTTP = true
	case len(data) >= 6 && prefix[:6] == "DELETE":
		isValidHTTP = true
	case len(data) >= 7 && (prefix[:7] == "OPTIONS" || prefix[:7] == "CONNECT"):
		isValidHTTP = true
	}

	if !isValidHTTP {
		return data, 0, nil
	}

	maxScan := 4096
	if len(data) < maxScan {
		maxScan = len(data)
	}

	for i := 0; i < maxScan-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return data[i+4:], 0, nil
		}
	}

	return data, 0, nil
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
		locked := m.lockedProfile
		m.Mutex.RUnlock()

		dpiThreat := m.detectDPI()
		if profile != nil {
			m.updateProfileFromRealTraffic(profile, active)
		}

		m.mlDrivenProfileSwitch(dpiThreat, active, locked)
	}()
}

func (m *Marionette) SetThreatLevel(level int) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.State.ThreatLevel = level
}

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

func (m *Marionette) GetState() *types.TrafficState {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	stateCopy := *m.State
	return &stateCopy
}

func (m *Marionette) GetProfileNames() []string {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	names := make([]string, 0, len(m.Profiles))
	for name := range m.Profiles {
		names = append(names, name)
	}
	return names
}

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

func (m *Marionette) SetStrict(strict bool) {
}

func (m *Marionette) SetUTLSFingerprint(fingerprint string) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.UTLSFingerprint = fingerprint
}

func (m *Marionette) GetUTLSFingerprint() string {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	if m.UTLSFingerprint == "" {
		return "chrome"
	}
	return m.UTLSFingerprint
}


type MarionetteAdapter struct {
	m *Marionette
}

func NewMarionetteAdapter() *MarionetteAdapter {
	return &MarionetteAdapter{
		m: NewMarionette(),
	}
}

func (ma *MarionetteAdapter) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	return ma.m.ProcessPacket(data, direction)
}

func (ma *MarionetteAdapter) SetThreatLevel(level int) {
	ma.m.SetThreatLevel(level)
}

func (ma *MarionetteAdapter) SetRealityKey(key string) {
	ma.m.SetRealityKey(key)
}

func (ma *MarionetteAdapter) GetCore() *Marionette {
	return ma.m
}

func (ma *MarionetteAdapter) SetActiveProfile(name string) error {
	return ma.m.SetActiveProfile(name)
}

func (ma *MarionetteAdapter) GetProfileNames() []string {
	return ma.m.GetProfileNames()
}

func (ma *MarionetteAdapter) GetState() *types.TrafficState {
	return ma.m.GetState()
}

func (ma *MarionetteAdapter) HealthCheck() map[string]interface{} {
	return ma.m.HealthCheck()
}

func (ma *MarionetteAdapter) GetSystemMetrics() *SystemMetrics {
	return ma.m.GetSystemMetrics()
}

func (ma *MarionetteAdapter) SetStrict(strict bool) {
	ma.m.SetStrict(strict)
}

func (ma *MarionetteAdapter) AddProfile(name string, config map[string]interface{}) error {
	return ma.m.AddProfile(name, config)
}

func (ma *MarionetteAdapter) RemoveProfile(name string) error {
	return ma.m.RemoveProfile(name)
}

func (ma *MarionetteAdapter) SwitchProfile(profile string, reason string) error {
	return ma.m.SwitchProfile(profile, reason)
}

func (ma *MarionetteAdapter) GetCurrentProfile() string {
	return ma.m.GetCurrentProfile()
}

func (ma *MarionetteAdapter) GetProfileSwitchHistory() []types.ProfileSwitch {
	return ma.m.GetProfileSwitchHistory()
}

func (ma *MarionetteAdapter) ApplyProductionDPIEvasion(data []byte, service string) ([]byte, time.Duration, error) {
	return ma.m.ApplyProductionDPIEvasion(data, service)
}

func (ma *MarionetteAdapter) StartDynamicManager() {
	ma.m.StartDynamicManager()
}


func (m *Marionette) SetBehavioralProfile(profileName string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	var profile *behavioral.MessengerProfile
	var isIOS bool

	// obfuscationProfile is the traffic-shaping profile name used by the rule engine.
	// utlsFP is the uTLS ClientHello preset used for JA3/JA4 fingerprint evasion.
	var obfuscationProfile, utlsFP string

	switch profileName {
	case "telegram":
		profile = behavioral.TelegramProfile()
		obfuscationProfile = "websocket" // closest to Telegram's MTProto-over-WebSocket look
		utlsFP = "android"
	case "vk", "vk_messenger":
		profile = behavioral.VKMessengerProfile()
		obfuscationProfile = "vk"
		utlsFP = "vk"
	case "vkvideo", "vk_video":
		profile = behavioral.VKVideoProfile()
		obfuscationProfile = "vk"
		utlsFP = "vk"
	case "instagram":
		profile = behavioral.InstagramProfile()
		obfuscationProfile = "http2"
		utlsFP = "android"
	case "max", "max_messenger":
		profile = behavioral.MaxMessengerProfile()
		obfuscationProfile = "mailru" // MAX is Mail.ru's product
		utlsFP = "max"
	case "wechat":
		profile = behavioral.WeChatProfile()
		obfuscationProfile = "http2"
		utlsFP = "android"
	case "facebook", "messenger", "fb_messenger":
		profile = behavioral.FacebookMessengerProfile()
		obfuscationProfile = "http2"
		utlsFP = "android"

	case "telegram_ios":
		profile = behavioral.TelegramIOSProfile()
		obfuscationProfile = "websocket"
		utlsFP = "ios"
		isIOS = true
	case "vk_ios", "vk_messenger_ios":
		profile = behavioral.VKMessengerIOSProfile()
		obfuscationProfile = "vk"
		utlsFP = "ios"
		isIOS = true
	case "instagram_ios":
		profile = behavioral.InstagramIOSProfile()
		obfuscationProfile = "http2"
		utlsFP = "ios"
		isIOS = true
	case "facebook_ios", "messenger_ios", "fb_messenger_ios":
		profile = behavioral.FacebookMessengerIOSProfile()
		obfuscationProfile = "http2"
		utlsFP = "ios"
		isIOS = true
	case "wechat_ios":
		profile = behavioral.WeChatIOSProfile()
		obfuscationProfile = "http2"
		utlsFP = "ios"
		isIOS = true

	default:
		return fmt.Errorf("unknown behavioral profile: %s, available: telegram, vk, vkvideo, instagram, max, wechat, facebook (add '_ios' for iOS variant)", profileName)
	}

	m.ActiveBehavioralProfile = profile
	m.BehaviorEngine = behavioral.NewBehaviorEngine(profile)
	m.lockedProfile = true
	m.UTLSFingerprint = utlsFP

	// Update active obfuscation profile directly (avoids re-locking the same mutex).
	if obfuscationProfile != "" {
		if _, exists := m.Profiles[obfuscationProfile]; exists {
			m.Active = obfuscationProfile
			if m.State != nil {
				m.State.Protocol = obfuscationProfile
			}
		}
	}

	_ = isIOS // used above for utlsFP selection

	return nil
}

func (m *Marionette) GetBehavioralDelay() time.Duration {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine == nil {
		return 0
	}

	return engine.NextPacketDelay()
}

func (m *Marionette) GetBehavioralPacketSize() int {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine == nil {
		return 0
	}

	return engine.NextPacketSize()
}

func (m *Marionette) TransitionBehavioralState() {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine != nil {
		engine.TransitionState()
	}
}

func (m *Marionette) GetBehavioralState() string {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine == nil {
		return "none"
	}

	return engine.GetCurrentState()
}

func (m *Marionette) SetBehavioralState(state string) {
	m.Mutex.RLock()
	engine := m.BehaviorEngine
	m.Mutex.RUnlock()

	if engine != nil {
		engine.SetState(state)
	}
}

func (m *Marionette) GetActiveBehavioralProfile() string {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	if m.ActiveBehavioralProfile == nil {
		return "none"
	}
	return m.ActiveBehavioralProfile.Name
}
