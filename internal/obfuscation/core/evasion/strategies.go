package evasion

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)


func (m *Marionette) applyAction(action types.Action, data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	switch action.Type {
	case "resize":
		return m.applyResizeAction(data, params)
	case "delay":
		return m.applyDelayAction(data, params)
	case "pad":
		return m.applyPaddingAction(data, params)
	case "encrypt":
		return m.applyEncryptionAction(data, params)
	case "obfuscate":
		return m.applyObfuscationAction(data, params)
	case "profile_switch":
		return m.applyProfileSwitchAction(data, params)
	case "ml_evasion":
		return m.applyMLEvasionAction(data, params)
	case "dpi_evasion":
		return m.applyDPIEvasionAction(data, params)
	case "behavioral_mimicry":
		return m.applyBehavioralMimicryAction(data, params)
	case "apply_russian_mimicry":
		return m.applyRussianMimicryAction(data, params)
	case "learn_patterns":
		return m.applyAdaptiveLearningAction(data, params)
	default:
		return data, 0
	}
}

func (m *Marionette) applyResizeAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	targetSize, ok := params["target_size"].(int)
	if !ok {
		return data, 0
	}

	if len(data) >= targetSize {
		return data, 0
	}

	result := make([]byte, targetSize)
	copy(result, data)
	rand.Read(result[len(data):])

	return result, 0
}

func (m *Marionette) applyDelayAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	delayMs, ok := params["delay_ms"].(int)
	if !ok {
		return data, 0
	}

	jitter := delayMs / 10
	if jitter > 0 {
		delayMs += (int(util.GetGlobalTimeCache().Now().UnixNano()) % (jitter * 2)) - jitter
	}

	delay := time.Duration(delayMs) * time.Millisecond
	return data, delay
}

func (m *Marionette) applyPaddingAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	paddingSize, ok := params["padding_size"].(int)
	if !ok {
		return data, 0
	}

	if paddingSize <= 0 {
		return data, 0
	}

	result := make([]byte, len(data)+paddingSize)
	copy(result, data)

	padding := m.generateRealisticPadding(paddingSize)
	copy(result[len(data):], padding)

	return result, 0
}

func (m *Marionette) applyEncryptionAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	key, ok := params["key"].([]byte)
	if !ok || len(key) == 0 {
		return data, 0
	}

	encrypted := make([]byte, len(data))
	keyLen := len(key)

	for i := range data {
		encrypted[i] = data[i] ^ key[i%keyLen]
	}

	return encrypted, 0
}

func (m *Marionette) applyObfuscationAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	obfuscationType, ok := params["type"].(string)
	if !ok {
		return data, 0
	}

	switch obfuscationType {
	case "entropy_adjustment":
		return m.adjustEntropy(data, params)
	case "pattern_masking":
		return m.maskPatterns(data, params)
	case "statistical_noise":
		return m.addStatisticalNoise(data, params)
	default:
		return data, 0
	}
}

func (m *Marionette) adjustEntropy(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	return data, 0
}

func (m *Marionette) maskPatterns(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	return data, 0
}

func (m *Marionette) addStatisticalNoise(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	return data, 0
}

func (m *Marionette) applyAdaptiveLearningAction(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	if m.AdaptiveLearning != nil {
		ctx := &types.TrafficContext{
			Direction: m.State.Direction,
			Protocol:  m.State.Protocol,
			Size:      len(data),
			Timestamp: time.Now(),
		}
		m.AdaptiveLearning.LearnFromTraffic(data, true, ctx)
	}
	return data, 0
}

func (m *Marionette) applyProfileSwitchAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	newProfile, ok := params["profile"].(string)
	if !ok {
		return data, 0
	}

	m.SwitchProfile(newProfile, "rule_action")

	return data, 0
}

func (m *Marionette) applyRussianMimicryAction(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	if !enableCoreEvasion {
		return data, 0
	}

	protocol := m.Active
	if protocol == "" {
		protocol = m.State.Protocol
	}

	var result []byte
	var delay time.Duration
	var err error

	switch protocol {
	case "vk":
		result, delay, err = m.applyProductionVKontakteEvasion(data)
	case "yandex":
		result, delay, err = m.applyProductionYandexEvasion(data)
	case "mailru":
		result, delay, err = m.applyProductionMailruEvasion(data)
	case "rutube":
		result, delay, err = m.applyProductionRutubeEvasion(data)
	case "ozon":
		result, delay, err = m.applyProductionOzonEvasion(data)
	default:
		return data, 0
	}

	if err != nil {
		return data, 0
	}
	return result, delay
}

func (m *Marionette) applyMLEvasionAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	if !enableCoreEvasion {
		return data, 0
	}
	return m.applyMLEvasion(data, params)
}

func (m *Marionette) applyMLEvasion(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	if m.Adversarial != nil {
		result := m.Adversarial.Apply(data)

		ja3Evasion, _ := params["ja3_evasion"].(bool)
		echEvasion, _ := params["ech_evasion"].(bool)
		greaseEvasion, _ := params["grease_evasion"].(bool)

		if ja3Evasion && len(result) > 5 && result[0] == 0x16 {
			me := &MLEvasion{adversarial: m.Adversarial}
			if ja3 := me.ApplyJA3Evasion(result); ja3 != nil {
				result = ja3
			}
		}
		if echEvasion {
			me := &MLEvasion{adversarial: m.Adversarial}
			echData := me.ApplyECHEvasion(result)
			result = append(result, echData...)
		}
		if greaseEvasion {
			me := &MLEvasion{adversarial: m.Adversarial}
			greaseData := me.ApplyGREASEEvasion(result)
			result = append(result, greaseData...)
		}

		return result, 0
	}

	noiseSize := len(data) / 20
	if noiseSize < 4 {
		noiseSize = 4
	}
	noise := make([]byte, noiseSize)
	rand.Read(noise)
	return append(data, noise...), 0
}

func (m *Marionette) applyDPIEvasionAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	if !enableCoreEvasion {
		return data, 0
	}
	evasionType, ok := params["type"].(string)
	if !ok {
		return data, 0
	}

	switch evasionType {
	case "ja3_evasion":
		return append(data, m.applyJA3Evasion(data)...), 0
	case "ja4_evasion":
		return append(data, m.applyJA4Evasion(data)...), 0
	case "http_evasion":
		return m.applyHTTPEvasion(data, params)
	case "tls_evasion":
		return m.applyTLSEvasion(data, params)
	default:
		return data, 0
	}
}

func (m *Marionette) applyBehavioralMimicryAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	if !enableCoreEvasion {
		return data, 0
	}
	mimicryType, ok := params["type"].(string)
	if !ok {
		return data, 0
	}

	switch mimicryType {
	case "human_behavior":
		return m.mimicHumanBehavior(data, params)
	case "service_behavior":
		return m.mimicServiceBehavior(data, params)
	case "device_behavior":
		return m.mimicDeviceBehavior(data, params)
	default:
		return data, 0
	}
}

func (m *Marionette) applyHTTPEvasion(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	return data, 0
}

func (m *Marionette) applyTLSEvasion(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	clientHello := m.generateTLSClientHello()
	extensions := m.generateTLSExtensions()
	tlsObfuscation := append(clientHello, extensions...)
	return append(data, tlsObfuscation...), 0
}

func (m *Marionette) mimicHumanBehavior(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	return data, 0
}

func (m *Marionette) mimicServiceBehavior(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	return data, 0
}

func (m *Marionette) mimicDeviceBehavior(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	return data, 0
}

func cryptoRandInt(n int) int {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	rand.Read(buf[:])
	v := binary.LittleEndian.Uint64(buf[:])
	return int(v % uint64(n))
}

func (m *Marionette) generateRealisticPadding(size int) []byte {
	padding := make([]byte, size)
	profileName := m.getCurrentServiceProfileName()
	if profileName != "" {
		padding = m.generateServiceSpecificPadding(profileName, size)
	} else {
		rand.Read(padding)
	}
	return padding
}

func (m *Marionette) generateServiceSpecificPadding(profile string, size int) []byte {
	padding := make([]byte, size)
	rand.Read(padding)
	switch profile {
	case "vk":
		for i := range padding {
			switch i % 3 {
			case 0:
				padding[i] = 32 + padding[i]%95
			case 1:
				padding[i] = 97 + padding[i]%26
			default:
				padding[i] = 48 + padding[i]%10
			}
		}
	case "yandex", "mailru", "ozon", "rutube":
		for i := range padding {
			padding[i] = 32 + padding[i]%95
		}
	}
	return padding
}


type DPIEvasion struct {
	detectionLevel    float64
	characteristics   map[string]float64
	evasionTechniques map[string]bool
}

func NewDPIEvasion() *DPIEvasion {
	return &DPIEvasion{
		detectionLevel:  0.0,
		characteristics: make(map[string]float64),
		evasionTechniques: map[string]bool{
			"ja3_evasion":               true,
			"ja4_evasion":               true,
			"grease_evasion":            true,
			"alpn_evasion":              true,
			"ech_evasion":               true,
			"hpack_evasion":             true,
			"qpack_evasion":             true,
			"doh_evasion":               true,
			"doq_evasion":               true,
			"timing_analysis_evasion":   true,
			"flow_analysis_evasion":     true,
			"statistical_evasion":       true,
			"ml_classification_evasion": true,
		},
	}
}

func (de *DPIEvasion) DetectDPI() {
	de.detectionLevel = de.analyzeDPICharacteristics()
	de.characteristics = map[string]float64{
		"timing_patterns":     de.analyzeTimingPatterns(),
		"protocol_signatures": de.analyzeProtocolSignatures(),
		"flow_anomalies":      de.analyzeFlowAnomalies(),
		"packet_sizes":        de.analyzePacketSizes(),
		"burst_patterns":      de.analyzeBurstPatterns(),
	}
}

func (de *DPIEvasion) analyzeDPICharacteristics() float64 {
	return 0.5
}

func (de *DPIEvasion) analyzeTimingPatterns() float64 {
	return 0.4
}

func (de *DPIEvasion) analyzeProtocolSignatures() float64 {
	return 0.3
}

func (de *DPIEvasion) analyzeFlowAnomalies() float64 {
	return 0.2
}

func (de *DPIEvasion) analyzePacketSizes() float64 {
	return 0.5
}

func (de *DPIEvasion) analyzeBurstPatterns() float64 {
	return 0.6
}
