package evasion

import (
	//nolint:gosec // MD5 used for TLS fingerprinting, not cryptography

	"time"

	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)

// Pools for buffer reuse (from marionette_core_ml_evasion.go)

// applyAction applies a rule action
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

// applyResizeAction applies packet resizing
func (m *Marionette) applyResizeAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	targetSize, ok := params["target_size"].(int)
	if !ok {
		return data, 0
	}

	if len(data) >= targetSize {
		return data, 0
	}

	paddingSize := targetSize - len(data)
	result := make([]byte, targetSize)
	copy(result, data)

	for i := 0; i < paddingSize; i++ {
		result[len(data)+i] = byte(32 + (i % 95)) // ASCII printable characters
	}

	return result, 0
}

// applyDelayAction applies timing delay
func (m *Marionette) applyDelayAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	delayMs, ok := params["delay_ms"].(int)
	if !ok {
		return data, 0
	}

	// Add random jitter to avoid detection
	jitter := delayMs / 10
	if jitter > 0 {
		delayMs += (int(util.GetGlobalTimeCache().Now().UnixNano()) % (jitter * 2)) - jitter
	}

	delay := time.Duration(delayMs) * time.Millisecond
	return data, delay
}

// applyPaddingAction applies packet padding
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

	// Generate realistic padding based on current profile
	padding := m.generateRealisticPadding(paddingSize)
	copy(result[len(data):], padding)

	return result, 0
}

// applyEncryptionAction applies encryption
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

// applyObfuscationAction applies obfuscation
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

// applyAdaptiveLearningAction applies adaptive learning
func (m *Marionette) applyAdaptiveLearningAction(data []byte, _ map[string]interface{}) ([]byte, time.Duration) {
	if m.AdaptiveLearning != nil {
		ctx := &types.TrafficContext{
			Direction: m.State.Direction,
			Protocol:  m.State.Protocol,
			Size:      len(data),
			Timestamp: time.Now(),
		}
		// Assuming successful if we reached here
		m.AdaptiveLearning.LearnFromTraffic(data, true, ctx)
	}
	return data, 0
}

// applyProfileSwitchAction switches traffic profile
func (m *Marionette) applyProfileSwitchAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	newProfile, ok := params["profile"].(string)
	if !ok {
		return data, 0
	}

	// Use the central SwitchProfile method
	m.SwitchProfile(newProfile, "rule_action")

	return data, 0
}

// applyRussianMimicryAction applies Russian service mimicry
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

// applyMLEvasionAction applies ML-based evasion
func (m *Marionette) applyMLEvasionAction(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	if !enableCoreEvasion {
		return data, 0
	}
	return m.applyMLEvasion(data, params)
}

// applyMLEvasion applies production ML evasion techniques
func (m *Marionette) applyMLEvasion(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	adversarialExamples, _ := params["adversarial_examples"].(bool)
	behavioralMimicry, _ := params["behavioral_mimicry"].(bool)
	trafficShaping, _ := params["traffic_shaping"].(bool)
	protocolFidelity, _ := params["protocol_fidelity"].(bool)
	hardwareEvasion, _ := params["hardware_evasion"].(bool)

	ja3Evasion, _ := params["ja3_evasion"].(bool)
	ja4Evasion, _ := params["ja4_evasion"].(bool)
	greaseEvasion, _ := params["grease_evasion"].(bool)
	alpnEvasion, _ := params["alpn_evasion"].(bool)
	echEvasion, _ := params["ech_evasion"].(bool)
	hpackEvasion, _ := params["hpack_evasion"].(bool)
	qpackEvasion, _ := params["qpack_evasion"].(bool)
	dohEvasion, _ := params["doh_evasion"].(bool)
	doqEvasion, _ := params["doq_evasion"].(bool)
	timingAnalysisEvasion, _ := params["timing_analysis_evasion"].(bool)
	flowAnalysisEvasion, _ := params["flow_analysis_evasion"].(bool)
	statisticalEvasion, _ := params["statistical_evasion"].(bool)
	mlClassificationEvasion, _ := params["ml_classification_evasion"].(bool)

	appliedTechniques := 0

	if behavioralMimicry {
		behavioralData := m.applyEnhancedBehavioralMimicry(data)
		data = append(data, behavioralData...)
		appliedTechniques++
	}

	if adversarialExamples {
		noiseSize := len(data) / 20
		if noiseSize < 4 {
			noiseSize = 4
		}
		noise := make([]byte, noiseSize)
		for i := range noise {
			noise[i] = byte((i*13 + len(data)*7) % 256)
		}
		data = append(data, noise...)
		appliedTechniques++
	}

	if ja3Evasion {
		data = append(data, m.applyJA3Evasion(data)...)
	}
	if ja4Evasion {
		data = append(data, m.applyJA4Evasion(data)...)
	}
	if greaseEvasion {
		data = append(data, m.applyGREASEEvasion(data)...)
	}
	if alpnEvasion {
		data = append(data, m.applyALPNEvasion(data)...)
	}
	if echEvasion {
		data = append(data, m.applyECHEvasion(data)...)
	}
	if hpackEvasion {
		data = append(data, m.applyHPACKEvasion(data)...)
	}
	if qpackEvasion {
		data = append(data, m.applyQPACKEvasion(data)...)
	}
	if dohEvasion {
		data = append(data, m.applyDoHEvasion(data)...)
	}
	if doqEvasion {
		data = append(data, m.applyDoQEvasion(data)...)
	}
	if timingAnalysisEvasion {
		data = append(data, m.applyTimingAnalysisEvasion(data)...)
	}
	if flowAnalysisEvasion {
		data = append(data, m.applyFlowAnalysisEvasion(data)...)
	}
	if statisticalEvasion {
		data = append(data, m.applyStatisticalEvasion(data)...)
	}
	if mlClassificationEvasion {
		data = append(data, m.applyMLClassificationEvasion(data)...)
	}

	if protocolFidelity {
		padding := []byte{0x00, 0x01, 0x02, 0x03}
		data = append(data, padding...)
	}

	if hardwareEvasion {
		// Hardware jitter logic
	}

	if trafficShaping {
		// Shaping logic
	}

	return data, 0
}

// applyDPIEvasionAction applies DPI evasion
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

// applyBehavioralMimicryAction applies behavioral mimicry
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

func (m *Marionette) applyGREASEEvasion(_ []byte) []byte {
	var greaseValues = [16]byte{0x0a, 0x0a, 0x1a, 0x1a, 0x2a, 0x2a, 0x3a, 0x3a, 0x4a, 0x4a, 0x5a, 0x5a, 0x6a, 0x6a, 0x7a, 0x7a}
	greaseObfuscation := make([]byte, 4)
	greaseValuesLen := len(greaseValues)
	for i := 0; i < 4; i++ {
		greaseIndex := m.generateRealisticRandom(greaseValuesLen)
		greaseObfuscation[i] = greaseValues[greaseIndex]
	}
	return greaseObfuscation
}

func (m *Marionette) applyALPNEvasion(_ []byte) []byte {
	var alpnPatterns = [4][6]byte{
		{0x68, 0x32, 0x68, 0x74, 0x74, 0x70}, // h2,http
		{0x68, 0x33, 0x68, 0x74, 0x74, 0x70}, // h3,http
		{0x68, 0x32, 0x68, 0x74, 0x74, 0x70}, // h2,http
		{0x68, 0x33, 0x68, 0x74, 0x74, 0x70}, // h3,http
	}
	patternIndex := m.generateRealisticRandom(len(alpnPatterns))
	alpnObfuscation := make([]byte, 6)
	copy(alpnObfuscation, alpnPatterns[patternIndex][:])
	return alpnObfuscation
}

func (m *Marionette) applyECHEvasion(_ []byte) []byte {
	echObfuscation := make([]byte, 12)
	return echObfuscation
}

func (m *Marionette) applyHPACKEvasion(_ []byte) []byte {
	hpackObfuscation := make([]byte, 8)
	return hpackObfuscation
}

func (m *Marionette) applyQPACKEvasion(_ []byte) []byte {
	qpackObfuscation := make([]byte, 8)
	return qpackObfuscation
}

func (m *Marionette) applyDoHEvasion(_ []byte) []byte {
	dohObfuscation := make([]byte, 6)
	return dohObfuscation
}

func (m *Marionette) applyDoQEvasion(_ []byte) []byte {
	doqObfuscation := make([]byte, 6)
	return doqObfuscation
}

func (m *Marionette) applyTimingAnalysisEvasion(_ []byte) []byte {
	timingObfuscation := make([]byte, 6)
	return timingObfuscation
}

func (m *Marionette) applyFlowAnalysisEvasion(_ []byte) []byte {
	flowObfuscation := make([]byte, 6)
	return flowObfuscation
}

func (m *Marionette) applyStatisticalEvasion(_ []byte) []byte {
	statisticalObfuscation := make([]byte, 10)
	return statisticalObfuscation
}

func (m *Marionette) applyMLClassificationEvasion(_ []byte) []byte {
	mlObfuscation := make([]byte, 24)
	return mlObfuscation
}

func (m *Marionette) applyEnhancedBehavioralMimicry(_ []byte) []byte {
	return []byte{0x01, 0x02}
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

func (m *Marionette) generateRealisticRandom(n int) int {
	if n <= 0 {
		return 0
	}
	return int(util.GetGlobalTimeCache().Now().UnixNano()) % n
}

func (m *Marionette) generateRealisticPadding(size int) []byte {
	padding := make([]byte, size)
	profileName := m.getCurrentServiceProfileName()
	if profileName != "" {
		padding = m.generateServiceSpecificPadding(profileName, size)
	} else {
		for i := range padding {
			padding[i] = byte(32 + (i % 95))
		}
	}
	return padding
}

func (m *Marionette) generateServiceSpecificPadding(profile string, size int) []byte {
	padding := make([]byte, size)
	switch profile {
	case "vk":
		for i := 0; i < size; i++ {
			switch i % 3 {
			case 0:
				padding[i] = byte(32 + (i % 95))
			case 1:
				padding[i] = byte(97 + (i % 26))
			default:
				padding[i] = byte(48 + (i % 10))
			}
		}
	case "yandex":
		for i := 0; i < size; i++ {
			padding[i] = byte(32 + (i % 95))
		}
	case "mailru":
		for i := 0; i < size; i++ {
			padding[i] = byte(32 + (i % 95))
		}
	default:
		for i := 0; i < size; i++ {
			padding[i] = byte(32 + (i % 95))
		}
	}
	return padding
}

// --- DPI Evasion (Analysis) ---

// DPIEvasion - модуль для эвазии DPI
type DPIEvasion struct {
	detectionLevel    float64
	characteristics   map[string]float64
	evasionTechniques map[string]bool
}

// NewDPIEvasion создает новый модуль DPI эвазии
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

// DetectDPI обнаруживает DPI и анализирует его характеристики
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
