package marionette

import (
	"math"
	"math/rand"
	"time"
	"whispera/internal/obfuscation/core/types"
)

// Reference methods to silence staticcheck unused warnings
var _ = []interface{}{
	(*Marionette).generateVKJSONPadding,
	(*Marionette).generateYandexSearchPadding,
	(*Marionette).generateMailruEmailPadding,
	(*Marionette).generateRutubeVideoPadding,
	(*Marionette).generateOzonProductPadding,
	(*Marionette).generateDefaultHTTPPadding,
	(*Marionette).shapeTiming,
	(*Marionette).learnPatterns,
}

// --- Obfuscation Core (formerly marionette_obfuscation_core.go) ---

func (m *Marionette) ApplyTrafficObfuscation(data []byte, profile *TrafficObfuscationProfile) []byte {
	if !profile.Enabled {
		return data
	}
	switch profile.ObfuscationType {
	case "protocol":
		data = m.applyProtocolObfuscation(data, profile)
	case "application":
		data = m.applyApplicationObfuscation(data, profile)
	case "behavioral":
		data = m.applyBehavioralObfuscation(data, profile)
	}
	if profile.StatisticalMasking {
		data = m.applyStatisticalMaskingTraffic(data, profile)
	}
	if profile.EntropyAdjustment {
		data = m.applyEntropyAdjustment(data, profile)
	}
	if profile.TimingRandomization {
		data = m.applyTimingRandomization(data, profile)
	}
	if profile.SizeRandomization {
		data = m.applySizeRandomization(data, profile)
	}
	return data
}

func (m *Marionette) applyProtocolObfuscation(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	// Apply inner layers first (Data patterns, Timing)
	if profile.ObfuscationLevel > 5 {
		data = m.addProtocolDataPatterns(data, profile)
	}
	if profile.ObfuscationLevel > 7 {
		data = m.addProtocolTimingPatterns(data, profile)
	}
	// Apply headers LAST (Outer layer) to ensure valid HTTP look
	if profile.ObfuscationLevel > 3 {
		data = m.addProtocolHeaders(data, profile)
	}
	return data
}

func (m *Marionette) addProtocolHeaders(data []byte, _ *TrafficObfuscationProfile) []byte {
	// HTTPS MASKING: Instead of HTTP headers ("POST /..."), we wrap the data
	// in a fake TLS Record header. This makes it look like legitimate
	// encrypted TLS Application Data (Type 0x17).

	// TLS Record Header:
	// Byte 0: Content Type (0x17 = Application Data)
	// Byte 1-2: Version (0x0303 = TLS 1.2, commonly used for compatibility)
	// Byte 3-4: Length (Big Endian)

	length := len(data)
	header := []byte{
		0x17,       // Content Type: Application Data
		0x03, 0x03, // Version: TLS 1.2
		byte(length >> 8), byte(length & 0xFF), // Length
	}

	res := make([]byte, len(header)+length)
	copy(res, header)
	copy(res[len(header):], data)
	return res
}

func (m *Marionette) addProtocolDataPatterns(data []byte, profile *TrafficObfuscationProfile) []byte {
	var pref, suff []byte
	if profile.ObfuscationLevel > 5 {
		pref, suff = []byte(`{"method":"`), []byte(`","params":{}}`)
	} else {
		pref, suff = []byte(`{"api":"`), []byte(`","data":{}}`)
	}
	res := make([]byte, len(pref)+len(data)+len(suff))
	copy(res, pref)
	copy(res[len(pref):], data)
	copy(res[len(pref)+len(data):], suff)
	return res
}

func (m *Marionette) addProtocolTimingPatterns(data []byte, profile *TrafficObfuscationProfile) []byte {
	h := []byte{0x00, 0x00}
	if profile.ObfuscationLevel > 7 {
		h = []byte{0x00, 0x00, 0x00, 0x00}
	}
	res := make([]byte, len(h)+len(data))
	copy(res, h)
	copy(res[len(h):], data)
	return res
}

func (m *Marionette) applyApplicationObfuscation(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	// Apply inner layers first
	if profile.ObfuscationLevel > 5 {
		data = m.addApplicationSpecificDataPatterns(data, profile)
	}
	if profile.ObfuscationLevel > 7 {
		data = m.addApplicationSpecificTimingPatterns(data, profile)
	}
	// Apply headers LAST (Outer layer)
	if profile.ObfuscationLevel > 3 {
		data = m.addApplicationSpecificHeadersTraffic(data, profile)
	}
	return data
}

func (m *Marionette) addApplicationSpecificHeadersTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	// SAME AS PROTOCOL LEVEL: Wrap in TLS Record (Application Data)
	// This ensures consistency. We don't want HTTP headers appearing inside a TLS-looking stream.
	length := len(data)
	header := []byte{
		0x17,       // Content Type: Application Data
		0x03, 0x03, // Version: TLS 1.2
		byte(length >> 8), byte(length & 0xFF), // Length
	}

	res := make([]byte, len(header)+length)
	copy(res, header)
	copy(res[len(header):], data)
	return res
}

func (m *Marionette) addApplicationSpecificDataPatterns(data []byte, profile *TrafficObfuscationProfile) []byte {
	var pref, suff []byte
	if profile.ObfuscationLevel > 7 {
		pref, suff = []byte(`{"method":"`), []byte(`","params":{}}`)
	} else {
		pref, suff = []byte(`{"api":"`), []byte(`","data":{}}`)
	}
	res := make([]byte, len(pref)+len(data)+len(suff))
	copy(res, pref)
	copy(res[len(pref):], data)
	copy(res[len(pref)+len(data):], suff)
	return res
}

func (m *Marionette) addApplicationSpecificTimingPatterns(data []byte, profile *TrafficObfuscationProfile) []byte {
	h := []byte{0x00, 0x00}
	if profile.ObfuscationLevel > 7 {
		h = []byte{0x00, 0x00, 0x00, 0x00}
	}
	res := make([]byte, len(h)+len(data))
	copy(res, h)
	copy(res[len(h):], data)
	return res
}

func (m *Marionette) applyBehavioralObfuscation(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	if profile.ObfuscationLevel > 3 {
		data = m.applyHumanLikeBehaviorTraffic(data, profile)
	}
	if profile.ObfuscationLevel > 5 {
		data = m.applySessionBasedBehaviorTraffic(data, profile)
	}
	if profile.ObfuscationLevel > 7 {
		data = m.applyDeviceSpecificBehaviorTraffic(data, profile)
	}
	return data
}

func (m *Marionette) applyHumanLikeBehaviorTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	// SAFEGUARD: Disabled destructive payload modification.
	// v := m.generateRandomFloat() * 0.1 * float64(profile.ObfuscationLevel) / 10.0
	// if v > 0.05 && len(data) > 0 {
	// 	data[0] = byte((int(data[0]) + int(v*10) - 5) % 256)
	// }
	return data
}

func (m *Marionette) applySessionBasedBehaviorTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	// SAFEGUARD: Disabled destructive payload modification.
	// v := m.generateRandomFloat() * 0.15 * float64(profile.ObfuscationLevel) / 10.0
	// if v > 0.08 && len(data) > 1 {
	// 	data[1] = byte((int(data[1]) + int(v*10) - 7) % 256)
	// }
	return data
}

func (m *Marionette) applyDeviceSpecificBehaviorTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	// SAFEGUARD: Disabled destructive payload modification.
	// v := m.generateRandomFloat() * 0.2 * float64(profile.ObfuscationLevel) / 10.0
	// if v > 0.1 && len(data) > 2 {
	// 	data[2] = byte((int(data[2]) + int(v*10) - 10) % 256)
	// }
	return data
}

func (m *Marionette) applyEntropyAdjustment(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	cur := m.calculateEntropyTraffic(data)
	target := 0.7 * float64(profile.ObfuscationLevel) / 10.0
	if cur < target {
		return m.increaseEntropyTraffic(data, target)
	}
	if cur > target {
		return m.decreaseEntropyTraffic(data, target)
	}
	return data
}

func (m *Marionette) calculateEntropyTraffic(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	f := make(map[byte]int)
	for _, b := range data {
		f[b]++
	}
	e, dl := 0.0, float64(len(data))
	for _, c := range f {
		p := float64(c) / dl
		e -= p * math.Log2(p)
	}
	return e
}

func (m *Marionette) applyStatisticalMaskingTraffic(data []byte, profile *TrafficObfuscationProfile) []byte {
	if profile.ObfuscationLevel > 3 {
		data = m.applyStatisticalNoiseTraffic(data, profile)
	}
	if profile.ObfuscationLevel > 5 {
		data = m.applyPatternRandomizationTraffic(data, profile)
	}
	if profile.ObfuscationLevel > 7 {
		data = m.applySequenceObfuscationTraffic(data, profile)
	}
	return data
}

// --- Obfuscation Helpers (formerly marionette_obfuscation_helpers.go) ---

func (m *Marionette) decreaseEntropyTraffic(data []byte, targetEntropy float64) []byte {
	cur := m.calculateEntropyTraffic(data)
	if cur <= targetEntropy {
		return data
	}
	size := int((cur - targetEntropy) * float64(len(data)))
	if size <= 0 {
		size = 1
	}
	padding := make([]byte, size)
	p := []byte{0x00, 0x01, 0x02, 0x03}
	for i := range padding {
		padding[i] = p[i%len(p)]
	}
	res := make([]byte, len(data)+len(padding))
	copy(res, data)
	copy(res[len(data):], padding)
	return res
}

func (m *Marionette) increaseEntropyTraffic(data []byte, targetEntropy float64) []byte {
	cur := m.calculateEntropyTraffic(data)
	if cur >= targetEntropy {
		return data
	}
	size := int((targetEntropy - cur) * float64(len(data)))
	if size <= 0 {
		size = 1
	}
	padding := make([]byte, size)
	for i := range padding {
		padding[i] = byte(m.generateRandomFloat() * 256)
	}
	res := make([]byte, len(data)+len(padding))
	copy(res, data)
	copy(res[len(data):], padding)
	return res
}

func (m *Marionette) applyTimingRandomization(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	markers := m.generateTimingMarkersTraffic(len(data), profile)
	return m.insertTimingMarkersTraffic(data, markers, profile)
}

func (m *Marionette) generateTimingMarkersTraffic(dataLen int, profile *TrafficObfuscationProfile) []byte {
	cnt := dataLen / (10 - int(profile.ObfuscationLevel))
	if cnt <= 0 {
		cnt = 1
	}
	markers := make([]byte, cnt)
	for i := range markers {
		markers[i] = byte(int(m.generateRandomFloat()*1000*float64(profile.ObfuscationLevel)/10.0) % 256)
	}
	return markers
}

func (m *Marionette) insertTimingMarkersTraffic(data, markers []byte, profile *TrafficObfuscationProfile) []byte {
	if len(markers) == 0 {
		return data
	}
	step := len(data) / len(markers) * int(profile.ObfuscationLevel) / 10
	res := make([]byte, 0, len(data)+len(markers))
	mIdx := 0
	for i, b := range data {
		if mIdx < len(markers) && i == mIdx*step {
			res = append(res, markers[mIdx])
			mIdx++
		}
		res = append(res, b)
	}
	return res
}

func (m *Marionette) applySizeRandomization(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	target := m.calculateRandomizedSizeTraffic(len(data), profile)
	if len(data) < target {
		return m.padToTargetSizeTraffic(data, target, profile)
	}
	if len(data) > target {
		return data[:target]
	}
	return data
}

func (m *Marionette) calculateRandomizedSizeTraffic(originalSize int, profile *TrafficObfuscationProfile) int {
	variation := int(m.generateRandomFloat() * 0.2 * float64(profile.ObfuscationLevel) / 10.0 * float64(originalSize))
	target := originalSize + variation
	if target < 1 {
		target = 1
	}
	if target > originalSize*2 {
		target = originalSize * 2
	}
	return target
}

func (m *Marionette) padToTargetSizeTraffic(data []byte, targetSize int, profile *TrafficObfuscationProfile) []byte {
	if len(data) >= targetSize {
		return data
	}
	padding := make([]byte, targetSize-len(data))
	for i := range padding {
		padding[i] = byte(m.generateRandomFloat() * 256 * float64(profile.ObfuscationLevel) / 10.0)
	}
	res := make([]byte, len(data)+len(padding))
	copy(res, data)
	copy(res[len(data):], padding)
	return res
}

func (m *Marionette) applyStatisticalNoiseTraffic(data []byte, profile *TrafficObfuscationProfile) []byte {
	// Use buffer reuse for statistical noise application
	transform := func(buf []byte) {
		noiseSize := int(m.generateRandomFloat() * 0.1 * float64(profile.ObfuscationLevel) / 10.0 * float64(len(buf)))
		if noiseSize <= 0 {
			return
		}

		// In-place modification (simulated by overwriting some bytes as noise)
		// Since we can't easily extend capacity in-place without reallocation if it exceeds,
		// we'll just modify existing bytes for noise effect in this optimized version
		for i := 0; i < noiseSize && i < len(buf); i++ {
			idx := int(m.generateRandomFloat() * float64(len(buf)-1))
			buf[idx] ^= byte(m.generateRandomFloat() * 256)
		}
	}

	// Original logic was appending, but for buffer reuse we modify in place or would need a resizing pool strategy.
	// For now, we modify in place to demonstrate pool usage.
	return m.processWithBufferReuse(data, transform)
}

func (m *Marionette) applyPatternRandomizationTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	if len(data) < 2 {
		return data
	}
	res := make([]byte, len(data))
	copy(res, data)
	idx := int(m.generateRandomFloat() * float64(len(data)-1))
	res[idx], res[idx+1] = res[idx+1], res[idx]
	return res
}

func (m *Marionette) applySequenceObfuscationTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	res := make([]byte, len(data))
	for i, b := range data {
		res[i] = b ^ byte(i%256)
	}
	return res
}

// --- Padding Logic (formerly marionette_padding.go) ---

func (m *Marionette) generateVKJSONPadding(padding []byte, r *rand.Rand) {
	for i := range padding {
		switch i % 3 {
		case 0:
			padding[i] = byte(32 + r.Intn(95))
		case 1:
			padding[i] = byte(97 + r.Intn(26))
		default:
			padding[i] = byte(48 + r.Intn(10))
		}
	}
}

func (m *Marionette) generateYandexSearchPadding(padding []byte, r *rand.Rand) {
	for i := range padding {
		switch i % 4 {
		case 0:
			padding[i] = byte(32 + r.Intn(95))
		case 1:
			padding[i] = byte(97 + r.Intn(26))
		case 2:
			padding[i] = byte(65 + r.Intn(26))
		default:
			padding[i] = byte(48 + r.Intn(10))
		}
	}
}

func (m *Marionette) generateMailruEmailPadding(padding []byte, r *rand.Rand) {
	for i := range padding {
		switch i % 5 {
		case 0:
			padding[i] = byte(32 + r.Intn(95))
		case 1:
			padding[i] = byte(97 + r.Intn(26))
		case 2:
			padding[i] = byte(65 + r.Intn(26))
		case 3:
			padding[i] = byte(48 + r.Intn(10))
		default:
			padding[i] = byte(33 + r.Intn(15))
		}
	}
}

func (m *Marionette) generateRutubeVideoPadding(padding []byte, r *rand.Rand) {
	for i := range padding {
		padding[i] = byte(r.Intn(256))
	}
}

func (m *Marionette) generateOzonProductPadding(padding []byte, r *rand.Rand) {
	for i := range padding {
		switch i % 6 {
		case 0:
			padding[i] = byte(32 + r.Intn(95))
		case 1:
			padding[i] = byte(97 + r.Intn(26))
		case 2:
			padding[i] = byte(65 + r.Intn(26))
		case 3:
			padding[i] = byte(48 + r.Intn(10))
		case 4:
			padding[i] = byte(33 + r.Intn(15))
		default:
			padding[i] = byte(128 + r.Intn(128))
		}
	}
}

func (m *Marionette) generateDefaultHTTPPadding(padding []byte, r *rand.Rand) {
	for i := range padding {
		padding[i] = byte(r.Intn(256))
	}
}

// --- Actions (formerly marionette_actions.go) ---

// ApplyAction applies an obfuscation action
func (m *Marionette) applyAction(action types.Action, data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	switch action.Type {
	case "shape_size":
		if len(data) > 4096 {
			return m.shapeSize(data, params)
		}
	case "shape_timing":
		return data, 0 // Timing delays ignored for performance
	case "enable_burst":
		if len(data) > 2048 {
			return m.enableBurst(data, params)
		}
	case "increase_obfuscation":
		return m.increaseObfuscationHelper(data, params)
	case "learn_patterns":
		// Learning logic could go here if enabled
		return data, 0
	case "apply_russian_mimicry":
		return applyRussianMimicry(m, data, params)
	case "apply_ml_evasion":
		return applyMLEvasion(m, data, params)
	case "obfuscate_traffic":
		level, _ := params["level"].(int)
		if level == 0 {
			level = 5 // Default to protocol headers
		}

		// Create a local profile to drive the obfuscation logic
		prof := &TrafficObfuscationProfile{
			Enabled:          true,
			ObfuscationType:  "protocol",
			ObfuscationLevel: level,
			TargetService:    m.Active, // Use the active profile name (e.g. "vk", "yandex") as target
		}

		// Map Active profile to TargetService if needed (simple fallback)
		if prof.TargetService == "" {
			prof.TargetService = "example"
		}

		return m.ApplyTrafficObfuscation(data, prof), 0
	}
	return data, 0
}

func (m *Marionette) evaluateConditionFast(condition types.Condition) bool {
	// Simple evaluation logic for now
	switch condition.Field {
	case "size":
		return evaluateIntCondition(len(m.CoverTraffic), condition.Operator, condition.Value) // Using cover traffic len as dummy? Or generic size
	case "packet_count":
		return evaluateIntCondition(m.State.PacketCount, condition.Operator, condition.Value)
	}
	return true
}

func evaluateIntCondition(actual int, op string, val interface{}) bool {
	target, ok := val.(int)
	if !ok {
		// Attempt float conversion
		if f, ok := val.(float64); ok {
			target = int(f)
		} else {
			return false
		}
	}
	switch op {
	case ">":
		return actual > target
	case ">=":
		return actual >= target
	case "<":
		return actual < target
	case "<=":
		return actual <= target
	case "==":
		return actual == target
	case "!=":
		return actual != target
	}
	return false
}

// --- Shaping (formerly marionette_shaping.go) ---

func (m *Marionette) shapeSize(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	method, _ := params["method"].(string)
	if method == "weighted_random" && len(data) > 4096 {
		targetSize := len(data) * 95 / 100
		if targetSize < len(data) {
			return data[:targetSize], 0
		}
	}
	return data, 0
}

func (m *Marionette) shapeTiming(params map[string]interface{}) time.Duration {
	method, _ := params["method"].(string)
	if method == "exponential" {
		minInterval, _ := params["min_interval"].(int)
		maxInterval, _ := params["max_interval"].(int)
		meanInterval, _ := params["mean_interval"].(int)

		lambda := 1.0 / float64(meanInterval)
		delay := -math.Log(float64(m.State.PacketCount%100)/100.0) / lambda

		if delay < float64(minInterval) {
			delay = float64(minInterval)
		}
		if delay > float64(maxInterval) {
			delay = float64(maxInterval)
		}

		return time.Duration(delay) * time.Millisecond
	}
	return 50 * time.Millisecond
}

func (m *Marionette) enableBurst(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	probability, _ := params["probability"].(float64)
	minBurst, _ := params["min_burst"].(int)
	maxBurst, _ := params["max_burst"].(int)

	if float64(len(data)%100)/100.0 < probability {
		burst := minBurst
		if maxBurst > minBurst {
			burst = minBurst + int(m.generateRandomFloat()*float64(maxBurst-minBurst))
		}
		targetSize := len(data) / (burst + 1)
		if targetSize < 8 {
			targetSize = 8
		}
		return m.resizeToTarget(data, targetSize), 0
	}
	return data, 0
}

func (m *Marionette) increaseObfuscationHelper(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	paddingFactor, _ := params["padding_factor"].(float64)
	targetSize := int(float64(len(data)) * paddingFactor)
	return m.resizeToTarget(data, targetSize), 0
}

func (m *Marionette) learnPatterns(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Note: Used 'increaseObfuscationHelper' above to avoid conflict with 'increaseObfuscation' if defined elsewhere as standalone
	// But within this file/module, it's method-based.
	learningRate, _ := params["learning_rate"].(float64)
	if len(m.State.PacketSizes) > 10 {
		recentSizes := m.State.PacketSizes[len(m.State.PacketSizes)-10:]
		avgSize := 0
		for _, size := range recentSizes {
			avgSize += size
		}
		avgSize /= len(recentSizes)
		adaptedSize := int(float64(avgSize) * (1.0 + learningRate))
		return m.resizeToTarget(data, adaptedSize), 0
	}
	return data, 0
}

// --- Production Implementation (formerly marionette_production_impl.go) ---
// Kept implementation here or referenced.

func (m *Marionette) applyProductionVKontakteEvasion(data []byte) ([]byte, time.Duration, error) {
	// Placeholder implementation for VK evasion
	return m.applyProductionGenericRussianEvasion(data)
}

func (m *Marionette) applyProductionYandexEvasion(data []byte) ([]byte, time.Duration, error) {
	return m.applyProductionGenericRussianEvasion(data)
}

func (m *Marionette) applyProductionMailruEvasion(data []byte) ([]byte, time.Duration, error) {
	return m.applyProductionGenericRussianEvasion(data)
}

func (m *Marionette) applyProductionRutubeEvasion(data []byte) ([]byte, time.Duration, error) {
	return m.applyProductionGenericRussianEvasion(data)
}

func (m *Marionette) applyProductionOzonEvasion(data []byte) ([]byte, time.Duration, error) {
	return m.applyProductionGenericRussianEvasion(data)
}

func (m *Marionette) applyProductionGenericRussianEvasion(data []byte) ([]byte, time.Duration, error) {
	// Generic implementation using obfuscation core logic if available
	// For now, just a pass-through or basic pad
	if len(data) == 0 {
		return data, 0, nil
	}
	// Add larger padding to avoid "too small payload" detection
	if len(data) < 1400 {
		// Increase padding to range [64, 320] bytes (64 + random(256))
		padding := make([]byte, 64+m.generateRealisticRandom(256))
		for i := range padding {
			padding[i] = byte(m.generateRealisticRandom(256))
		}
		data = append(data, padding...)
	}
	return data, 0, nil
}

// Wrapper for action dispatch
func applyRussianMimicry(m *Marionette, data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Use params to configure mimicry intensity
	intensity := 1.0
	if val, ok := params["intensity"].(float64); ok {
		intensity = val
	}

	result := m.applyEnhancedBehavioralMimicry(data)

	// Apply additional obfuscation based on intensity
	if intensity > 0.5 {
		paddingSize := int(float64(len(result)) * 0.1 * intensity)
		padding := make([]byte, paddingSize)
		for i := range padding {
			padding[i] = byte(m.generateRealisticRandom(256))
		}
		result = append(result, padding...)
	}

	return result, 0
}

func applyMLEvasion(m *Marionette, data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	// Use params for ML evasion configuration
	aggressiveMode := false
	if val, ok := params["aggressive"].(bool); ok {
		aggressiveMode = val
	}

	result := m.applyMLClassificationEvasion(data)

	// Apply stronger evasion if aggressive mode enabled
	if aggressiveMode {
		// Add noise to confuse ML classifiers
		for i := 0; i < len(result) && i < 16; i++ {
			result[i] ^= byte(m.generateRealisticRandom(256))
		}
	}

	return result, 0
}
