package fte

import (
	"math"
	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)

// Reference methods to silence staticcheck unused warnings
// These methods are part of the FTE API but may not be called internally
var _ = []interface{}{
	(*FTE).getMLFeedback,
	(*FTE).applyReinforcementActionWithFeedback,
	(*FTE).applyVKMLEvasion,
	(*FTE).applyVKHardwareEvasion,
	(*FTE).applyVKProtocolFidelity,
	(*FTE).realVKSizeObfuscation,
	(*FTE).applyYandexMLEvasion,
	(*FTE).applyOzonBehavioralPatterns,
	(*FTE).applyRutubeBehavioralPatterns,
	(*FTE).applyGenericRussianBehavioralPatterns,
	(*FTE).applyWebsiteFingerprintDefense,
}

// --- ML FEEDBACK & EFFECTIVENESS TRACKING ---

// MLFeedback represents ML system feedback for reinforcement learning
type MLFeedback struct {
	Confidence     float64
	DPIDetected    bool
	Recommendation string // "maintain", "optimize", "aggressive", "fallback", "no_change"
}

func (fte *FTE) getMLFeedback(data []byte) *MLFeedback {
	if fte.mlSystem == nil {
		return &MLFeedback{Confidence: 0.5, DPIDetected: false, Recommendation: "no_change"}
	}
	context := &types.UnifiedTrafficContext{Direction: "outbound", Protocol: fte.active, Size: len(data), Timestamp: util.GetGlobalTimeCache().Now()}
	if _, err := fte.mlSystem.ProcessTraffic(data, context); err != nil {
		return &MLFeedback{Confidence: 0.3, DPIDetected: false, Recommendation: "fallback"}
	}
	stats := fte.mlSystem.GetStats()
	recommendation := "optimize"
	if stats.DPIEvasionRate > 0.8 {
		recommendation = "maintain"
	} else if stats.DPIEvasionRate < 0.3 {
		recommendation = "aggressive"
	}
	return &MLFeedback{Confidence: stats.Accuracy, DPIDetected: stats.DPIEvasionRate < 0.5, Recommendation: recommendation}
}

func (fte *FTE) applyReinforcementActionWithFeedback(data []byte, action string, feedback *MLFeedback) []byte {
	adapted := fte.applyReinforcementAction(data, action)
	switch feedback.Recommendation {
	case "aggressive":
		adapted = fte.adaptPacketSize(adapted)
	case "optimize":
		adapted = fte.adaptTiming(adapted)
	case "maintain": // noop
	case "fallback":
		adapted = fte.applyStatisticalMasking(adapted)
	}
	if fte.effectivenessTracker != nil {
		fte.updateEffectivenessTracking(feedback.Confidence > 0.7 && !feedback.DPIDetected)
	}
	return adapted
}

func (fte *FTE) updateEffectivenessTracking(success bool) {
	if fte.effectivenessTracker == nil {
		return
	}
	fte.effectivenessTracker.TotalAttempts++
	if success {
		fte.effectivenessTracker.SuccessfulEvasion++
	} else {
		fte.effectivenessTracker.FailedEvasion++
	}
	fte.effectivenessTracker.EffectivenessRate = float64(fte.effectivenessTracker.SuccessfulEvasion) / float64(fte.effectivenessTracker.TotalAttempts)
	if fte.active != "" {
		fte.effectivenessTracker.ProfileEffectiveness[fte.active] = fte.effectivenessTracker.EffectivenessRate
	}
	fte.effectivenessTracker.LastUpdate = util.GetGlobalTimeCache().Now()
}

func NewEffectivenessTracker() *EffectivenessTracker {
	return &EffectivenessTracker{
		TotalAttempts:        0,
		SuccessfulEvasion:    0,
		FailedEvasion:        0,
		EffectivenessRate:    0.0,
		LastUpdate:           util.GetGlobalTimeCache().Now(),
		ProfileEffectiveness: make(map[string]float64),
		AdaptationHistory:    make([]AdaptationRecord, 0),
	}
}

func (rl *ReinforcementLearning) SelectAction(state string) string {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.QTable == nil {
		rl.QTable = make(map[string]map[string]float64)
	}
	if rl.QTable[state] == nil {
		rl.QTable[state] = make(map[string]float64)
		for _, action := range rl.ActionSpace {
			rl.QTable[state][action] = 0.0
		}
		if len(rl.QTable) > rl.maxQTableSize {
			rl.cleanupQTable()
		}
	}

	if secureRandFloat64() < rl.Epsilon {
		return rl.ActionSpace[secureRandInt(len(rl.ActionSpace))]
	}
	return rl.getBestAction(state)
}

func (rl *ReinforcementLearning) UpdateQTable(state, action, nextState string, reward float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.QTable == nil {
		rl.QTable = make(map[string]map[string]float64)
	}
	if rl.QTable[state] == nil {
		rl.QTable[state] = make(map[string]float64)
	}
	if rl.QTable[nextState] == nil {
		rl.QTable[nextState] = make(map[string]float64)
		for _, a := range rl.ActionSpace {
			rl.QTable[nextState][a] = 0.0
		}
	}

	currentQ := rl.QTable[state][action]
	maxNextQ := rl.getMaxQValue(nextState)
	newQ := currentQ + rl.LearningRate*(reward+rl.DiscountFactor*maxNextQ-currentQ)
	rl.QTable[state][action] = newQ

	if rl.Epsilon > rl.MinEpsilon {
		rl.Epsilon *= rl.EpsilonDecay
	}
}

func (rl *ReinforcementLearning) getBestAction(state string) string {
	bestAction := rl.ActionSpace[0]
	if stateData, ok := rl.QTable[state]; ok && len(stateData) > 0 {
		bestValue := stateData[bestAction]
		for action, value := range stateData {
			if value > bestValue {
				bestValue = value
				bestAction = action
			}
		}
	}
	return bestAction
}

func (rl *ReinforcementLearning) getMaxQValue(state string) float64 {
	maxValue := 0.0
	for _, value := range rl.QTable[state] {
		if value > maxValue {
			maxValue = value
		}
	}
	return maxValue
}

func (rl *ReinforcementLearning) cleanupQTable() {
	toRemove := len(rl.QTable) - rl.maxQTableSize + (rl.maxQTableSize / 10)
	count := 0
	for state := range rl.QTable {
		if count >= toRemove {
			break
		}
		delete(rl.QTable, state)
		count++
	}
}

// --- REINFORCEMENT ACTIONS & ADAPTATION ---

func (fte *FTE) applyReinforcementAction(data []byte, action string) []byte {
	switch action {
	case ActionSizeAdapt:
		return fte.adaptPacketSize(data)
	case ActionTimingAdapt:
		return fte.adaptTiming(data)
	case ActionHeaderAdapt:
		return fte.adaptHeaders(data)
	case ActionEntropyAdapt:
		return fte.adaptEntropy(data)
	case ActionBehavioralAdapt:
		return fte.adaptBehavioral(data)
	default:
		return data
	}
}

func (fte *FTE) adaptPacketSize(data []byte) []byte {
	profile := fte.getProfile()
	if profile == nil {
		return data
	}
	targetSize := profile.MinSize + secureRandInt(profile.MaxSize-profile.MinSize)
	return fte.resizeToTarget(data, targetSize)
}

func (fte *FTE) adaptTiming(data []byte) []byte {
	return fte.applyTimingRandomization(data)
}

func (fte *FTE) adaptHeaders(data []byte) []byte {
	profile := fte.getProfile()
	if profile == nil {
		return data
	}
	return fte.applyHeaderSpoofing(data, profile.Fingerprint.ProtocolMasquerading)
}

func (fte *FTE) adaptEntropy(data []byte) []byte {
	profile := fte.getProfile()
	if profile == nil {
		return data
	}
	return fte.applyEntropyAntiAnalysis(data)
}

func (fte *FTE) adaptBehavioral(data []byte) []byte {
	profile := fte.getProfile()
	if profile == nil {
		return data
	}
	return fte.applyBehavioralMimicry(data, profile.Fingerprint.ProtocolMasquerading)
}

// --- ADVANCED EVASION TECHNIQUES ---

func (fte *FTE) ApplyAdvancedFingerprintingEvasion(data []byte) []byte {
	obfuscated := fte.applyPacketSizeObfuscation(data)
	obfuscated = fte.applyTimingPatternObfuscation(obfuscated)
	obfuscated = fte.applyStatisticalMasking(obfuscated)
	obfuscated = fte.applyEntropyAntiAnalysis(obfuscated)
	// Apply size randomization for anti-fingerprinting
	obfuscated = fte.applySizeRandomization(obfuscated)
	return obfuscated
}

func (fte *FTE) applyPacketSizeObfuscation(data []byte) []byte {
	profile := fte.getProfile()
	if profile == nil {
		return data
	}
	targetSize := fte.calculateRealisticTargetSize(len(data), profile)
	if len(data) < targetSize {
		padding := make([]byte, targetSize-len(data))
		for i := range padding {
			padding[i] = fte.generateRealisticPadding(i, len(data))
		}
		data = append(data, padding...)
	} else if len(data) > targetSize {
		data = data[:targetSize]
	}
	return data
}

func (fte *FTE) calculateRealisticTargetSize(originalSize int, profile *ProtocolProfile) int {
	if len(profile.CommonSizes) == 0 {
		return originalSize
	}
	weights := make([]float64, len(profile.CommonSizes))
	totalWeight := 0.0
	for i, size := range profile.CommonSizes {
		weights[i] = math.Exp(-float64(size) / 500.0)
		totalWeight += weights[i]
	}
	return profile.CommonSizes[0] // Simplified
}

func (fte *FTE) generateRealisticPadding(index, dataLen int) byte {
	active := fte.getActive()
	switch active {
	case "vk":
		return JSONCharsFTE[(index+dataLen)%len(JSONCharsFTE)]
	case ProfileYandexFTE:
		return JSONCharsFTE[(index*2+dataLen)%len(JSONCharsFTE)]
	case ProfileMailruFTE:
		return JSONCharsFTE[(index*3+dataLen)%len(JSONCharsFTE)]
	default:
		return byte(32 + (index % 95))
	}
}

func (fte *FTE) applyTimingPatternObfuscation(data []byte) []byte { return data }

func (fte *FTE) applyStatisticalMasking(data []byte) []byte {
	profile := fte.getProfile()
	if profile == nil || !profile.Fingerprint.StatisticalMasking {
		return data
	}
	noiseLevel := profile.Fingerprint.EntropyProfile.StatisticalNoise
	if noiseLevel > 0 {
		for i := range data {
			if secureRandFloat64() < noiseLevel {
				data[i] = byte((int(data[i]) + secureRandInt(256)) % 256)
			}
		}
	}
	return data
}

func (fte *FTE) applyEntropyAntiAnalysis(data []byte) []byte {
	profile := fte.getProfile()
	if profile == nil || !profile.Fingerprint.EntropyProfile.AntiEntropy {
		return data
	}
	currentEntropy := fte.calculateEntropy(data)
	targetEntropy := profile.Fingerprint.EntropyProfile.TargetEntropy
	if math.Abs(currentEntropy-targetEntropy) > profile.Fingerprint.EntropyProfile.EntropyVariance {
		data = fte.adjustEntropy(data, targetEntropy)
	}
	return data
}

func (fte *FTE) adjustEntropy(data []byte, targetEntropy float64) []byte {
	if len(data) == 0 {
		return data
	}

	currentEntropy := fte.calculateEntropy(data)
	if math.Abs(currentEntropy-targetEntropy) < 0.1 {
		return data // Already close enough
	}

	result := make([]byte, len(data))
	copy(result, data)

	// If entropy is too low, add randomness
	if currentEntropy < targetEntropy {
		numBytesToRandomize := int(float64(len(data)) * (targetEntropy - currentEntropy) / 8.0)
		if numBytesToRandomize < 1 {
			numBytesToRandomize = 1
		}
		for i := 0; i < numBytesToRandomize && i < len(result); i++ {
			idx := secureRandInt(len(result))
			result[idx] = byte(secureRandInt(256))
		}
	} else {
		// If entropy is too high, add patterns to reduce it
		patternBytes := []byte{0x00, 0x20, 0x41, 0x61}
		numBytesToPattern := int(float64(len(data)) * (currentEntropy - targetEntropy) / 8.0)
		if numBytesToPattern < 1 {
			numBytesToPattern = 1
		}
		for i := 0; i < numBytesToPattern && i < len(result); i++ {
			idx := secureRandInt(len(result))
			result[idx] = patternBytes[i%len(patternBytes)]
		}
	}

	return result
}

func (fte *FTE) applyMLResistance(data []byte, masquerading ProtocolMasquerading) []byte {
	// SAFEGUARD: Disabled destructive payload modification (bit-flipping).
	// ML Resistance was modifying random bytes, which corrupts the encrypted stream.
	return data
}

func (fte *FTE) applyFeatureObfuscation(data []byte) []byte {
	// SAFEGUARD: Disabled destructive payload modification.
	return data
}

func (fte *FTE) applyStatisticalNoise(data []byte) []byte {
	// SAFEGUARD: Disabled destructive payload modification.
	return data
}

// --- SERVICE-SPECIFIC BEHAVIORAL PATTERNS ---

func (fte *FTE) applyVKBehavioralPatterns(data []byte) []byte {
	if fte.getMessageCount()%10 == 0 {
		burstData := make([]byte, len(data)+32)
		copy(burstData, data)
		for i := len(data); i < len(burstData); i++ {
			burstData[i] = byte(32 + (i % 95))
		}
		return burstData
	}
	return data
}

func (fte *FTE) applyVKMLEvasion(obfuscated []byte) []byte        { return obfuscated }
func (fte *FTE) applyVKHardwareEvasion(obfuscated []byte) []byte  { return obfuscated }
func (fte *FTE) applyVKProtocolFidelity(obfuscated []byte) []byte { return obfuscated }
func (fte *FTE) realVKSizeObfuscation(originalSize int) int       { return originalSize + 32 }

func (fte *FTE) applyYandexBehavioralPatterns(data []byte) []byte {
	if fte.getMessageCount()%8 == 0 {
		searchData := make([]byte, len(data)+24)
		copy(searchData, data)
		for i := len(data); i < len(searchData); i++ {
			searchData[i] = byte(32 + (i % 95))
		}
		return searchData
	}
	return data
}

func (fte *FTE) applyYandexMLEvasion(data []byte) []byte {
	mlEvaded := make([]byte, len(data)+8)
	copy(mlEvaded, data)
	mlPatterns := [][]byte{{0x5F, 0xA0}, {0x2F, 0xD0}}
	pattern := mlPatterns[len(data)%len(mlPatterns)]
	copy(mlEvaded[len(data):], pattern)
	return mlEvaded
}

func (fte *FTE) applyMailruBehavioralPatterns(data []byte) []byte {
	if fte.getMessageCount()%12 == 0 {
		emailData := make([]byte, len(data)+28)
		copy(emailData, data)
		for i := len(data); i < len(emailData); i++ {
			emailData[i] = byte(32 + (i % 95))
		}
		return emailData
	}
	return data
}

func (fte *FTE) applyOzonBehavioralPatterns(data []byte) []byte {
	if fte.getMessageCount()%6 == 0 {
		shoppingData := make([]byte, len(data)+36)
		copy(shoppingData, data)
		for i := len(data); i < len(shoppingData); i++ {
			shoppingData[i] = byte(32 + (i % 95))
		}
		return shoppingData
	}
	return data
}

func (fte *FTE) applyRutubeBehavioralPatterns(data []byte) []byte {
	if fte.getMessageCount()%15 == 0 {
		videoData := make([]byte, len(data)+40)
		copy(videoData, data)
		for i := len(data); i < len(videoData); i++ {
			videoData[i] = byte(32 + (i % 95))
		}
		return videoData
	}
	return data
}

func (fte *FTE) applyGenericRussianBehavioralPatterns(data []byte) []byte {
	if fte.getMessageCount()%20 == 0 {
		genericData := make([]byte, len(data)+32)
		copy(genericData, data)
		for i := len(data); i < len(genericData); i++ {
			genericData[i] = byte(32 + (i % 95))
		}
		return genericData
	}
	return data
}

// --- WEBSITE FINGERPRINT DEFENSE ---

func (fte *FTE) applyWebsiteFingerprintDefense(data []byte, defense WebsiteFingerprintDefense) []byte {
	if !defense.Enabled {
		return data
	}
	switch defense.PaddingStrategy {
	case "adaptive":
		data = fte.applyAdaptivePadding(data, defense)
	case "deterministic":
		data = fte.applyDeterministicPadding(data, defense)
	case "random":
		data = fte.applyRandomPadding(data, defense)
	}
	if defense.TimingObfuscation {
		data = fte.applyTimingObfuscation(data)
	}
	return data
}

func (fte *FTE) applyAdaptivePadding(data []byte, defense WebsiteFingerprintDefense) []byte {
	targetSize := len(data) + secureRandInt(defense.CoverSize)
	return fte.padToTargetSize(data, targetSize)
}

func (fte *FTE) applyDeterministicPadding(data []byte, defense WebsiteFingerprintDefense) []byte {
	targetSize := ((len(data) + defense.CoverSize - 1) / defense.CoverSize) * defense.CoverSize
	return fte.padToTargetSize(data, targetSize)
}

func (fte *FTE) applyRandomPadding(data []byte, defense WebsiteFingerprintDefense) []byte {
	if secureRandFloat64() < defense.CoverProbability {
		targetSize := len(data) + secureRandInt(defense.CoverSize)
		return fte.padToTargetSize(data, targetSize)
	}
	return data
}

// Helper methods to avoid mutex issues or repetitive logic
func (fte *FTE) getProfile() *ProtocolProfile {
	fte.mutex.RLock()
	defer fte.mutex.RUnlock()
	return fte.profiles[fte.active]
}

func (fte *FTE) getActive() string {
	fte.mutex.RLock()
	defer fte.mutex.RUnlock()
	return fte.active
}

func (fte *FTE) getMessageCount() int {
	fte.mutex.RLock()
	defer fte.mutex.RUnlock()
	if fte.state == nil {
		return 0
	}
	return fte.state.MessageCount
}
