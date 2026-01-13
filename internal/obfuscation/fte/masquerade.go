package fte

import (
	"crypto/md5"
	"crypto/rand"
	"math"
	"math/big"
	mrand "math/rand"
	"time"

	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)

// Reference methods to silence staticcheck unused warnings
var _ = []interface{}{
	(*FTE).applyProtocolMasquerading,
}

// --- PROTOCOL MASQUERADING ---

func (fte *FTE) ApplyProtocolMasquerading(data []byte) []byte {
	profile := fte.getProfile()
	if profile == nil || !profile.Fingerprint.ProtocolMasquerading.Enabled {
		return data
	}
	masq := profile.Fingerprint.ProtocolMasquerading

	// CRITICAL FIX: Do not apply header spoofing to TLS handshakes!
	isTLS := isTLSHandshake(data)

	if masq.HeaderSpoofing && !isTLS {
		data = fte.applyHeaderSpoofing(data, masq)
	}
	if masq.BehavioralMimicry {
		data = fte.applyBehavioralMimicry(data, masq)
	}
	if masq.TimingMimicry {
		data = fte.applyTimingMimicry(data, masq)
	}
	if masq.SizeMimicry {
		data = fte.applySizeMimicry(data, masq)
	}
	if masq.MLResistance {
		data = fte.applyMLResistance(data, masq)
	}
	return data
}

// isTLSHandshake checks if the data is a TLS handshake packet
func isTLSHandshake(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// Content Type 0x16 = Handshake
	if data[0] != 0x16 {
		return false
	}
	// Version 0x0301 (TLS 1.0) - 0x0304 (TLS 1.3)
	if data[1] != 0x03 {
		return false
	}
	return true
}

func (fte *FTE) applyProtocolMasquerading(data []byte, obfuscation TrafficObfuscation) []byte {
	if obfuscation.ObfuscationLevel > 5 && obfuscation.TargetService != "" {
		data = fte.addApplicationSpecificHeaders(data, obfuscation)
	}
	return data
}

func (fte *FTE) applyHeaderSpoofing(data []byte, masq ProtocolMasquerading) []byte {
	if len(data) == 0 {
		return data
	}
	if masq.MasqueradingLevel > 3 {
		data = fte.addHTTPHeaders(data)
	}
	if masq.MasqueradingLevel > 5 {
		data = fte.addTLSHeaders(data)
	}
	if masq.MasqueradingLevel > 7 {
		data = fte.addApplicationHeaders(data, masq)
	}
	return data
}

func (fte *FTE) addHTTPHeaders(data []byte) []byte {
	httpHeader := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
	return append(httpHeader, data...)
}

func (fte *FTE) addTLSHeaders(data []byte) []byte {
	tlsHeader := []byte{0x16, 0x03, 0x03}
	return append(tlsHeader, data...)
}

func (fte *FTE) addApplicationHeaders(data []byte, masq ProtocolMasquerading) []byte {
	var appHeader []byte
	switch masq.TargetService {
	case "vk":
		appHeader = []byte("POST /api/v1/ HTTP/1.1\r\nHost: vk.com\r\n\r\n")
	case ProfileYandexFTE:
		appHeader = []byte("POST /api/ HTTP/1.1\r\nHost: yandex.ru\r\n\r\n")
	case ProfileMailruFTE:
		appHeader = []byte("POST /api/ HTTP/1.1\r\nHost: mail.ru\r\n\r\n")
	default:
		appHeader = []byte("POST /api/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	}
	return append(appHeader, data...)
}

func (fte *FTE) addApplicationSpecificHeaders(data []byte, obfuscation TrafficObfuscation) []byte {
	var headers []byte
	switch obfuscation.TargetService {
	case "vk":
		headers = []byte("POST /api/v1/messages.send HTTP/1.1\r\nHost: vk.com\r\nContent-Type: application/json\r\n\r\n")
	case ProfileYandexFTE:
		headers = []byte("POST /api/v1/search HTTP/1.1\r\nHost: yandex.ru\r\nContent-Type: application/json\r\n\r\n")
	case ProfileMailruFTE:
		headers = []byte("POST /api/v1/messages HTTP/1.1\r\nHost: mail.ru\r\nContent-Type: application/json\r\n\r\n")
	default:
		headers = []byte("POST /api/v1/ HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n")
	}
	return append(headers, data...)
}

func (fte *FTE) applyBehavioralMimicry(data []byte, masq ProtocolMasquerading) []byte {
	// SAFEGUARD: Disabled destructive payload modification.
	// These functions were modifying data[0], data[1], data[2] directly,
	// which corrupts the encrypt/transport headers and causes RST.
	/*
		if masq.MasqueradingLevel > 3 {
			data = fte.applyHumanLikePatterns(data)
		}
		if masq.MasqueradingLevel > 5 {
			data = fte.applySessionBehavior(data)
		}
		if masq.MasqueradingLevel > 7 {
			data = fte.applyDeviceBehavior(data)
		}
	*/
	return data
}

func (fte *FTE) applyHumanLikePatterns(data []byte) []byte {
	var v = secureRandInt(3) - 1
	if v != 0 && len(data) > 0 {
		data[0] = byte((int(data[0]) + v) % 256)
	}
	return data
}

func (fte *FTE) applySessionBehavior(data []byte) []byte {
	var v = secureRandInt(5) - 2
	if v != 0 && len(data) > 1 {
		data[1] = byte((int(data[1]) + v) % 256)
	}
	return data
}

func (fte *FTE) applyDeviceBehavior(data []byte) []byte {
	var v = secureRandInt(7) - 3
	if v != 0 && len(data) > 2 {
		data[2] = byte((int(data[2]) + v) % 256)
	}
	return data
}

// --- PADDING & SIZE MASQUERADING ---

func (fte *FTE) resizeToTarget(data []byte, targetSize int) []byte {
	if len(data) >= targetSize || targetSize > 1400 {
		return data
	}

	paddingSize := targetSize - len(data)
	padding := getPaddingBuffer(paddingSize)
	if cap(padding) < paddingSize {
		padding = make([]byte, paddingSize)
	} else {
		padding = padding[:paddingSize]
	}

	tempBuf := getPaddingBuffer(len(padding))
	if cap(tempBuf) < len(padding) {
		tempBuf = make([]byte, len(padding))
	} else {
		tempBuf = tempBuf[:len(padding)]
	}
	defer putPaddingBuffer(tempBuf)

	for i := range tempBuf {
		tempBuf[i] = byte(secureRandInt(256))
	}
	copy(padding, tempBuf)

	targetEntropy := fte.calculateTargetEntropy(fte.getActive())
	padding = fte.adjustPaddingEntropy(padding, targetEntropy)

	active := fte.getActive()
	switch active {
	case "vk":
		fte.applyVKontaktePadding(padding, data)
	case ProfileYandexFTE:
		fte.applyYandexPadding(padding, data)
	case ProfileMailruFTE:
		fte.applyMailruPadding(padding, data)
	default:
		fte.applyGenericPadding(padding, data)
	}

	return append(data, padding...)
}

func (fte *FTE) applyVKontaktePadding(padding, originalData []byte) {
	dataSeed := 0
	if len(originalData) > 0 {
		dataSeed = int(originalData[0])
	}
	jsonKeyOffset := 3 + (dataSeed % 7)
	jsonValueOffset := 5 + secureRandInt(9)
	for i := range padding {
		if i%jsonKeyOffset == 0 && i+1 < len(padding) && secureRandFloat64() < 0.6 {
			padding[i] = '"'
			padding[i+1] = byte(97 + secureRandInt(26))
		} else if i%jsonValueOffset == 0 && i+2 < len(padding) && secureRandFloat64() < 0.45 {
			padding[i] = ':'
			padding[i+1] = '"'
			padding[i+2] = byte(48 + secureRandInt(10))
		} else if secureRandFloat64() >= 0.1 {
			padding[i] = byte(32 + (int(padding[i]) % 95))
		}
	}
}

func (fte *FTE) applyYandexPadding(padding, originalData []byte) {
	htmlTagOffset := 4 + (len(originalData) % 6)
	for i := range padding {
		if i%htmlTagOffset == 0 && i+1 < len(padding) && secureRandFloat64() < 0.55 {
			padding[i] = '<'
			padding[i+1] = byte(97 + secureRandInt(26))
		} else if secureRandFloat64() >= 0.08 {
			padding[i] = byte(32 + (int(padding[i]) % 95))
		}
	}
}

func (fte *FTE) applyMailruPadding(padding, originalData []byte) {
	qpOffset := 10 + (len(originalData) % 7)
	for i := range padding {
		if i%qpOffset == 0 && i+1 < len(padding) && secureRandFloat64() < 0.5 {
			padding[i] = '='
			padding[i+1] = byte(48 + secureRandInt(10))
		} else if secureRandFloat64() >= 0.1 {
			padding[i] = byte(32 + (int(padding[i]) % 95))
		}
	}
}

func (fte *FTE) applyGenericPadding(padding, originalData []byte) {
	entropySeed := len(originalData)
	for i := range padding {
		padding[i] = byte(32 + ((int(padding[i]) + entropySeed) % 95))
	}
}

func (fte *FTE) applySizeMimicry(data []byte, masq ProtocolMasquerading) []byte {
	if !masq.SizeMimicry {
		return data
	}

	// Use masquerading level to determine size variation intensity
	variationFactor := float64(masq.MasqueradingLevel) / 10.0

	targetSize := fte.calculateRandomizedSize(len(data))
	// Apply masquerading level to adjust target
	if masq.MasqueradingLevel > 5 {
		// Higher levels: more aggressive padding for better mimicry
		targetSize = int(float64(targetSize) * (1.0 + variationFactor*0.3))
	}

	if len(data) < targetSize {
		data = fte.padToTargetSize(data, targetSize)
	} else if len(data) > targetSize {
		data = data[:targetSize]
	}
	return data
}

func (fte *FTE) applySizeRandomization(data []byte) []byte {
	targetSize := fte.calculateRandomizedSize(len(data))
	if len(data) < targetSize {
		data = fte.padToTargetSize(data, targetSize)
	} else if len(data) > targetSize {
		data = data[:targetSize]
	}
	return data
}

func (fte *FTE) calculateRandomizedSize(originalSize int) int {
	factor := secureRandFloat64() * 0.2
	target := originalSize + int(factor*float64(originalSize))
	if target < 1 {
		target = 1
	}
	if target > originalSize*2 {
		target = originalSize * 2
	}
	return target
}

func (fte *FTE) padToTargetSize(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data
	}
	padding := make([]byte, targetSize-len(data))
	for i := range padding {
		padding[i] = byte(secureRandInt(256))
	}
	return append(data, padding...)
}

// --- CORE TIMING MASQUERADING ---

func (fte *FTE) GetTimingDelay() int {
	fte.mutex.RLock()
	active := fte.active
	profile := fte.profiles[active]
	if active == "" || profile == nil {
		fte.mutex.RUnlock()
		return 50
	}
	inBurst := fte.state.InBurst
	burstCount := fte.state.BurstCount
	typingPause := fte.state.TypingPause
	pauseStart := fte.state.PauseStart
	fte.mutex.RUnlock()

	timing := profile.Timing

	if inBurst && burstCount > 0 {
		fte.mutex.Lock()
		fte.state.BurstCount--
		fte.mutex.Unlock()
		burstDelay := timing.MinInterval + (timing.MaxInterval-timing.MinInterval)/3
		return fte.applyNetworkConditions(burstDelay)
	}

	if typingPause {
		if pauseStart > 0 {
			pauseDelay := timing.PauseMin + (timing.PauseMax-timing.PauseMin)/2
			return fte.applyNetworkConditions(pauseDelay)
		}
		fte.mutex.Lock()
		fte.state.TypingPause = false
		fte.mutex.Unlock()
	}

	baseDelay := fte.calculateAdaptiveTiming(timing)
	if fte.mlSystem != nil {
		mlAdjustment := fte.getMLTimingAdjustment()
		baseDelay = int(float64(baseDelay) * mlAdjustment)
	}

	humanVar := fte.calculateHumanTimingVariance()
	baseDelay = int(float64(baseDelay) * (1.0 + 0.05*humanVar))
	if secureRandInt(20) == 0 {
		baseDelay += int(fte.generateRealisticHumanThinkTime() / time.Millisecond)
	}

	adjustedDelay := fte.applyNetworkConditions(baseDelay)
	if adjustedDelay < timing.MinInterval {
		adjustedDelay = timing.MinInterval
	} else if adjustedDelay > timing.MaxInterval {
		adjustedDelay = timing.MaxInterval
	}

	return adjustedDelay
}

func (fte *FTE) calculateAdaptiveTiming(timing TimingProfile) int {
	baseDelay := timing.MinInterval + (timing.MaxInterval-timing.MinInterval)/2
	active := fte.getActive()
	switch active {
	case "vk":
		baseDelay = int(float64(baseDelay) * 0.8)
	case ProfileYandexFTE:
		baseDelay = int(float64(baseDelay) * 0.9)
	case ProfileMailruFTE:
		baseDelay = int(float64(baseDelay) * 1.1)
	}
	timeVariance := fte.getTimeBasedVariance()
	baseDelay = int(float64(baseDelay) * timeVariance)
	return baseDelay
}

func (fte *FTE) getMLTimingAdjustment() float64 {
	if fte.mlSystem == nil {
		return 1.0
	}
	active := fte.getActive()
	count := fte.getMessageCount()
	context := &types.UnifiedTrafficContext{
		Direction: "outbound",
		Protocol:  active,
		Size:      count,
		Timestamp: util.GetGlobalTimeCache().Now(),
	}
	adjustmentBase := 1.0
	if context.Direction == "inbound" {
		adjustmentBase = 0.95
	}
	if context.Size > 1000 {
		adjustmentBase *= 1.05
	}

	// Use Protocol for service-specific timing adjustments
	switch context.Protocol {
	case "vk":
		adjustmentBase *= 0.85 // VK uses faster timing
	case "yandex":
		adjustmentBase *= 0.9 // Yandex is fast
	case "mailru":
		adjustmentBase *= 1.1 // Mail.ru is slower
	case "rutube":
		adjustmentBase *= 1.2 // Video streaming has longer intervals
	}

	// Use Timestamp for time-of-day adjustment
	hour := context.Timestamp.Hour()
	if hour >= 22 || hour <= 6 {
		// Night time: slower, humans sleeping
		adjustmentBase *= 1.3
	} else if hour >= 12 && hour <= 14 {
		// Lunch hour: slightly slower
		adjustmentBase *= 1.1
	}

	return adjustmentBase * (0.9 + secureRandFloat64()*0.2)
}

func (fte *FTE) applyNetworkConditions(delay int) int {
	profile := fte.getProfile()
	jitterBase := 10
	if profile != nil && profile.Name != "" {
		jitterBase = int(profile.Timing.Jitter)
	}
	gammaValue := fte.generateGamma(1.5, 0.3)
	jitter := int(float64(jitterBase) * gammaValue)
	if secureRandFloat64() < 0.05 {
		jitter *= 2 + int(secureRandFloat64()*3)
	}
	extraJitter := int(fte.generateRealisticNetworkJitter() / time.Millisecond)
	adjustedDelay := delay + (jitter - jitterBase/2) + extraJitter/4
	if adjustedDelay < 1 {
		adjustedDelay = 1
	}
	return adjustedDelay
}

func (fte *FTE) getTimeBasedVariance() float64 {
	now := util.GetGlobalTimeCache().Now()
	hour := now.Hour()
	dayOfWeek := int(now.Weekday())
	baseVariance := 1.0
	if hour >= 9 && hour <= 18 {
		baseVariance += 0.1
	} else if hour >= 22 || hour <= 6 {
		baseVariance -= 0.1
	}
	if dayOfWeek >= 1 && dayOfWeek <= 5 {
		baseVariance += 0.05
	} else {
		baseVariance -= 0.05
	}
	return baseVariance * (0.9 + secureRandFloat64()*0.2)
}

func (fte *FTE) calculateHumanTimingVariance() float64 {
	count := fte.getMessageCount()
	thinkTimeVariance := 0.05 + float64(count%8)/100.0
	burstVariance := 0.0
	if count%5 == 0 {
		burstVariance = 0.08 + float64(count%12)/100.0
	}
	sessionVariance := 0.0
	if count > 20 {
		sessionVariance = 0.04 + float64(count%8)/100.0
	}
	networkJitter := 0.02 + float64(count%5)/100.0
	return thinkTimeVariance + burstVariance + sessionVariance + networkJitter
}

func (fte *FTE) generateRealisticHumanThinkTime() time.Duration {
	active := fte.getActive()
	count := fte.getMessageCount()
	r := mrand.New(mrand.NewSource(util.GetGlobalTimeCache().NowNano() + int64(count)))
	var baseThinkTime time.Duration
	var variance float64
	switch active {
	case "vk":
		baseThinkTime, variance = 200*time.Millisecond, 0.3+r.Float64()*0.4
	case ProfileYandexFTE:
		baseThinkTime, variance = 500*time.Millisecond, 0.2+r.Float64()*0.3
	case ProfileRutubeFTE:
		baseThinkTime, variance = 800*time.Millisecond, 0.4+r.Float64()*0.4
	default:
		baseThinkTime, variance = 400*time.Millisecond, 0.3+r.Float64()*0.4
	}
	logNormalValue := math.Exp(r.NormFloat64()*math.Sqrt(variance) + math.Log(float64(baseThinkTime)))
	if count%7 < 2 {
		logNormalValue *= 0.3
	}
	return time.Duration(logNormalValue)
}

func (fte *FTE) generateRealisticNetworkJitter() time.Duration {
	active := fte.getActive()
	count := fte.getMessageCount()
	r := mrand.New(mrand.NewSource(util.GetGlobalTimeCache().NowNano() + int64(count)))
	var baseJitter time.Duration
	var shape, scale float64
	switch active {
	case "vk":
		baseJitter, shape, scale = 10*time.Millisecond, 2.0, 0.5
	case ProfileYandexFTE:
		baseJitter, shape, scale = 5*time.Millisecond, 1.5, 0.3
	case ProfileRutubeFTE:
		baseJitter, shape, scale = 15*time.Millisecond, 2.5, 0.6
	default:
		baseJitter, shape, scale = 6*time.Millisecond, 1.5, 0.3
	}
	jitter := time.Duration(float64(baseJitter) * fte.generateGamma(shape, scale))
	if r.Float64() < 0.05 {
		jitter *= time.Duration(2 + r.Float64()*3)
	}
	return jitter
}

func (fte *FTE) generateGamma(shape, scale float64) float64 {
	if shape < 1.0 {
		return fte.generateGamma(shape+1.0, scale) * math.Pow(secureRandFloat64(), 1.0/shape)
	}
	d := shape - 1.0/3.0
	c := 1.0 / math.Sqrt(9.0*d)
	for {
		x := mrand.NormFloat64()
		v := 1.0 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := secureRandFloat64()
		if u < 1.0-0.0331*(x*x)*(x*x) {
			return d * v * scale
		}
		if math.Log(u) < 0.5*x*x+d*(1.0-v+math.Log(v)) {
			return d * v * scale
		}
	}
}

func (fte *FTE) generateRealisticTiming(baseDelay int, variance float64) time.Duration {
	b, _ := rand.Int(rand.Reader, big.NewInt(10000))
	randFactor := float64(b.Int64())/5000.0 - 1.0
	variation := float64(baseDelay) * variance * randFactor
	finalDelay := float64(baseDelay) + variation
	if finalDelay < 0 {
		finalDelay = 0
	}
	return time.Duration(finalDelay) * time.Millisecond
}

func (fte *FTE) applyTimingMimicry(data []byte, masq ProtocolMasquerading) []byte {
	// SAFEGUARD: Disabled destructive payload modification.
	// These functions were modifying data[3], data[4], data[5] directly.
	/*
		if masq.MasqueradingLevel > 3 {
			data = fte.applyTimingVariations(data)
		}
		if masq.MasqueradingLevel > 5 {
			data = fte.applyBurstPatterns(data)
		}
		if masq.MasqueradingLevel > 7 {
			data = fte.applySessionTiming(data)
		}
	*/
	return data
}

func (fte *FTE) applyTimingVariations(data []byte) []byte {
	v := secureRandInt(10) - 5
	if v != 0 && len(data) > 3 {
		data[3] = byte((int(data[3]) + v) % 256)
	}
	return data
}

func (fte *FTE) applyBurstPatterns(data []byte) []byte {
	if len(data) > 4 {
		data[4] ^= 0x55
	}
	return data
}

func (fte *FTE) applySessionTiming(data []byte) []byte {
	if len(data) > 5 {
		data[5] ^= 0xAA
	}
	return data
}

func (fte *FTE) applyTimingRandomization(data []byte) []byte {
	markers := fte.generateTimingMarkersBytes(len(data))
	return fte.insertTimingMarkers(data, markers)
}

func (fte *FTE) generateTimingMarkersBytes(dataLen int) []byte {
	count := dataLen / 10
	if count <= 0 {
		count = 1
	}
	markers := make([]byte, count)
	for i := range markers {
		markers[i] = byte(secureRandInt(256))
	}
	return markers
}

func (fte *FTE) insertTimingMarkers(data, markers []byte) []byte {
	if len(markers) == 0 {
		return data
	}
	step := len(data) / len(markers)
	result := make([]byte, len(data)+len(markers))
	rI, mI := 0, 0
	for i, b := range data {
		if mI < len(markers) && i == mI*step {
			result[rI] = markers[mI]
			rI++
			mI++
		}
		result[rI] = b
		rI++
	}
	return result
}

// --- REAL DPI EVASION ---

func (fte *FTE) ApplyRealDPIEvasion(data []byte, active string) ([]byte, error) {
	if active == "" {
		return data, nil
	}
	serviceHash := fte.calculateServiceHashBytes(active)
	data = fte.addEvasionMarkers(data, serviceHash)
	data = fte.applyStatisticalMasking(data)
	return data, nil
}

func (fte *FTE) calculateServiceHashBytes(service string) []byte {
	hash := md5.Sum([]byte(service))
	return hash[:4]
}

func (fte *FTE) addEvasionMarkers(data []byte, hash []byte) []byte {
	if len(data) < 10 {
		return data
	}
	for i := 0; i < len(hash); i++ {
		pos := (int(hash[i]) * 13) % len(data)
		data[pos] ^= hash[i]
	}
	return data
}
