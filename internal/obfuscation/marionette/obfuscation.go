package marionette

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math"
	mrand "math/rand"
	"time"

	"golang.org/x/crypto/curve25519"

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
	// Apply headers LAST (Outer layer) to ensure valid HTTP/TLS look
	if profile.ObfuscationLevel > 3 {
		data = m.addProtocolHeaders(data, profile)
	}

	// HTTPS MASQUERADE: Inject Fake Client Hello on the VERY FIRST packet.
	// This makes the connection start look like a real TLS Handshake to google.com.
	// We only do this once per connection session.
	m.Mutex.RLock()
	count := m.State.PacketCount
	m.Mutex.RUnlock()

	// Note: PacketCount is incremented in ProcessPacket BEFORE calling applyAction/applyProtocolObfuscation.
	// So for the first packet, count is 1.
	if count == 1 {
		// Prepend Fake Client Hello (SNI=high reputation domain)
		// XTLS/REALITY strategy: Use a domain that usually resolves to a large cloud (CDNs).
		// We avoid iterating random small domains to prevent SNI/IP mismatches if the server falls back.

		// Check for custom SNI in profile
		sni := profile.SNI
		realityKey := profile.RealityPublicKey

		if sni == "" || sni == "random_ru" || sni == "random" {
			var snis []string

			if sni == "random_ru" {
				snis = []string{
					"vk.com",
					"dzen.ru",
					"www.ozon.ru",
					"www.wildberries.ru",
					"rutube.ru",
					"yandex.ru",
					"disk.yandex.ru",
					"mail.ru",
					"ok.ru",
				}
			} else {
				// Global Mix
				snis = []string{
					// Global high-reputation
					"www.microsoft.com",
					"www.google.com",
					"www.samsung.com",
					"www.apple.com",
					"code.jquery.com",
					"www.twitch.tv",
					"ajax.googleapis.com",
					// Russian High-Reputation
					"vk.com",
					"dzen.ru",
					"rutube.ru",
					"yandex.ru",
				}
			}
			sni = snis[m.Rand.Intn(len(snis))]
		}
		// This header mimics a standard Chrome Client Hello
		fakeHello := m.generateFakeClientHello(sni, realityKey)

		// Create a new buffer: [Fake Hello] + [Real Data (already wrapped in AppData)]
		res := make([]byte, len(fakeHello)+len(data))
		copy(res, fakeHello)
		copy(res[len(fakeHello):], data)
		return res
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

// --- HTTPS Masquerade Helpers ---

func (m *Marionette) generateFakeClientHello(sni string, realityPubKeyHex string) []byte {
	// Construct a realistic TLS 1.3 Client Hello (Simulating Chrome)
	// Structure:
	// 1. Handshake Header
	// 2. Client Hello Body:
	//    - Legacy Version (0x0303)
	//    - Random (32)
	//    - Session ID (32)
	//    - Cipher Suites (Modern 1.3 + 1.2 Fallback)
	//    - Compression (0x00)
	//    - Extensions (SNI, SupportedVersions, KeyShare, SigAlgs, etc.)

	// Default Public Key
	// This matches the server's public key provided in the connection string
	// Provided by user: 6c4b5a0a561f56792270ef886245bc8e3c66bc3bd1e685d13b89a3a3a875772a
	defaultPubKey := "6c4b5a0a561f56792270ef886245bc8e3c66bc3bd1e685d13b89a3a3a875772a"

	// Use provided key or fallback to default
	targetKeyHex := realityPubKeyHex
	if targetKeyHex == "" {
		targetKeyHex = defaultPubKey
	}

	// --- Authentication (REALITY) ---
	// Start with secure random for ClientRandom placeholder
	clientRandom := make([]byte, 32)
	// Use crypto/rand for secure random
	if _, err := rand.Read(clientRandom); err != nil {
		m.Rand.Read(clientRandom)
	}

	var sessionID []byte

	// Perform X25519-based Auth
	if len(targetKeyHex) == 64 { // Expecting 32 bytes hex
		pubKeyBytes, err := hex.DecodeString(targetKeyHex)
		if err == nil {
			// Generate Ephemeral Private Key
			priv := make([]byte, 32)
			if _, err := rand.Read(priv); err == nil {
				// Derive Ephemeral Public Key (Client's Public Key)
				myPub, err := curve25519.X25519(priv, curve25519.Basepoint)
				if err == nil {
					// 1. ClientRandom BECOMES the Client's Ephemeral Public Key
					copy(clientRandom, myPub)

					// 2. Calculate Shared Secret: X25519(ClientPriv, ServerPub)
					sharedSecret, err := curve25519.X25519(priv, pubKeyBytes)
					if err == nil {
						// 3. Calculate Auth Tag: HMAC-SHA256(SharedSecret, "whispera-session-id")
						mac := hmac.New(sha256.New, sharedSecret)
						mac.Write([]byte("whispera-session-id"))
						sessionID = mac.Sum(nil)[:32]
					}
				}
			}
		}
	}

	// Recovery: If sessionID is still nil (Key decode failed or crypto error), generate random one
	// This will likely fail server auth, but ensures valid TLS structure.
	if sessionID == nil {
		sessionID = make([]byte, 32)
		// Use a fixed fallback pattern or random
		m.Rand.Read(sessionID)
	}

	// --- Extensions Construction ---

	// 1. SNI Extension
	sniContent := []byte(sni)
	sniExtLen := 5 + len(sniContent)
	sniExt := make([]byte, 4+sniExtLen)
	sniExt[0], sniExt[1] = 0x00, 0x00 // Type: server_name
	sniExt[2], sniExt[3] = byte(sniExtLen>>8), byte(sniExtLen)
	sniExt[4], sniExt[5] = byte((sniExtLen-2)>>8), byte(sniExtLen-2)
	sniExt[6] = 0x00 // Name Type: host_name
	sniExt[7], sniExt[8] = byte(len(sniContent)>>8), byte(len(sniContent))
	copy(sniExt[9:], sniContent)

	// 2. Supported Groups (Curve25519, secp256r1)
	groups := []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18} // X25519, P-256, P-384
	sgExt := make([]byte, 4+2+len(groups))
	sgExt[0], sgExt[1] = 0x00, 0x0a // Type: supported_groups
	sgExt[2], sgExt[3] = 0x00, byte(2+len(groups))
	sgExt[4], sgExt[5] = 0x00, byte(len(groups))
	copy(sgExt[6:], groups)

	// 3. Key Share (for TLS 1.3 1-RTT) - Fake X25519 key
	keyShareData := make([]byte, 32)
	m.Rand.Read(keyShareData)
	ksContentLen := 2 + 2 + 2 + 32 // GroupListLen(2) + Group(2) + KeyLen(2) + Key(32)
	ksExt := make([]byte, 4+ksContentLen)
	ksExt[0], ksExt[1] = 0x00, 0x33 // Type: key_share
	ksExt[2], ksExt[3] = byte(ksContentLen>>8), byte(ksContentLen)
	idx := 4
	ksExt[idx], ksExt[idx+1] = byte((ksContentLen-2)>>8), byte(ksContentLen-2) // ClientKeyShareList Len
	idx += 2
	ksExt[idx], ksExt[idx+1] = 0x00, 0x1d // Group: X25519
	idx += 2
	ksExt[idx], ksExt[idx+1] = 0x00, 0x20 // Key Len: 32
	idx += 2
	copy(ksExt[idx:], keyShareData)

	// 4. Supported Versions (TLS 1.3 Only for Strict Mode)
	svExt := []byte{
		0x00, 0x2b, // Type: supported_versions
		0x00, 0x03, // Len
		0x02,       // Versions List Len
		0x03, 0x04, // TLS 1.3
	}

	// 5. Signature Algorithms
	saExt := []byte{
		0x00, 0x0d, // Type: signature_algorithms
		0x00, 0x08, // Len
		0x00, 0x06, // List Len
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x08, 0x04, // rsa_pss_rsae_sha256
		0x04, 0x01, // rsa_pkcs1_sha256
	}

	// Combine Extensions (Order typically: SNI, SigAlgs, Groups, Versions, KeyShare, Padding)
	extensions := []byte{}
	extensions = append(extensions, sniExt...)
	extensions = append(extensions, saExt...)
	extensions = append(extensions, sgExt...)
	extensions = append(extensions, svExt...)
	extensions = append(extensions, ksExt...)

	// Handshake Body
	// NOTE: ClientRandom is already set above (used for Public Key transport in REALITY)

	// Modern Ciphers (TLS 1.3 + GCM)
	ciphers := []byte{
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
		0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
		0xc0, 0x2b, // ECDHE-ECDSA-AES128-GCM-SHA256
		0xc0, 0x2f, // ECDHE-RSA-AES128-GCM-SHA256
	}

	compression := []byte{0x01, 0x00} // Null compression

	bodyLen := 2 + 32 + 1 + 32 + 2 + len(ciphers) + len(compression) + 2 + len(extensions)

	handshake := make([]byte, 4+bodyLen)
	handshake[0] = 0x01 // Type: Client Hello
	handshake[1] = 0x00
	handshake[2] = byte(bodyLen >> 8)
	handshake[3] = byte(bodyLen)

	idx = 4
	handshake[idx], handshake[idx+1] = 0x03, 0x03 // Legacy Version (TLS 1.2)
	idx += 2
	copy(handshake[idx:], clientRandom)
	idx += 32
	handshake[idx] = 32 // Session ID Len
	idx++
	copy(handshake[idx:], sessionID)
	idx += 32
	handshake[idx], handshake[idx+1] = byte(len(ciphers)>>8), byte(len(ciphers))
	idx += 2
	copy(handshake[idx:], ciphers)
	idx += len(ciphers)
	copy(handshake[idx:], compression)
	idx += len(compression)
	handshake[idx], handshake[idx+1] = byte(len(extensions)>>8), byte(len(extensions))
	idx += 2
	copy(handshake[idx:], extensions)

	// Wrap in TLS Record (Type 0x16)
	recordLen := len(handshake)
	record := make([]byte, 5+recordLen)
	record[0] = 0x16
	record[1], record[2] = 0x03, 0x01 // Record Layer Version (TLS 1.0)
	record[3], record[4] = byte(recordLen>>8), byte(recordLen)
	copy(record[5:], handshake)

	return record
}

// --- Padding Logic (formerly marionette_padding.go) ---

func (m *Marionette) generateVKJSONPadding(padding []byte, r *mrand.Rand) {
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

func (m *Marionette) generateYandexSearchPadding(padding []byte, r *mrand.Rand) {
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

func (m *Marionette) generateMailruEmailPadding(padding []byte, r *mrand.Rand) {
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

func (m *Marionette) generateRutubeVideoPadding(padding []byte, r *mrand.Rand) {
	for i := range padding {
		padding[i] = byte(r.Intn(256))
	}
}

func (m *Marionette) generateOzonProductPadding(padding []byte, r *mrand.Rand) {
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

func (m *Marionette) generateDefaultHTTPPadding(padding []byte, r *mrand.Rand) {
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

		if sni, ok := params["sni"].(string); ok {
			prof.SNI = sni
		}
		if pubKey, ok := params["reality_public_key"].(string); ok {
			prof.RealityPublicKey = pubKey
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
