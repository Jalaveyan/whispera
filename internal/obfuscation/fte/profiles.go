package fte

import (
	"regexp"
	"time"
)

// addRussianServiceProfiles definitions for VK, VK Video, Yandex, MailRu, Rutube, Ozon
func (fte *FTE) addRussianServiceProfiles() {
	fte.addVKProfile()
	fte.addVKVideoProfile()
	fte.addYandexProfile()
	fte.addMailRuProfile()
	fte.addRutubeProfile()
	fte.addOzonProfile()
}

func (fte *FTE) addVKProfile() {
	// VK (VKontakte) accurate profile based on real API analysis
	// VK uses REST API with JSON, ~3 billion page views daily
	fte.addProfile("vk", &ProtocolProfile{
		Name:  "VKontakte App",
		Regex: regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`),
		// Real VK API packet sizes
		MinSize:     64,
		MaxSize:     16384,
		CommonSizes: []int{128, 256, 512, 1024, 2048, 4096, 8192},
		Timing: TimingProfile{
			// VK real usage: avg 37 min/day sessions, scrolling feed
			MinInterval: 100,  // API polling
			MaxInterval: 5000, // Feed scrolling pause
			BurstProb:   0.35, // Feed loading bursts
			BurstMin:    3,
			BurstMax:    12,    // Multiple media loads
			PauseProb:   0.20,  // Reading pauses
			PauseMin:    2000,  // 2 sec reading
			PauseMax:    30000, // 30 sec reading long post
			RTT:         35,    // Moscow DC
			Jitter:      10,
		},
		Headers: map[string]string{
			// Real VK Android app User-Agent format
			"User-Agent":          "VKAndroidApp/8.72-19234 (Android 14; SDK 34; arm64-v8a; samsung SM-S918B; ru)",
			"Content-Type":        "application/x-www-form-urlencoded",
			"Accept":              "application/json",
			"X-VK-Android-Client": "new",
			"X-Requested-With":    "XMLHttpRequest",
		},
		Fingerprint: FingerprintProfile{
			JA3:                fte.generateUniqueJA3Fingerprint("vk"),
			JA4:                fte.generateUniqueJA4Fingerprint("vk"),
			JA4S:               fte.generateUniqueJA4Fingerprint("vk"),
			PacketSizePatterns: []int{128, 256, 512, 1024, 2048, 4096, 8192},
			TimingPatterns:     []int64{100, 300, 800, 2000, 5000, 15000},
			EntropyProfile:     EntropyProfile{TargetEntropy: 7.2, EntropyVariance: 0.3, AntiEntropy: true, StatisticalNoise: 0.12},
			ObfuscationLevel:   9, AntiAnalysis: true, StatisticalMasking: true,
			HTTP2: HTTP2Fingerprint{
				Settings:    map[string]int{"HEADER_TABLE_SIZE": 4096, "ENABLE_PUSH": 0, "MAX_CONCURRENT_STREAMS": 100, "INITIAL_WINDOW_SIZE": 65535, "MAX_FRAME_SIZE": 16384},
				HeaderOrder: []string{":method", ":path", ":scheme", ":authority", "user-agent", "accept", "accept-language"},
				WindowSize:  65535, StreamCount: 100, PingInterval: 30 * time.Second,
			},
			Behavioral: BehavioralProfile{
				ThinkTime:           2 * time.Second,  // Reading content
				BurstPattern:        "feed_scroll",    // Scrolling behavior
				SessionLength:       37 * time.Minute, // Real VK avg session
				IdleTime:            5 * time.Minute,
				HumanLikePatterns:   true,
				AdaptiveLearning:    true,
				InteractionPatterns: []string{"feed_scroll", "like", "comment", "message", "story_view"},
				DeviceFingerprint:   "samsung_android14_vk",
				ContextAwareness:    true,
			},
			WebsiteFingerprintDefense: WebsiteFingerprintDefense{Enabled: true, PaddingStrategy: "adaptive", TimingObfuscation: true, SizeObfuscation: true, DirectionObfuscation: true, CoverTraffic: true, CoverProbability: 0.12, CoverSize: 256, CoverInterval: 8 * time.Second},
			TrafficObfuscation:        TrafficObfuscation{Enabled: true, MasqueradingType: "behavioral", ObfuscationLevel: 9, AdaptiveObfuscation: true, StatisticalMasking: true, EntropyAdjustment: true, TimingRandomization: true, SizeRandomization: true},
			ProtocolMasquerading:      ProtocolMasquerading{Enabled: true, TargetProtocol: "vk", MasqueradingLevel: 9, HeaderSpoofing: true, BehavioralMimicry: true, TimingMimicry: true, SizeMimicry: true, AdaptiveMimicry: true, MLResistance: true},
		},
	})
}

// VK Video profile - accurate for video.vk.com streaming
// Based on VK video traffic patterns: 960 million video views daily
func (fte *FTE) addVKVideoProfile() {
	fte.addProfile("vkvideo", &ProtocolProfile{
		Name:  "VK Video",
		Regex: regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`),
		// Video streaming packet sizes - chunks and segments
		MinSize:     256,                                                // Minimum chunk
		MaxSize:     65536,                                              // Full video segment
		CommonSizes: []int{1024, 2048, 4096, 8192, 16384, 32768, 65536}, // HLS/DASH chunks
		Timing: TimingProfile{
			// Video streaming timing - buffering + continuous playback
			MinInterval: 20,    // Fast segment requests during buffering
			MaxInterval: 10000, // Segment duration gaps
			BurstProb:   0.45,  // High burst during initial buffering
			BurstMin:    5,
			BurstMax:    25,   // Multiple quality segments
			PauseProb:   0.08, // Rare pauses during streaming
			PauseMin:    100,
			PauseMax:    5000, // Bitrate adaptation pause
			RTT:         30,   // CDN edge server
			Jitter:      8,
		},
		Headers: map[string]string{
			// VK Video player headers
			"User-Agent":         "VKAndroidApp/8.72-19234 (Android 14; SDK 34; arm64-v8a; samsung SM-S918B; ru)",
			"Accept":             "video/*,*/*;q=0.8",
			"Accept-Encoding":    "gzip, deflate, br",
			"Range":              "bytes=0-",
			"X-VK-Video-Player":  "android_native",
			"X-VK-Video-Quality": "auto",
		},
		Fingerprint: FingerprintProfile{
			JA3:                fte.generateUniqueJA3Fingerprint("vkvideo"),
			JA4:                fte.generateUniqueJA4Fingerprint("vkvideo"),
			PacketSizePatterns: []int{1024, 2048, 4096, 8192, 16384, 32768, 65536},
			TimingPatterns:     []int64{20, 50, 100, 500, 2000, 5000, 10000},
			EntropyProfile:     EntropyProfile{TargetEntropy: 0.98, EntropyVariance: 0.02, AntiEntropy: false}, // Video is high entropy
			ObfuscationLevel:   8, AntiAnalysis: true, StatisticalMasking: true,
			HTTP2: HTTP2Fingerprint{
				Settings:     map[string]int{"HEADER_TABLE_SIZE": 4096, "ENABLE_PUSH": 0, "MAX_CONCURRENT_STREAMS": 250, "INITIAL_WINDOW_SIZE": 16777216, "MAX_FRAME_SIZE": 16384},
				HeaderOrder:  []string{":method", ":path", ":scheme", ":authority", "range", "user-agent", "accept"},
				WindowSize:   16777216, // Large window for video
				StreamCount:  250,
				PingInterval: 30 * time.Second,
			},
			Behavioral: BehavioralProfile{
				ThinkTime:           100 * time.Millisecond, // Fast segment requests
				BurstPattern:        "video_streaming",
				SessionLength:       15 * time.Minute, // Average video watch time
				IdleTime:            5 * time.Second,  // Buffering interval
				HumanLikePatterns:   true,
				InteractionPatterns: []string{"play", "pause", "seek", "quality_change", "fullscreen"},
				DeviceFingerprint:   "samsung_android14_vkvideo",
				ContextAwareness:    true,
			},
			WebsiteFingerprintDefense: WebsiteFingerprintDefense{Enabled: true, PaddingStrategy: "streaming", TimingObfuscation: false, SizeObfuscation: true, DirectionObfuscation: false, CoverTraffic: false},
			TrafficObfuscation:        TrafficObfuscation{Enabled: true, MasqueradingType: "video_streaming", ObfuscationLevel: 8, AdaptiveObfuscation: true, StatisticalMasking: true, EntropyAdjustment: false, TimingRandomization: false, SizeRandomization: true},
			ProtocolMasquerading:      ProtocolMasquerading{Enabled: true, TargetProtocol: "vkvideo", MasqueradingLevel: 9, HeaderSpoofing: true, BehavioralMimicry: true, TimingMimicry: true, SizeMimicry: true, AdaptiveMimicry: true, MLResistance: true},
		},
	})
}

func (fte *FTE) addYandexProfile() {
	fte.addProfile("yandex", &ProtocolProfile{
		Name:    "Yandex",
		Regex:   regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`),
		MinSize: 24, MaxSize: 4096,
		CommonSizes: []int{24, 48, 96, 192, 384, 768, 1536, 3072},
		Timing: TimingProfile{
			MinInterval: 30, MaxInterval: 150, BurstProb: 0.25, BurstMin: 1, BurstMax: 6,
			PauseProb: 0.1, PauseMin: 100, PauseMax: 800, RTT: 35, Jitter: 10,
		},
		Headers: map[string]string{
			"User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Content-Type":     "application/x-www-form-urlencoded",
			"X-Yandex-API-Key": "yandex-api-key",
		},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("yandex"),
			JA4: fte.generateUniqueJA4Fingerprint("yandex"),
			HTTP2: HTTP2Fingerprint{
				Settings:    map[string]int{"HEADER_TABLE_SIZE": 4096, "ENABLE_PUSH": 1, "MAX_CONCURRENT_STREAMS": 100, "INITIAL_WINDOW_SIZE": 65535, "MAX_FRAME_SIZE": 16384, "MAX_HEADER_LIST_SIZE": 8192},
				HeaderOrder: []string{":method", ":path", ":scheme", ":authority", "user-agent", "accept"},
				WindowSize:  65535, StreamCount: 100, PingInterval: 30 * time.Second,
			},
			Behavioral: BehavioralProfile{ThinkTime: 1500 * time.Millisecond, BurstPattern: "normal", SessionLength: 20 * time.Minute, IdleTime: 1 * time.Minute},
		},
	})
}

func (fte *FTE) addMailRuProfile() {
	fte.addProfile("mailru", &ProtocolProfile{
		Name:    "Mail.ru",
		Regex:   regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`),
		MinSize: 28, MaxSize: 6144,
		CommonSizes: []int{28, 56, 112, 224, 448, 896, 1792, 3584},
		Timing: TimingProfile{
			MinInterval: 40, MaxInterval: 180, BurstProb: 0.18, BurstMin: 1, BurstMax: 5,
			PauseProb: 0.12, PauseMin: 150, PauseMax: 600, RTT: 40, Jitter: 12,
		},
		Headers: map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Content-Type": "application/json",
			"X-Mailru-API": "mailru-api-key",
		},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("mailru"),
			JA4: fte.generateUniqueJA4Fingerprint("mailru"),
			HTTP2: HTTP2Fingerprint{
				Settings:    map[string]int{"HEADER_TABLE_SIZE": 4096, "ENABLE_PUSH": 1, "MAX_CONCURRENT_STREAMS": 100},
				HeaderOrder: []string{":method", ":path", ":scheme", ":authority", "user-agent", "accept"},
				WindowSize:  65535, StreamCount: 100, PingInterval: 30 * time.Second,
			},
			Behavioral: BehavioralProfile{ThinkTime: 2 * time.Second, BurstPattern: "exponential", SessionLength: 25 * time.Minute, IdleTime: 2 * time.Minute},
		},
	})
}

func (fte *FTE) addRutubeProfile() {
	fte.addProfile("rutube", &ProtocolProfile{
		Name:    "Rutube",
		Regex:   regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`),
		MinSize: 40, MaxSize: 4096,
		CommonSizes: []int{40, 80, 160, 320, 640, 1280, 2560, 4096},
		Timing: TimingProfile{
			MinInterval: 60, MaxInterval: 300, BurstProb: 0.25, BurstMin: 1, BurstMax: 6,
			PauseProb: 0.15, PauseMin: 200, PauseMax: 1000, RTT: 50, Jitter: 20,
		},
		Headers: map[string]string{
			"User-Agent":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Content-Type":   "application/json",
			"X-Rutube-API":   "rutube-api-key",
			"X-Rutube-Video": "rutube-video",
		},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("rutube"),
			JA4: fte.generateUniqueJA4Fingerprint("rutube"),
			HTTP2: HTTP2Fingerprint{
				Settings:    map[string]int{"HEADER_TABLE_SIZE": 4096, "ENABLE_PUSH": 1, "MAX_CONCURRENT_STREAMS": 100},
				HeaderOrder: []string{":method", ":path", ":scheme", ":authority", "user-agent", "accept"},
				WindowSize:  65535, StreamCount: 100, PingInterval: 30 * time.Second,
			},
			Behavioral: BehavioralProfile{ThinkTime: 2 * time.Second, BurstPattern: "exponential", SessionLength: 30 * time.Minute, IdleTime: 2 * time.Minute},
		},
	})
}

func (fte *FTE) addOzonProfile() {
	fte.addProfile("ozon", &ProtocolProfile{
		Name:    "Ozon",
		Regex:   regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`),
		MinSize: 36, MaxSize: 2048,
		CommonSizes: []int{36, 72, 144, 288, 576, 1152, 2048},
		Timing: TimingProfile{
			MinInterval: 45, MaxInterval: 250, BurstProb: 0.22, BurstMin: 1, BurstMax: 4,
			PauseProb: 0.18, PauseMin: 100, PauseMax: 800, RTT: 55, Jitter: 18,
		},
		Headers: map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Content-Type": "application/json",
			"X-Ozon-API":   "ozon-api-key",
		},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("ozon"),
			JA4: fte.generateUniqueJA4Fingerprint("ozon"),
			HTTP2: HTTP2Fingerprint{
				Settings:    map[string]int{"HEADER_TABLE_SIZE": 4096, "ENABLE_PUSH": 1, "MAX_CONCURRENT_STREAMS": 100},
				HeaderOrder: []string{":method", ":path", ":scheme", ":authority", "user-agent", "accept"},
				WindowSize:  65535, StreamCount: 100, PingInterval: 30 * time.Second,
			},
			Behavioral: BehavioralProfile{ThinkTime: 1 * time.Second, BurstPattern: "normal", SessionLength: 15 * time.Minute, IdleTime: 1 * time.Minute},
		},
	})
}

func (fte *FTE) addModernProfiles() {
	fte.addHTTP2Profile()
	fte.addWebSocketProfile()
	fte.addQUICProfile()
	fte.addTLSProfile()
}

func (fte *FTE) addHTTP2Profile() {
	fte.addProfile("http2", &ProtocolProfile{
		Name:    "HTTP/2",
		Regex:   regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`),
		MinSize: 8, MaxSize: 16384,
		CommonSizes: []int{8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 512, 1024},
		Timing: TimingProfile{
			MinInterval: 50, MaxInterval: 300, BurstProb: 0.12, BurstMin: 2, BurstMax: 8,
			PauseProb: 0.08, PauseMin: 200, PauseMax: 1000, RTT: 50, Jitter: 10,
		},
		Headers: map[string]string{"Content-Type": "application/octet-stream", "User-Agent": "Mozilla/5.0..."},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("vk"), JA4: fte.generateUniqueJA4Fingerprint("vk"),
			HTTP2: HTTP2Fingerprint{
				Settings:    map[string]int{"HEADER_TABLE_SIZE": 4096, "ENABLE_PUSH": 1, "MAX_CONCURRENT_STREAMS": 100, "INITIAL_WINDOW_SIZE": 65535},
				HeaderOrder: []string{":method", ":path", ":scheme", ":authority"},
				WindowSize:  65535, StreamCount: 100, PingInterval: 30 * time.Second,
			},
			Behavioral:         BehavioralProfile{ThinkTime: 1 * time.Second, BurstPattern: "exponential", SessionLength: 30 * time.Minute, IdleTime: 2 * time.Minute},
			PacketSizePatterns: []int{64, 128, 512, 1300, 1600, 4096, 16384}, TimingPatterns: []int64{1, 5, 10, 50, 150, 300},
			EntropyProfile:   EntropyProfile{TargetEntropy: 0.9, EntropyVariance: 0.05, AntiEntropy: true, StatisticalNoise: 0.1},
			ObfuscationLevel: 8, AntiAnalysis: true, StatisticalMasking: true, MLResistance: true, AdaptiveEvasion: true, ContextAwareness: true,
		},
	})
}

func (fte *FTE) addWebSocketProfile() {
	fte.addProfile("websocket", &ProtocolProfile{
		Name:    "WebSocket",
		Regex:   regexp.MustCompile(`^[\x00-\x7F]{12,}$`),
		MinSize: 12, MaxSize: 4096,
		CommonSizes: []int{12, 18, 25, 32, 45, 67, 89, 120, 156, 200, 280, 350, 512},
		Timing: TimingProfile{
			MinInterval: 100, MaxInterval: 500, BurstProb: 0.08, BurstMin: 1, BurstMax: 4,
			PauseProb: 0.15, PauseMin: 1000, PauseMax: 5000, RTT: 30, Jitter: 5,
		},
		Headers: map[string]string{"Sec-WebSocket-Protocol": "chat", "Sec-WebSocket-Version": "13", "Origin": "https://vk.com"},
		Fingerprint: FingerprintProfile{
			Behavioral:         BehavioralProfile{BurstPattern: "interactive", HumanLikePatterns: true},
			PacketSizePatterns: []int{20, 100, 400}, TimingPatterns: []int64{100, 300, 800, 1500},
			EntropyProfile: EntropyProfile{TargetEntropy: 0.6, EntropyVariance: 0.2, StatisticalNoise: 0.15},
		},
	})
}

func (fte *FTE) addQUICProfile() {
	fte.addProfile("quic", &ProtocolProfile{
		Name:    "QUIC",
		Regex:   regexp.MustCompile(`^[\x00-\xFF]{20,}$`),
		MinSize: 20, MaxSize: 1200,
		CommonSizes: []int{20, 28, 36, 44, 60, 76, 92, 108, 140, 172, 204, 236, 300, 400, 600, 800, 1000, 1200},
		Timing: TimingProfile{
			MinInterval: 10, MaxInterval: 100, BurstProb: 0.25, BurstMin: 2, BurstMax: 12,
			PauseProb: 0.05, PauseMin: 100, PauseMax: 500,
		},
		Headers: map[string]string{"Alt-Svc": "h3=\":443\"; ma=86400"},
		Fingerprint: FingerprintProfile{
			QUIC: QUICFingerprint{Version: 1}, Behavioral: BehavioralProfile{BurstPattern: "streaming", HumanLikePatterns: false},
			PacketSizePatterns: []int{1200, 1252, 1300}, TimingPatterns: []int64{1, 2, 4, 8},
			EntropyProfile: EntropyProfile{TargetEntropy: 0.98, EntropyVariance: 0.01, AntiEntropy: false},
			MLResistance:   true, AdaptiveEvasion: true,
		},
	})
}

func (fte *FTE) addTLSProfile() {
	fte.addProfile("tls", &ProtocolProfile{
		Name:    "TLS",
		Regex:   regexp.MustCompile(`^[\x00-\xFF]{16,}$`),
		MinSize: 16, MaxSize: 16384,
		CommonSizes: []int{16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384},
		Timing: TimingProfile{
			MinInterval: 100, MaxInterval: 1000, BurstProb: 0.05, BurstMin: 1, BurstMax: 3,
			PauseProb: 0.3, PauseMin: 1000, PauseMax: 5000,
		},
		Headers: map[string]string{"Content-Type": "application/octet-stream", "Strict-Transport-Security": "max-age=31536000"},
		Fingerprint: FingerprintProfile{
			JA3:        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
			JA4:        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
			Behavioral: BehavioralProfile{ThinkTime: 2 * time.Second, BurstPattern: "normal", SessionLength: 60 * time.Minute, IdleTime: 5 * time.Minute},
		},
	})
}

func (fte *FTE) addSocialProfiles() {
	fte.addTelegramProfile()
	fte.addWhatsAppProfile()
	fte.addInstagramProfile()
	fte.addYouTubeProfile()
}

func (fte *FTE) addTelegramProfile() {
	// Telegram MTProto 2.0 accurate profile
	// Based on real protocol analysis - padding 12-1024 bytes, message length multiple of 16
	fte.addProfile("telegram", &ProtocolProfile{
		Name: "Telegram MTProto",
		// MTProto packet sizes - padding ensures length is multiple of 16
		MinSize:     12,                                                      // Quick ACK tokens 8-16 bytes
		MaxSize:     1024,                                                    // Max MTProto padding
		CommonSizes: []int{16, 32, 48, 64, 80, 96, 112, 128, 256, 512, 1024}, // Multiples of 16
		Timing: TimingProfile{
			// MTProto timing - fast messaging with variable gaps
			MinInterval: 10,    // Very fast for real-time messaging
			MaxInterval: 30000, // Long idle periods
			BurstProb:   0.40,  // High burst probability for message threads
			BurstMin:    3,
			BurstMax:    15,     // Rapid message exchanges in groups
			PauseProb:   0.25,   // Significant pause probability between conversations
			PauseMin:    1000,   // 1 second min pause
			PauseMax:    300000, // 5 minute max pause
			RTT:         40,     // Low RTT for Moscow DC
			Jitter:      15,
		},
		Headers: map[string]string{
			// Real Telegram Desktop User-Agent
			"User-Agent": "TDesktop/4.15.2 (Windows 10.0.22631; x64)",
			"Accept":     "*/*",
		},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("telegram"),
			JA4: fte.generateUniqueJA4Fingerprint("telegram"),
			// MTProto behavioral patterns
			Behavioral: BehavioralProfile{
				ThinkTime:         300 * time.Millisecond, // Fast typing response
				BurstPattern:      "interactive",          // Real-time messaging
				SessionLength:     12 * time.Hour,         // Long persistent sessions
				IdleTime:          45 * time.Second,       // Keep-alive interval
				HumanLikePatterns: true,
			},
			PacketSizePatterns: []int{16, 32, 64, 128, 256, 512, 1024}, // MTProto aligned
			TimingPatterns:     []int64{10, 50, 150, 500, 2000, 10000},
			EntropyProfile:     EntropyProfile{TargetEntropy: 0.99, EntropyVariance: 0.01, AntiEntropy: true},
		},
	})
}

func (fte *FTE) addWhatsAppProfile() {
	fte.addProfile("whatsapp", &ProtocolProfile{
		MinSize: 32, MaxSize: 8192, CommonSizes: []int{64, 128, 256, 512, 1024, 4096},
		Timing:  TimingProfile{MinInterval: 100, MaxInterval: 3000, BurstMin: 1, BurstMax: 5, PauseMin: 200, PauseMax: 10000, RTT: 80, Jitter: 15},
		Headers: map[string]string{"User-Agent": "WhatsApp/2.23.16.81 (Windows NT 10.0; Win64; x64)", "Accept": "*/*"},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("whatsapp"), JA4: fte.generateUniqueJA4Fingerprint("whatsapp"),
			Behavioral: BehavioralProfile{ThinkTime: 1 * time.Second, BurstPattern: "exponential", SessionLength: 3 * time.Hour, IdleTime: 1 * time.Minute},
		},
	})
}

func (fte *FTE) addInstagramProfile() {
	fte.addProfile("instagram", &ProtocolProfile{
		MinSize: 128, MaxSize: 16384, CommonSizes: []int{256, 512, 1024, 2048, 4096, 8192},
		Timing:  TimingProfile{MinInterval: 200, MaxInterval: 5000, BurstMin: 3, BurstMax: 15, PauseMin: 500, PauseMax: 15000, RTT: 100, Jitter: 20},
		Headers: map[string]string{"User-Agent": "Mozilla/5.0... Chrome/120.0.0.0", "X-Instagram-AJAX": "1"},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("instagram"), JA4: fte.generateUniqueJA4Fingerprint("instagram"),
			Behavioral: BehavioralProfile{ThinkTime: 2 * time.Second, BurstPattern: "exponential", SessionLength: 45 * time.Minute, IdleTime: 2 * time.Minute},
		},
	})
}

func (fte *FTE) addYouTubeProfile() {
	fte.addProfile("youtube", &ProtocolProfile{
		MinSize: 256, MaxSize: 32768, CommonSizes: []int{512, 1024, 2048, 4096, 8192, 16384},
		Timing:  TimingProfile{MinInterval: 100, MaxInterval: 2000, BurstMin: 5, BurstMax: 20, PauseMin: 1000, PauseMax: 5000, RTT: 60, Jitter: 12},
		Headers: map[string]string{"User-Agent": "Mozilla/5.0... Chrome/120.0.0.0", "X-YouTube-Client-Name": "1"},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("youtube"), JA4: fte.generateUniqueJA4Fingerprint("youtube"),
			Behavioral: BehavioralProfile{ThinkTime: 1 * time.Second, BurstPattern: "normal", SessionLength: 90 * time.Minute, IdleTime: 30 * time.Second},
		},
	})
}

// ========================================
// RUSSIAN MESSENGER PROFILES
// ========================================

func (fte *FTE) addRussianMessengerProfiles() {
	fte.addMaxProfile()
	fte.addVKMessengerProfile()
	fte.addTamTamProfile()
	fte.addYandexMessengerProfile()
}

func (fte *FTE) addMaxProfile() {
	fte.addProfile("max", &ProtocolProfile{
		Name:        "Max Messenger",
		MinSize:     32,
		MaxSize:     8192,
		CommonSizes: []int{64, 128, 256, 512, 1024, 2048},
		Timing: TimingProfile{
			MinInterval: 15,
			MaxInterval: 3000,
			BurstProb:   0.30,
			BurstMin:    2,
			BurstMax:    8,
			PauseProb:   0.10,
			PauseMin:    500,
			PauseMax:    5000,
			RTT:         30,
			Jitter:      10,
		},
		Headers: map[string]string{
			"User-Agent":   "Max/1.0.0 (Android 14; samsung SM-S918B; ru)",
			"X-Max-Client": "android",
		},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("max"),
			JA4: fte.generateUniqueJA4Fingerprint("max"),
			Behavioral: BehavioralProfile{
				ThinkTime:         400 * time.Millisecond,
				BurstPattern:      "typing",
				SessionLength:     6 * time.Hour,
				IdleTime:          45 * time.Second,
				HumanLikePatterns: true,
			},
		},
	})
}

func (fte *FTE) addVKMessengerProfile() {
	fte.addProfile("vk_messenger", &ProtocolProfile{
		Name:        "VK Messenger",
		MinSize:     24,
		MaxSize:     8192,
		CommonSizes: []int{64, 128, 256, 512, 1024},
		Timing: TimingProfile{
			MinInterval: 10,
			MaxInterval: 5000,
			BurstProb:   0.35,
			BurstMin:    2,
			BurstMax:    10,
			PauseProb:   0.12,
			PauseMin:    300,
			PauseMax:    3000,
			RTT:         25,
			Jitter:      8,
		},
		Headers: map[string]string{
			"User-Agent":  "VK Messenger/8.32 (Android 14; SDK 34; arm64-v8a)",
			"X-VK-Client": "messenger",
		},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("vk_messenger"),
			JA4: fte.generateUniqueJA4Fingerprint("vk_messenger"),
			Behavioral: BehavioralProfile{
				ThinkTime:         300 * time.Millisecond,
				BurstPattern:      "typing",
				SessionLength:     8 * time.Hour,
				IdleTime:          30 * time.Second,
				HumanLikePatterns: true,
			},
		},
	})
}

func (fte *FTE) addTamTamProfile() {
	fte.addProfile("tamtam", &ProtocolProfile{
		Name:        "TamTam Messenger",
		MinSize:     32,
		MaxSize:     4096,
		CommonSizes: []int{64, 128, 256, 512},
		Timing: TimingProfile{
			MinInterval: 50,
			MaxInterval: 3000,
			BurstProb:   0.25,
			BurstMin:    1,
			BurstMax:    6,
			PauseProb:   0.15,
			PauseMin:    400,
			PauseMax:    4000,
			RTT:         35,
			Jitter:      10,
		},
		Headers: map[string]string{
			"User-Agent":      "TamTam/3.12.0 (Android 14)",
			"X-TamTam-Client": "android",
		},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("tamtam"),
			JA4: fte.generateUniqueJA4Fingerprint("tamtam"),
			Behavioral: BehavioralProfile{
				ThinkTime:         500 * time.Millisecond,
				BurstPattern:      "conversational",
				SessionLength:     4 * time.Hour,
				IdleTime:          45 * time.Second,
				HumanLikePatterns: true,
			},
		},
	})
}

func (fte *FTE) addYandexMessengerProfile() {
	fte.addProfile("yandex_messenger", &ProtocolProfile{
		Name:        "Yandex Messenger",
		MinSize:     32,
		MaxSize:     6144,
		CommonSizes: []int{64, 128, 256, 512, 1024},
		Timing: TimingProfile{
			MinInterval: 20,
			MaxInterval: 4000,
			BurstProb:   0.28,
			BurstMin:    2,
			BurstMax:    8,
			PauseProb:   0.12,
			PauseMin:    350,
			PauseMax:    3500,
			RTT:         32,
			Jitter:      9,
		},
		Headers: map[string]string{
			"User-Agent":           "YandexMessenger/2.15.0 (Android 14)",
			"X-Yandex-Client-Type": "messenger-android",
		},
		Fingerprint: FingerprintProfile{
			JA3: fte.generateUniqueJA3Fingerprint("yandex_messenger"),
			JA4: fte.generateUniqueJA4Fingerprint("yandex_messenger"),
			Behavioral: BehavioralProfile{
				ThinkTime:         450 * time.Millisecond,
				BurstPattern:      "typing",
				SessionLength:     5 * time.Hour,
				IdleTime:          40 * time.Second,
				HumanLikePatterns: true,
			},
		},
	})
}
