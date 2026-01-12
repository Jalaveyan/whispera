// Package behavioral - WeChat behavioral profile
package behavioral

import "time"

// WeChatProfile returns a complete WeChat behavioral profile
// Based on WeChat Android app traffic analysis
func WeChatProfile() *MessengerProfile {
	return &MessengerProfile{
		Name: "WeChat",

		// L3/L4 Transport
		Transport: TransportProfile{
			PreferredProtocol: "tcp",
			TCP: TCPFingerprint{
				// Tencent MMTLS stack
				OptionsOrder:         []string{"mss", "sack_permitted", "timestamps", "nop", "window_scale"},
				InitialWindowSize:    65535,
				MSS:                  1460,
				WindowScale:          6,
				SACKPermitted:        true,
				Timestamps:           true,
				KeepAliveInterval:    60 * time.Second,
				KeepAliveProbes:      9,
				RetransmitMinTimeout: 200 * time.Millisecond,
				RetransmitMaxTimeout: 120 * time.Second,
			},
			UDP: UDPProfile{
				PreferredSizes:     []int{512, 1024, 1200},
				PMTUDiscovery:      true,
				AllowFragmentation: false,
			},
		},

		// L5/L6 TLS - Tencent MMTLS (modified TLS)
		TLS: TLSProfile{
			// WeChat uses MMTLS - modified TLS 1.3
			JA3: "771,4866-4867-4865-49196-49200-159-52393-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2",
			JA4: "t13d1516h2_wechat7e78f70_mmtls2dd1658",

			ClientHello: ClientHelloProfile{
				CipherSuites: []uint16{
					0x1302, 0x1303, 0x1301, // TLS 1.3
					0xc02c, 0xc030, 0x009f,
					0xcca9, 0xc02b, 0xc02f, 0x009e,
					0xc024, 0xc028, 0x006b,
					0xc023, 0xc027, 0x0067,
					0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033,
					0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
				},
				Extensions: []uint16{
					0x0000, 0x000b, 0x000a, 0x0023, 0x0016, 0x0017,
					0x000d, 0x002b, 0x002d, 0x0033,
				},
				SupportedGroups: []uint16{0x001d, 0x0017, 0x0019, 0x0018},
				SignatureAlgorithms: []uint16{
					0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
					0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
				},
				ALPN:              []string{"mmtls", "http/1.1"}, // WeChat uses MMTLS ALPN
				SupportedVersions: []uint16{0x0304, 0x0303},
				KeyShareGroups:    []uint16{0x001d, 0x0017},
				PSKModes:          []uint8{0x01},
				ECHEnabled:        false,
				PaddingEnabled:    false, // MMTLS has its own padding
			},
			SessionResumption: true,
			SessionTickets:    true,
			ZeroRTT:           true, // MMTLS supports 0-RTT
		},

		// L7 Application - Super app with many features
		Application: ApplicationProfile{
			Message: MessagePattern{
				// Chinese text - compact
				TextSizeDistribution:    Distribution{Type: "lognormal", Params: []float64{4.5, 0.9}},
				EmojiSize:               16,
				StickerSizeMin:          10000,
				StickerSizeMax:          50000,
				VoiceDurationMin:        1 * time.Second,
				VoiceDurationMax:        60 * time.Second,
				VoiceBitrate:            48000,
				TypingIndicatorInterval: 5 * time.Second,
				TypingTimeout:           8 * time.Second,
			},

			States: []ActivityState{
				{
					Name:             "idle",
					PacketsPerSecond: Distribution{Type: "exponential", Params: []float64{0.02}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{32, 128}},
					Duration:         Distribution{Type: "exponential", Params: []float64{0.0006}},
					Transitions:      map[string]float64{"idle": 0.55, "typing": 0.2, "moments": 0.15, "receiving": 0.1},
				},
				{
					Name:             "typing",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{3.0, 1.0}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{64, 128}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.8, 0.8}},
					Transitions:      map[string]float64{"sending": 0.55, "idle": 0.3, "typing": 0.15},
				},
				{
					Name:             "sending",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{15.0, 5.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{5.5, 1.2}},
					Duration:         Distribution{Type: "uniform", Params: []float64{150, 2000}},
					Transitions:      map[string]float64{"idle": 0.45, "typing": 0.35, "receiving": 0.2},
				},
				{
					Name:             "receiving",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{10.0, 4.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{6.0, 1.3}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.5, 0.6}},
					Transitions:      map[string]float64{"idle": 0.45, "typing": 0.4, "receiving": 0.15},
				},
				{
					Name:             "moments",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{12.0, 4.0}}, // Photo viewing
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{8.5, 1.5}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{4.0, 1.0}},
					Transitions:      map[string]float64{"idle": 0.4, "moments": 0.4, "typing": 0.2},
				},
				{
					Name:             "mini_program",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{25.0, 10.0}}, // Heavy app usage
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{7.5, 1.5}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{5.0, 1.5}},
					Transitions:      map[string]float64{"idle": 0.6, "mini_program": 0.3, "moments": 0.1},
				},
				{
					Name:             "voice_call",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{50.0, 10.0}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{180, 320}}, // SILK codec
					Duration:         Distribution{Type: "lognormal", Params: []float64{8.5, 1.5}},
					Transitions:      map[string]float64{"idle": 0.95, "typing": 0.05},
				},
			},

			Bursts: BurstProfile{
				ThreadBurstSize:    Distribution{Type: "pareto", Params: []float64{3, 2.0}},
				ThreadBurstGap:     Distribution{Type: "lognormal", Params: []float64{5.5, 0.8}},
				ThreadCooldown:     Distribution{Type: "exponential", Params: []float64{0.0003}},
				MediaBurstPackets:  Distribution{Type: "uniform", Params: []float64{20, 80}},
				MediaBurstInterval: Distribution{Type: "uniform", Params: []float64{20, 60}},
				GroupReadBurst:     Distribution{Type: "pareto", Params: []float64{10, 2.5}}, // Large groups
				GroupReplyDelay:    Distribution{Type: "lognormal", Params: []float64{7.5, 1.2}},
			},

			Heartbeat: HeartbeatProfile{
				BackgroundInterval: 30 * time.Second,
				BackgroundJitter:   0.2,
				ActiveInterval:     5 * time.Second,
				ActiveJitter:       0.1,
				PowerSaveInterval:  5 * time.Minute,
			},

			ACK: ACKProfile{
				DelayedACKTimeout: 50 * time.Millisecond,
				CoalesceMax:       5,
				MessageACK:        ACKBehavior{ImmediateACK: false, DelayMs: 100, BatchSize: 8},
			},

			Media: MediaProfile{
				PhotoChunkSize:       65536,
				PhotoChunks:          Distribution{Type: "uniform", Params: []float64{10, 60}},
				PhotoUploadInterval:  Distribution{Type: "uniform", Params: []float64{25, 60}},
				VideoChunkSize:       524288,
				VideoBufferSegments:  4,
				VideoSegmentDuration: 5 * time.Second,
				FileChunkSize:        131072,
				FileChunkGap:         Distribution{Type: "uniform", Params: []float64{20, 50}},
			},
		},

		// Timing Model
		Timing: TimingModel{
			IPD: Distribution{Type: "lognormal", Params: []float64{4.2, 1.6}},

			Jitter: JitterModel{
				BaseJitter:    8.0,
				NetworkJitter: 30.0, // Higher RTT to China
				AppJitter:     12.0,
				Distribution:  "gaussian",
			},

			DailyPattern: DailyActivityPattern{
				// China timezone (UTC+8) pattern
				HourlyActivity: [24]float64{
					0.25, 0.15, 0.08, 0.05, 0.03, 0.05, // 00-05
					0.10, 0.30, 0.60, 0.80, 0.90, 0.95, // 06-11
					1.0, 0.98, 0.95, 0.90, 0.88, 0.85, // 12-17
					0.90, 0.95, 1.0, 0.95, 0.70, 0.45, // 18-23
				},
				WeekendModifier: 1.1,
				PeakHours:       []int{12, 13, 19, 20, 21, 22},
			},

			HumanNoise: HumanNoiseModel{
				ReadingTimePerChar:  80 * time.Millisecond, // Chinese is denser
				ThinkingTime:        Distribution{Type: "lognormal", Params: []float64{7.2, 1.0}},
				CorrectionRate:      0.08, // IME auto-correct
				DistractionRate:     0.10, // Super app - many distractions
				DistractionDuration: Distribution{Type: "lognormal", Params: []float64{8.5, 1.0}},
				MultitaskingGaps:    Distribution{Type: "pareto", Params: []float64{3000, 1.8}},
			},

			NetworkResponse: NetworkResponseModel{
				RetryIntervals:    []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, 800 * time.Millisecond, 2 * time.Second, 5 * time.Second},
				BackoffMultiplier: 2.0,
				MaxRetries:        5,
				ReconnectDelay:    Distribution{Type: "uniform", Params: []float64{1000, 5000}},
			},
		},

		// Context - Tencent infrastructure
		Context: ContextProfile{
			DNS: DNSProfile{
				Servers:    []string{"119.29.29.29", "182.254.116.116"}, // Tencent DNS
				QueryTypes: []string{"A", "AAAA"},
				RespectTTL: true,
				DoHEnabled: false,
			},

			CDN: CDNProfile{
				Domains: []string{
					"wx.qq.com",
					"weixin.qq.com",
					"szlong.weixin.qq.com",
					"szshort.weixin.qq.com",
					"mmtls.weixin.qq.com",
					"dns.weixin.qq.com",
					"cdn.weixin.qq.com",
				},
				ConnectionsPerDomain: 4,
				PrefetchEnabled:      true,
			},

			Push: PushProfile{
				Technology:        "websocket", // WeChat uses long-poll/websocket
				HeartbeatInterval: 5 * time.Minute,
				WakeupPattern: WakeupPattern{
					Interval:         15 * time.Minute,
					Jitter:           0.2,
					PostWakeActivity: 8 * time.Second,
				},
			},

			Background: BackgroundProfile{
				ConnectionCount: 4,
				Connections: []BackgroundConnection{
					{Purpose: "mmtls_long", Interval: 30 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{32, 128}}},
					{Purpose: "sync", Interval: 60 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{64, 256}}},
					{Purpose: "dns_resolve", Interval: 300 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{48, 96}}},
					{Purpose: "voip_register", Interval: 120 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{128, 256}}},
				},
			},
		},

		// Client Profile
		Client: ClientProfile{
			OS: OSProfile{
				Name:             "Android",
				Version:          "14",
				Build:            "UP1A.231005.007",
				SocketBufferSize: 262144,
				PowerSaveMode:    "normal",
				PowerSaveBehavior: PowerSaveBehavior{
					NetworkSchedule:    15 * time.Minute,
					ReducedHeartbeat:   5 * time.Minute,
					BatchedRequests:    true,
					DeferrableInterval: 10 * time.Minute,
				},
			},

			App: AppProfile{
				Name:               "WeChat",
				Version:            "8.0.44",
				BuildNumber:        "2360",
				UserAgent:          "MicroMessenger/8.0.44.2360(0x2800002C) NetType/WIFI Language/zh_CN ABI/arm64",
				ForegroundInterval: 5 * time.Second,
				BackgroundInterval: 30 * time.Second,
			},

			Device: DeviceProfile{
				Manufacturer:    "Huawei",
				Model:           "P60 Pro",
				ScreenDensity:   3.0,
				CellularCapable: true,
				WiFiPreferred:   true,
				IPv6Supported:   true,
			},

			Network: ClientNetworkProfile{
				TCPNoDelay:    true,
				TCPQuickACK:   true,
				SocketTimeout: 30 * time.Second,
				MaxIdleConns:  8,
				IdleTimeout:   120 * time.Second,
			},
		},
	}
}
