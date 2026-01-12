// Package behavioral - Telegram MTProto realistic profile
package behavioral

import "time"

// TelegramProfile returns a complete Telegram behavioral profile
// Based on real MTProto 2.0 traffic analysis
func TelegramProfile() *MessengerProfile {
	return &MessengerProfile{
		Name: "Telegram",

		// L3/L4 Transport
		Transport: TransportProfile{
			PreferredProtocol: "tcp", // MTProto over TCP preferred
			TCP: TCPFingerprint{
				// Android OkHttp/Netty stack fingerprint
				OptionsOrder:         []string{"mss", "sack_permitted", "timestamps", "nop", "window_scale"},
				InitialWindowSize:    65535,
				MSS:                  1460,
				WindowScale:          7,
				SACKPermitted:        true,
				Timestamps:           true,
				KeepAliveInterval:    75 * time.Second,
				KeepAliveProbes:      9,
				RetransmitMinTimeout: 200 * time.Millisecond,
				RetransmitMaxTimeout: 120 * time.Second,
			},
			UDP: UDPProfile{
				PreferredSizes:     []int{548, 1024, 1400},
				PMTUDiscovery:      true,
				AllowFragmentation: false,
			},
		},

		// L5/L6 TLS
		TLS: TLSProfile{
			// Real Telegram JA3 fingerprint
			JA3: "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2",
			JA4: "t13d1517h2_8daaf6152771_b0da82dd1658",

			ClientHello: ClientHelloProfile{
				// Telegram's cipher suite order
				CipherSuites: []uint16{
					0x1302, 0x1303, 0x1301, // TLS 1.3 ciphers
					0xc02c, 0xc030, 0x009f, // ECDHE
					0xcca9, 0xcca8, 0xccaa,
					0xc02b, 0xc02f, 0x009e,
					0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067,
					0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033,
					0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
				},
				// Extensions order matters!
				Extensions: []uint16{
					0x0000, // server_name
					0x000b, // ec_point_formats
					0x000a, // supported_groups
					0x0023, // session_ticket
					0x0016, // encrypt_then_mac
					0x0017, // extended_master_secret
					0x000d, // signature_algorithms
					0x002b, // supported_versions
					0x002d, // psk_key_exchange_modes
					0x0033, // key_share
				},
				SupportedGroups: []uint16{0x001d, 0x0017, 0x001e, 0x0019, 0x0018},
				SignatureAlgorithms: []uint16{
					0x0403, 0x0503, 0x0603, 0x0807,
					0x0808, 0x0809, 0x080a, 0x080b,
					0x0804, 0x0805, 0x0806, 0x0401,
					0x0501, 0x0601, 0x0303, 0x0301,
					0x0302, 0x0402, 0x0502, 0x0602,
				},
				ALPN:              []string{"h2", "http/1.1"},
				SupportedVersions: []uint16{0x0304, 0x0303}, // TLS 1.3, 1.2
				KeyShareGroups:    []uint16{0x001d, 0x0017},
				PSKModes:          []uint8{0x01},
				ECHEnabled:        false, // Telegram doesn't use ECH yet
				PaddingEnabled:    true,
				PaddingMin:        12,
				PaddingMax:        1024, // MTProto padding
			},
			SessionResumption: true,
			SessionTickets:    true,
			ZeroRTT:           false, // Telegram doesn't use 0-RTT
			MaxEarlyDataSize:  0,
		},

		// L7 Application
		Application: ApplicationProfile{
			Message: MessagePattern{
				// Text messages: typically 20-500 bytes, peak around 100
				TextSizeDistribution: Distribution{Type: "lognormal", Params: []float64{4.5, 0.8}}, // peaks ~90 bytes

				EmojiSize:      16, // UTF-8 emoji
				StickerSizeMin: 10000,
				StickerSizeMax: 50000,

				VoiceDurationMin: 1 * time.Second,
				VoiceDurationMax: 60 * time.Second,
				VoiceBitrate:     64000, // OPUS

				TypingIndicatorInterval: 5 * time.Second,
				TypingTimeout:           6 * time.Second,
			},

			States: []ActivityState{
				{
					Name:             "idle",
					PacketsPerSecond: Distribution{Type: "exponential", Params: []float64{0.033}}, // ~1 packet per 30 sec
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{16, 64}},    // Keep-alive
					Duration:         Distribution{Type: "exponential", Params: []float64{0.001}}, // Average 1000 sec
					Transitions: map[string]float64{
						"idle":      0.7,
						"receiving": 0.2,
						"typing":    0.1,
					},
				},
				{
					Name:             "typing",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{2.0, 0.5}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{32, 64}},     // Typing indicators
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.5, 0.8}}, // 5-30 sec typing
					Transitions: map[string]float64{
						"typing":  0.3,
						"sending": 0.5,
						"idle":    0.2,
					},
				},
				{
					Name:             "sending",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{10.0, 3.0}}, // Burst
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{5.0, 1.0}}, // Variable message sizes
					Duration:         Distribution{Type: "uniform", Params: []float64{100, 2000}},  // Quick send
					Transitions: map[string]float64{
						"idle":        0.4,
						"waiting_ack": 0.5,
						"typing":      0.1,
					},
				},
				{
					Name:             "waiting_ack",
					PacketsPerSecond: Distribution{Type: "uniform", Params: []float64{0.5, 2.0}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{16, 64}},
					Duration:         Distribution{Type: "uniform", Params: []float64{50, 500}},
					Transitions: map[string]float64{
						"idle":      0.6,
						"receiving": 0.3,
						"typing":    0.1,
					},
				},
				{
					Name:             "receiving",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{5.0, 2.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{5.5, 1.2}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.0, 0.5}},
					Transitions: map[string]float64{
						"idle":      0.5,
						"typing":    0.3,
						"receiving": 0.2,
					},
				},
			},

			Bursts: BurstProfile{
				// Rapid message exchange in conversation
				ThreadBurstSize: Distribution{Type: "pareto", Params: []float64{2, 1.5}},      // 2-10 messages
				ThreadBurstGap:  Distribution{Type: "lognormal", Params: []float64{6.0, 1.0}}, // 100ms-2s between
				ThreadCooldown:  Distribution{Type: "exponential", Params: []float64{0.0005}}, // avg 2000s cooldown

				MediaBurstPackets:  Distribution{Type: "uniform", Params: []float64{10, 50}},
				MediaBurstInterval: Distribution{Type: "uniform", Params: []float64{20, 100}},

				GroupReadBurst:  Distribution{Type: "pareto", Params: []float64{5, 2.0}},
				GroupReplyDelay: Distribution{Type: "lognormal", Params: []float64{8.0, 1.5}}, // 5-60 sec reading
			},

			Heartbeat: HeartbeatProfile{
				BackgroundInterval: 30 * time.Second,
				BackgroundJitter:   0.2,
				ActiveInterval:     5 * time.Second,
				ActiveJitter:       0.1,
				PowerSaveInterval:  5 * time.Minute,
			},

			ACK: ACKProfile{
				DelayedACKTimeout: 40 * time.Millisecond,
				CoalesceMax:       3,
				MessageACK: ACKBehavior{
					ImmediateACK: false,
					DelayMs:      100,
					BatchSize:    5,
				},
			},

			Media: MediaProfile{
				PhotoChunkSize:      32768, // 32KB chunks
				PhotoChunks:         Distribution{Type: "uniform", Params: []float64{10, 100}},
				PhotoUploadInterval: Distribution{Type: "uniform", Params: []float64{20, 50}},

				VideoChunkSize:       524288, // 512KB
				VideoBufferSegments:  3,
				VideoSegmentDuration: 4 * time.Second,

				FileChunkSize: 131072, // 128KB
				FileChunkGap:  Distribution{Type: "uniform", Params: []float64{10, 30}},
			},
		},

		// Timing Model
		Timing: TimingModel{
			IPD: Distribution{Type: "lognormal", Params: []float64{4.0, 1.5}}, // Variable delays

			Jitter: JitterModel{
				BaseJitter:    5.0, // 5ms
				NetworkJitter: 15.0,
				AppJitter:     10.0,
				Distribution:  "gaussian",
			},

			DailyPattern: DailyActivityPattern{
				// Moscow timezone typical usage
				HourlyActivity: [24]float64{
					0.2, 0.1, 0.05, 0.03, 0.02, 0.05, // 00-05 low
					0.15, 0.4, 0.7, 0.8, 0.85, 0.9, // 06-11 morning rise
					0.95, 1.0, 0.95, 0.9, 0.85, 0.8, // 12-17 peak
					0.85, 0.9, 0.95, 0.85, 0.6, 0.4, // 18-23 evening
				},
				WeekendModifier: 0.8,
				PeakHours:       []int{12, 13, 14, 19, 20, 21},
			},

			HumanNoise: HumanNoiseModel{
				ReadingTimePerChar:  50 * time.Millisecond,
				ThinkingTime:        Distribution{Type: "lognormal", Params: []float64{7.5, 1.2}}, // 1-30 sec
				CorrectionRate:      0.15,                                                         // 15% typo-correction
				DistractionRate:     0.05,                                                         // 5% get distracted
				DistractionDuration: Distribution{Type: "exponential", Params: []float64{0.0001}}, // avg 10 sec
				MultitaskingGaps:    Distribution{Type: "pareto", Params: []float64{5000, 2.0}},
			},

			NetworkResponse: NetworkResponseModel{
				RetryIntervals:    []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second},
				BackoffMultiplier: 2.0,
				MaxRetries:        5,
				ReconnectDelay:    Distribution{Type: "uniform", Params: []float64{1000, 5000}},
			},
		},

		// Context & Ecosystem
		Context: ContextProfile{
			DNS: DNSProfile{
				Servers:    []string{"149.154.167.50", "149.154.167.51"}, // Telegram DC DNS
				QueryTypes: []string{"A", "AAAA"},
				RespectTTL: true,
				DoHEnabled: false,
			},

			CDN: CDNProfile{
				Domains: []string{
					"telegram.org",
					"t.me",
					"cdn4.telesco.pe",
					"cdn5.telesco.pe",
					"telegram-cdn.org",
				},
				ConnectionsPerDomain: 2,
				PrefetchEnabled:      true,
			},

			Push: PushProfile{
				Technology:        "fcm", // Android
				HeartbeatInterval: 4 * time.Minute,
				WakeupPattern: WakeupPattern{
					Interval:         15 * time.Minute,
					Jitter:           0.2,
					PostWakeActivity: 5 * time.Second,
				},
			},

			Background: BackgroundProfile{
				ConnectionCount: 3,
				Connections: []BackgroundConnection{
					{Purpose: "api", Interval: 30 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{16, 64}}},
					{Purpose: "events", Interval: 5 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{32, 128}}},
					{Purpose: "presence", Interval: 60 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{16, 32}}},
				},
			},

			Endpoints: []EndpointProfile{
				{Path: "/api/v1/getUpdates", Method: "POST", RequestSize: Distribution{Type: "uniform", Params: []float64{64, 256}}, ResponseSize: Distribution{Type: "lognormal", Params: []float64{6, 2}}, CallFrequency: Distribution{Type: "uniform", Params: []float64{100, 500}}},
				{Path: "/api/v1/sendMessage", Method: "POST", RequestSize: Distribution{Type: "lognormal", Params: []float64{5, 1}}, ResponseSize: Distribution{Type: "uniform", Params: []float64{128, 512}}, CallFrequency: Distribution{Type: "exponential", Params: []float64{0.01}}},
			},
		},

		// Client Profile
		Client: ClientProfile{
			OS: OSProfile{
				Name:             "Android",
				Version:          "14",
				Build:            "UP1A.231005.007",
				SocketBufferSize: 212992,
				PowerSaveMode:    "normal",
				PowerSaveBehavior: PowerSaveBehavior{
					NetworkSchedule:    15 * time.Minute,
					ReducedHeartbeat:   5 * time.Minute,
					BatchedRequests:    true,
					DeferrableInterval: 10 * time.Minute,
				},
			},

			App: AppProfile{
				Name:               "Telegram",
				Version:            "10.8.3",
				BuildNumber:        "41832",
				UserAgent:          "Telegram/10.8.3 (Android 14; SDK 34; arm64-v8a; samsung SM-S918B; ru)",
				ForegroundInterval: 5 * time.Second,
				BackgroundInterval: 30 * time.Second,
			},

			Device: DeviceProfile{
				Manufacturer:    "samsung",
				Model:           "SM-S918B",
				ScreenDensity:   3.0,
				CellularCapable: true,
				WiFiPreferred:   true,
				IPv6Supported:   true,
			},

			Network: ClientNetworkProfile{
				TCPNoDelay:    true,
				TCPQuickACK:   true,
				SocketTimeout: 30 * time.Second,
				MaxIdleConns:  5,
				IdleTimeout:   90 * time.Second,
			},
		},
	}
}
