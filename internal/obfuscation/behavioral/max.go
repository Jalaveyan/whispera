// Package behavioral - Max Messenger behavioral profile
package behavioral

import "time"

// MaxMessengerProfile returns a complete Max Messenger behavioral profile
// Max messenger - Russian messenger from VK team, launched 2024
func MaxMessengerProfile() *MessengerProfile {
	return &MessengerProfile{
		Name: "Max Messenger",

		// L3/L4 Transport
		Transport: TransportProfile{
			PreferredProtocol: "tcp",
			TCP: TCPFingerprint{
				OptionsOrder:         []string{"mss", "sack_permitted", "timestamps", "nop", "window_scale"},
				InitialWindowSize:    65535,
				MSS:                  1460,
				WindowScale:          7,
				SACKPermitted:        true,
				Timestamps:           true,
				KeepAliveInterval:    30 * time.Second,
				KeepAliveProbes:      9,
				RetransmitMinTimeout: 200 * time.Millisecond,
				RetransmitMaxTimeout: 120 * time.Second,
			},
			UDP: UDPProfile{
				PreferredSizes:     []int{512, 1024, 1400},
				PMTUDiscovery:      true,
				AllowFragmentation: false,
			},
		},

		// L5/L6 TLS
		TLS: TLSProfile{
			JA3: "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2",
			JA4: "t13d1517h2_max1e7e78f70_b0da82dd1658",

			ClientHello: ClientHelloProfile{
				CipherSuites: []uint16{
					0x1302, 0x1303, 0x1301,
					0xc02c, 0xc030, 0x009f,
					0xcca9, 0xcca8, 0xccaa,
					0xc02b, 0xc02f, 0x009e,
					0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067,
					0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033,
					0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
				},
				Extensions: []uint16{
					0x0000, 0x000b, 0x000a, 0x0023, 0x0016, 0x0017,
					0x000d, 0x002b, 0x002d, 0x0033,
				},
				SupportedGroups: []uint16{0x001d, 0x0017, 0x001e, 0x0019, 0x0018},
				SignatureAlgorithms: []uint16{
					0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
					0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
				},
				ALPN:              []string{"h2", "http/1.1"},
				SupportedVersions: []uint16{0x0304, 0x0303},
				KeyShareGroups:    []uint16{0x001d, 0x0017},
				PSKModes:          []uint8{0x01},
				ECHEnabled:        false,
				PaddingEnabled:    true,
				PaddingMin:        0,
				PaddingMax:        256,
			},
			SessionResumption: true,
			SessionTickets:    true,
			ZeroRTT:           false,
		},

		// L7 Application - Modern messenger
		Application: ApplicationProfile{
			Message: MessagePattern{
				// Russian text messages
				TextSizeDistribution:    Distribution{Type: "lognormal", Params: []float64{4.0, 0.8}},
				EmojiSize:               16,
				StickerSizeMin:          8000,
				StickerSizeMax:          35000,
				VoiceDurationMin:        1 * time.Second,
				VoiceDurationMax:        120 * time.Second,
				VoiceBitrate:            64000,
				TypingIndicatorInterval: 3 * time.Second,
				TypingTimeout:           5 * time.Second,
			},

			States: []ActivityState{
				{
					Name:             "idle",
					PacketsPerSecond: Distribution{Type: "exponential", Params: []float64{0.03}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{32, 128}},
					Duration:         Distribution{Type: "exponential", Params: []float64{0.0008}},
					Transitions:      map[string]float64{"idle": 0.6, "typing": 0.25, "receiving": 0.15},
				},
				{
					Name:             "typing",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{2.5, 0.8}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{48, 96}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.5, 0.7}},
					Transitions:      map[string]float64{"sending": 0.6, "idle": 0.3, "typing": 0.1},
				},
				{
					Name:             "sending",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{12.0, 4.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{5.0, 1.0}},
					Duration:         Distribution{Type: "uniform", Params: []float64{100, 1500}},
					Transitions:      map[string]float64{"idle": 0.5, "typing": 0.3, "receiving": 0.2},
				},
				{
					Name:             "receiving",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{8.0, 3.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{5.5, 1.2}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.0, 0.5}},
					Transitions:      map[string]float64{"idle": 0.5, "typing": 0.35, "receiving": 0.15},
				},
				{
					Name:             "voice_call",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{50.0, 10.0}}, // High frequency
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{200, 400}},    // OPUS frames
					Duration:         Distribution{Type: "lognormal", Params: []float64{9.0, 1.5}},  // Long calls
					Transitions:      map[string]float64{"idle": 0.95, "typing": 0.05},
				},
			},

			Bursts: BurstProfile{
				ThreadBurstSize:    Distribution{Type: "pareto", Params: []float64{3, 1.8}},
				ThreadBurstGap:     Distribution{Type: "lognormal", Params: []float64{5.8, 0.9}},
				ThreadCooldown:     Distribution{Type: "exponential", Params: []float64{0.0004}},
				MediaBurstPackets:  Distribution{Type: "uniform", Params: []float64{15, 60}},
				MediaBurstInterval: Distribution{Type: "uniform", Params: []float64{25, 70}},
				GroupReadBurst:     Distribution{Type: "pareto", Params: []float64{6, 2.2}},
				GroupReplyDelay:    Distribution{Type: "lognormal", Params: []float64{7.2, 1.0}},
			},

			Heartbeat: HeartbeatProfile{
				BackgroundInterval: 15 * time.Second,
				BackgroundJitter:   0.15,
				ActiveInterval:     3 * time.Second,
				ActiveJitter:       0.1,
				PowerSaveInterval:  3 * time.Minute,
			},

			ACK: ACKProfile{
				DelayedACKTimeout: 40 * time.Millisecond,
				CoalesceMax:       4,
				MessageACK:        ACKBehavior{ImmediateACK: false, DelayMs: 80, BatchSize: 6},
			},

			Media: MediaProfile{
				PhotoChunkSize:       65536,
				PhotoChunks:          Distribution{Type: "uniform", Params: []float64{8, 50}},
				PhotoUploadInterval:  Distribution{Type: "uniform", Params: []float64{20, 50}},
				VideoChunkSize:       524288,
				VideoBufferSegments:  3,
				VideoSegmentDuration: 4 * time.Second,
				FileChunkSize:        131072,
				FileChunkGap:         Distribution{Type: "uniform", Params: []float64{15, 40}},
			},
		},

		// Timing Model
		Timing: TimingModel{
			IPD: Distribution{Type: "lognormal", Params: []float64{4.0, 1.5}},

			Jitter: JitterModel{
				BaseJitter:    6.0,
				NetworkJitter: 18.0,
				AppJitter:     10.0,
				Distribution:  "gaussian",
			},

			DailyPattern: DailyActivityPattern{
				HourlyActivity: [24]float64{
					0.12, 0.06, 0.03, 0.02, 0.02, 0.05,
					0.12, 0.35, 0.65, 0.80, 0.85, 0.90,
					0.95, 1.0, 0.95, 0.88, 0.82, 0.80,
					0.88, 0.95, 1.0, 0.88, 0.60, 0.30,
				},
				WeekendModifier: 1.05,
				PeakHours:       []int{12, 13, 14, 19, 20, 21},
			},

			HumanNoise: HumanNoiseModel{
				ReadingTimePerChar:  45 * time.Millisecond,
				ThinkingTime:        Distribution{Type: "lognormal", Params: []float64{7.0, 1.0}},
				CorrectionRate:      0.12,
				DistractionRate:     0.06,
				DistractionDuration: Distribution{Type: "lognormal", Params: []float64{8.0, 0.8}},
				MultitaskingGaps:    Distribution{Type: "pareto", Params: []float64{4000, 2.0}},
			},

			NetworkResponse: NetworkResponseModel{
				RetryIntervals:    []time.Duration{80 * time.Millisecond, 200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second},
				BackoffMultiplier: 2.0,
				MaxRetries:        4,
				ReconnectDelay:    Distribution{Type: "uniform", Params: []float64{500, 2500}},
			},
		},

		// Context
		Context: ContextProfile{
			DNS: DNSProfile{
				Servers:    []string{"87.240.129.133", "93.186.225.208"},
				QueryTypes: []string{"A", "AAAA"},
				RespectTTL: true,
				DoHEnabled: false,
			},

			CDN: CDNProfile{
				Domains: []string{
					"max.ru",
					"api.max.ru",
					"cdn.max.ru",
					"media.max.ru",
				},
				ConnectionsPerDomain: 3,
				PrefetchEnabled:      true,
			},

			Push: PushProfile{
				Technology:        "fcm",
				HeartbeatInterval: 3 * time.Minute,
				WakeupPattern: WakeupPattern{
					Interval:         10 * time.Minute,
					Jitter:           0.2,
					PostWakeActivity: 5 * time.Second,
				},
			},

			Background: BackgroundProfile{
				ConnectionCount: 3,
				Connections: []BackgroundConnection{
					{Purpose: "longpoll", Interval: 15 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{64, 256}}},
					{Purpose: "sync", Interval: 30 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{32, 128}}},
					{Purpose: "presence", Interval: 20 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{24, 48}}},
				},
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
					NetworkSchedule:    10 * time.Minute,
					ReducedHeartbeat:   3 * time.Minute,
					BatchedRequests:    true,
					DeferrableInterval: 8 * time.Minute,
				},
			},

			App: AppProfile{
				Name:               "Max",
				Version:            "1.2.0",
				BuildNumber:        "1200",
				UserAgent:          "Max/1.2.0 (Android 14; SDK 34; arm64-v8a; samsung SM-S918B; ru)",
				ForegroundInterval: 3 * time.Second,
				BackgroundInterval: 15 * time.Second,
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
				SocketTimeout: 25 * time.Second,
				MaxIdleConns:  6,
				IdleTimeout:   60 * time.Second,
			},
		},
	}
}
