// Package behavioral - VK Messenger realistic profile
package behavioral

import "time"

// VKMessengerProfile returns a complete VK Messenger behavioral profile
// Based on real VK Android app traffic analysis
func VKMessengerProfile() *MessengerProfile {
	return &MessengerProfile{
		Name: "VK Messenger",

		// L3/L4 Transport
		Transport: TransportProfile{
			PreferredProtocol: "tcp",
			TCP: TCPFingerprint{
				// OkHttp Android stack fingerprint
				OptionsOrder:         []string{"mss", "sack_permitted", "timestamps", "nop", "window_scale"},
				InitialWindowSize:    65535,
				MSS:                  1460,
				WindowScale:          8,
				SACKPermitted:        true,
				Timestamps:           true,
				KeepAliveInterval:    60 * time.Second,
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
			// VK Android OkHttp-based JA3
			JA3: "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2",
			JA4: "t13d1517h2_e8f1e7e78f70_6ce26a12b3cc",

			ClientHello: ClientHelloProfile{
				CipherSuites: []uint16{
					0x1302, 0x1303, 0x1301,
					0xc02c, 0xc030, 0x009f,
					0xcca9, 0xcca8, 0xccaa,
					0xc02b, 0xc02f, 0x009e,
					0xc024, 0xc028, 0x006b,
					0xc023, 0xc027, 0x0067,
					0xc00a, 0xc014, 0x0039,
					0xc009, 0xc013, 0x0033,
					0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
				},
				Extensions: []uint16{
					0x0000, 0x000b, 0x000a, 0x0023, 0x0016, 0x0017,
					0x000d, 0x002b, 0x002d, 0x0033, 0x0015, // includes "padding"
				},
				SupportedGroups: []uint16{0x001d, 0x0017, 0x001e, 0x0019, 0x0018},
				SignatureAlgorithms: []uint16{
					0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b,
					0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
				},
				ALPN:              []string{"h2", "http/1.1"},
				SupportedVersions: []uint16{0x0304, 0x0303, 0x0302},
				KeyShareGroups:    []uint16{0x001d, 0x0017},
				PSKModes:          []uint8{0x01},
				ECHEnabled:        false,
				PaddingEnabled:    true,
				PaddingMin:        0,
				PaddingMax:        512,
			},
			SessionResumption: true,
			SessionTickets:    true,
			ZeroRTT:           false,
		},

		// L7 Application
		Application: ApplicationProfile{
			Message: MessagePattern{
				// Russian text tends to be shorter
				TextSizeDistribution:    Distribution{Type: "lognormal", Params: []float64{4.2, 0.9}},
				EmojiSize:               16,
				StickerSizeMin:          8000,
				StickerSizeMax:          40000,
				VoiceDurationMin:        2 * time.Second,
				VoiceDurationMax:        120 * time.Second,
				VoiceBitrate:            48000,
				TypingIndicatorInterval: 3 * time.Second,
				TypingTimeout:           5 * time.Second,
			},

			States: []ActivityState{
				{
					Name:             "idle",
					PacketsPerSecond: Distribution{Type: "exponential", Params: []float64{0.025}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{32, 128}},
					Duration:         Distribution{Type: "exponential", Params: []float64{0.0008}},
					Transitions:      map[string]float64{"idle": 0.6, "feed_scroll": 0.25, "typing": 0.15},
				},
				{
					Name:             "feed_scroll",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{8.0, 2.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{7.0, 1.2}}, // Images, videos loading
					Duration:         Distribution{Type: "lognormal", Params: []float64{3.5, 0.8}},
					Transitions:      map[string]float64{"idle": 0.3, "feed_scroll": 0.4, "content_view": 0.2, "typing": 0.1},
				},
				{
					Name:             "content_view",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{3.0, 1.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{8.0, 1.5}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.5, 1.0}},
					Transitions:      map[string]float64{"feed_scroll": 0.5, "idle": 0.3, "typing": 0.2},
				},
				{
					Name:             "typing",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{2.5, 0.8}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{48, 96}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.8, 0.7}},
					Transitions:      map[string]float64{"sending": 0.6, "idle": 0.3, "typing": 0.1},
				},
				{
					Name:             "sending",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{12.0, 4.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{5.5, 1.2}},
					Duration:         Distribution{Type: "uniform", Params: []float64{200, 1500}},
					Transitions:      map[string]float64{"idle": 0.5, "feed_scroll": 0.3, "typing": 0.2},
				},
			},

			Bursts: BurstProfile{
				ThreadBurstSize:    Distribution{Type: "pareto", Params: []float64{3, 1.8}},
				ThreadBurstGap:     Distribution{Type: "lognormal", Params: []float64{5.5, 0.9}},
				ThreadCooldown:     Distribution{Type: "exponential", Params: []float64{0.0003}},
				MediaBurstPackets:  Distribution{Type: "uniform", Params: []float64{15, 80}},
				MediaBurstInterval: Distribution{Type: "uniform", Params: []float64{30, 80}},
				GroupReadBurst:     Distribution{Type: "pareto", Params: []float64{8, 2.5}},
				GroupReplyDelay:    Distribution{Type: "lognormal", Params: []float64{7.5, 1.2}},
			},

			Heartbeat: HeartbeatProfile{
				BackgroundInterval: 25 * time.Second,
				BackgroundJitter:   0.15,
				ActiveInterval:     3 * time.Second,
				ActiveJitter:       0.1,
				PowerSaveInterval:  3 * time.Minute,
			},

			ACK: ACKProfile{
				DelayedACKTimeout: 50 * time.Millisecond,
				CoalesceMax:       5,
				MessageACK:        ACKBehavior{ImmediateACK: false, DelayMs: 80, BatchSize: 8},
			},

			Media: MediaProfile{
				PhotoChunkSize:       65536,
				PhotoChunks:          Distribution{Type: "uniform", Params: []float64{5, 50}},
				PhotoUploadInterval:  Distribution{Type: "uniform", Params: []float64{15, 40}},
				VideoChunkSize:       1048576,
				VideoBufferSegments:  4,
				VideoSegmentDuration: 6 * time.Second,
				FileChunkSize:        262144,
				FileChunkGap:         Distribution{Type: "uniform", Params: []float64{15, 35}},
			},
		},

		// Timing Model
		Timing: TimingModel{
			IPD: Distribution{Type: "lognormal", Params: []float64{3.8, 1.6}},

			Jitter: JitterModel{
				BaseJitter:    8.0,
				NetworkJitter: 20.0,
				AppJitter:     12.0,
				Distribution:  "gaussian",
			},

			DailyPattern: DailyActivityPattern{
				HourlyActivity: [24]float64{
					0.15, 0.08, 0.04, 0.02, 0.02, 0.05,
					0.12, 0.35, 0.65, 0.80, 0.85, 0.90,
					0.95, 1.0, 0.95, 0.90, 0.85, 0.80,
					0.85, 0.95, 1.0, 0.90, 0.65, 0.35,
				},
				WeekendModifier: 1.1, // More active on weekends
				PeakHours:       []int{13, 14, 19, 20, 21, 22},
			},

			HumanNoise: HumanNoiseModel{
				ReadingTimePerChar:  45 * time.Millisecond, // Russian text slightly faster
				ThinkingTime:        Distribution{Type: "lognormal", Params: []float64{7.0, 1.0}},
				CorrectionRate:      0.12,
				DistractionRate:     0.08, // VK has more distractions (stories, clips)
				DistractionDuration: Distribution{Type: "lognormal", Params: []float64{8.5, 0.8}},
				MultitaskingGaps:    Distribution{Type: "pareto", Params: []float64{3000, 1.8}},
			},

			NetworkResponse: NetworkResponseModel{
				RetryIntervals:    []time.Duration{50 * time.Millisecond, 150 * time.Millisecond, 400 * time.Millisecond, 1 * time.Second},
				BackoffMultiplier: 1.8,
				MaxRetries:        4,
				ReconnectDelay:    Distribution{Type: "uniform", Params: []float64{500, 3000}},
			},
		},

		// Context & Ecosystem
		Context: ContextProfile{
			DNS: DNSProfile{
				Servers:    []string{"87.240.129.133", "93.186.225.208"}, // VK DNS
				QueryTypes: []string{"A", "AAAA", "HTTPS"},
				RespectTTL: true,
				DoHEnabled: false,
			},

			CDN: CDNProfile{
				Domains: []string{
					"vk.com",
					"api.vk.com",
					"st.vk.com",
					"sun1-95.userapi.com",
					"sun9-west.userapi.com",
					"pp.userapi.com",
					"vkvideo.ru",
				},
				ConnectionsPerDomain: 4,
				PrefetchEnabled:      true,
			},

			Push: PushProfile{
				Technology:        "fcm",
				HeartbeatInterval: 3 * time.Minute,
				WakeupPattern: WakeupPattern{
					Interval:         10 * time.Minute,
					Jitter:           0.25,
					PostWakeActivity: 8 * time.Second,
				},
			},

			Background: BackgroundProfile{
				ConnectionCount: 4,
				Connections: []BackgroundConnection{
					{Purpose: "longpoll", Interval: 25 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{64, 256}}},
					{Purpose: "api", Interval: 15 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{32, 128}}},
					{Purpose: "presence", Interval: 30 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{24, 48}}},
					{Purpose: "stats", Interval: 60 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{128, 512}}},
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
					NetworkSchedule:    10 * time.Minute,
					ReducedHeartbeat:   3 * time.Minute,
					BatchedRequests:    true,
					DeferrableInterval: 8 * time.Minute,
				},
			},

			App: AppProfile{
				Name:               "VK",
				Version:            "8.72",
				BuildNumber:        "19234",
				UserAgent:          "VKAndroidApp/8.72-19234 (Android 14; SDK 34; arm64-v8a; samsung SM-S918B; ru)",
				ForegroundInterval: 3 * time.Second,
				BackgroundInterval: 25 * time.Second,
			},

			Device: DeviceProfile{
				Manufacturer:    "samsung",
				Model:           "SM-S918B", // Galaxy S23 Ultra
				ScreenDensity:   3.0,
				CellularCapable: true,
				WiFiPreferred:   true,
				IPv6Supported:   true,
			},

			Network: ClientNetworkProfile{
				TCPNoDelay:    true,
				TCPQuickACK:   true,
				SocketTimeout: 25 * time.Second,
				MaxIdleConns:  8,
				IdleTimeout:   60 * time.Second,
			},
		},
	}
}

// VKVideoProfile returns VK Video specific behavioral profile
func VKVideoProfile() *MessengerProfile {
	profile := VKMessengerProfile()
	profile.Name = "VK Video"

	// Override for video streaming behavior
	profile.Application.States = []ActivityState{
		{
			Name:             "buffering",
			PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{50.0, 15.0}}, // High burst
			PacketSizes:      Distribution{Type: "lognormal", Params: []float64{10.0, 0.5}}, // Large chunks
			Duration:         Distribution{Type: "uniform", Params: []float64{500, 3000}},
			Transitions:      map[string]float64{"playing": 0.95, "buffering": 0.05},
		},
		{
			Name:             "playing",
			PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{15.0, 5.0}},  // Steady stream
			PacketSizes:      Distribution{Type: "uniform", Params: []float64{4096, 65536}}, // Segment sizes
			Duration:         Distribution{Type: "lognormal", Params: []float64{8.0, 1.0}},  // 30 sec - 5 min
			Transitions:      map[string]float64{"playing": 0.7, "buffering": 0.1, "paused": 0.15, "seeking": 0.05},
		},
		{
			Name:             "paused",
			PacketsPerSecond: Distribution{Type: "exponential", Params: []float64{0.1}}, // Low activity
			PacketSizes:      Distribution{Type: "uniform", Params: []float64{64, 256}},
			Duration:         Distribution{Type: "lognormal", Params: []float64{7.0, 1.5}},
			Transitions:      map[string]float64{"playing": 0.7, "idle": 0.3},
		},
		{
			Name:             "seeking",
			PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{30.0, 10.0}}, // Burst on seek
			PacketSizes:      Distribution{Type: "lognormal", Params: []float64{9.0, 0.8}},
			Duration:         Distribution{Type: "uniform", Params: []float64{200, 1500}},
			Transitions:      map[string]float64{"buffering": 0.8, "playing": 0.2},
		},
	}

	profile.Application.Media = MediaProfile{
		VideoChunkSize:       1048576, // 1MB chunks
		VideoBufferSegments:  5,
		VideoSegmentDuration: 4 * time.Second,
	}

	return profile
}
