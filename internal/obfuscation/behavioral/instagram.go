// Package behavioral - Instagram behavioral profile
package behavioral

import "time"

// InstagramProfile returns a complete Instagram behavioral profile
// Based on Instagram Android app traffic analysis
func InstagramProfile() *MessengerProfile {
	return &MessengerProfile{
		Name: "Instagram",

		// L3/L4 Transport
		Transport: TransportProfile{
			PreferredProtocol: "tcp",
			TCP: TCPFingerprint{
				OptionsOrder:         []string{"mss", "sack_permitted", "timestamps", "nop", "window_scale"},
				InitialWindowSize:    65535,
				MSS:                  1460,
				WindowScale:          8,
				SACKPermitted:        true,
				Timestamps:           true,
				KeepAliveInterval:    45 * time.Second,
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

		// L5/L6 TLS - Facebook/Meta stack
		TLS: TLSProfile{
			JA3: "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2",
			JA4: "t13d1517h2_e8f1e7e78f70_fb4c3a2b1d9e",

			ClientHello: ClientHelloProfile{
				CipherSuites: []uint16{
					0x1302, 0x1303, 0x1301,
					0xc02c, 0xc030, 0x009f,
					0xcca9, 0xcca8, 0xccaa,
					0xc02b, 0xc02f, 0x009e,
					0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
				},
				Extensions: []uint16{
					0x0000, 0x000b, 0x000a, 0x0023, 0x0016, 0x0017,
					0x000d, 0x002b, 0x002d, 0x0033, 0x0015,
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

		// L7 Application - Visual content heavy
		Application: ApplicationProfile{
			Message: MessagePattern{
				// Instagram DMs are typically short
				TextSizeDistribution:    Distribution{Type: "lognormal", Params: []float64{3.8, 0.7}},
				EmojiSize:               16,
				StickerSizeMin:          5000,
				StickerSizeMax:          30000,
				VoiceDurationMin:        1 * time.Second,
				VoiceDurationMax:        60 * time.Second,
				VoiceBitrate:            64000,
				TypingIndicatorInterval: 5 * time.Second,
				TypingTimeout:           10 * time.Second,
			},

			States: []ActivityState{
				{
					Name:             "idle",
					PacketsPerSecond: Distribution{Type: "exponential", Params: []float64{0.02}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{64, 256}},
					Duration:         Distribution{Type: "exponential", Params: []float64{0.001}},
					Transitions:      map[string]float64{"idle": 0.5, "feed_browse": 0.35, "story_view": 0.15},
				},
				{
					Name:             "feed_browse",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{15.0, 5.0}}, // Heavy image loading
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{9.0, 1.5}}, // Large images
					Duration:         Distribution{Type: "lognormal", Params: []float64{4.0, 1.0}},
					Transitions:      map[string]float64{"feed_browse": 0.5, "content_view": 0.25, "idle": 0.15, "story_view": 0.1},
				},
				{
					Name:             "story_view",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{20.0, 8.0}}, // Video/image stories
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{10.0, 1.2}},
					Duration:         Distribution{Type: "uniform", Params: []float64{3000, 15000}}, // 3-15 sec per story
					Transitions:      map[string]float64{"story_view": 0.6, "feed_browse": 0.25, "idle": 0.15},
				},
				{
					Name:             "content_view",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{8.0, 3.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{8.5, 1.0}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{3.5, 1.2}},
					Transitions:      map[string]float64{"feed_browse": 0.4, "dm_typing": 0.2, "content_view": 0.25, "idle": 0.15},
				},
				{
					Name:             "dm_typing",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{2.0, 0.5}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{64, 128}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.5, 0.8}},
					Transitions:      map[string]float64{"dm_sending": 0.6, "feed_browse": 0.2, "idle": 0.2},
				},
				{
					Name:             "dm_sending",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{10.0, 4.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{5.0, 1.0}},
					Duration:         Distribution{Type: "uniform", Params: []float64{100, 1000}},
					Transitions:      map[string]float64{"idle": 0.4, "feed_browse": 0.4, "dm_typing": 0.2},
				},
			},

			Bursts: BurstProfile{
				ThreadBurstSize:    Distribution{Type: "pareto", Params: []float64{2, 1.5}},
				ThreadBurstGap:     Distribution{Type: "lognormal", Params: []float64{6.5, 1.0}},
				ThreadCooldown:     Distribution{Type: "exponential", Params: []float64{0.0002}},
				MediaBurstPackets:  Distribution{Type: "uniform", Params: []float64{20, 100}}, // Image heavy
				MediaBurstInterval: Distribution{Type: "uniform", Params: []float64{10, 50}},
				GroupReadBurst:     Distribution{Type: "pareto", Params: []float64{5, 2.0}},
				GroupReplyDelay:    Distribution{Type: "lognormal", Params: []float64{7.0, 1.2}},
			},

			Heartbeat: HeartbeatProfile{
				BackgroundInterval: 20 * time.Second,
				BackgroundJitter:   0.15,
				ActiveInterval:     5 * time.Second,
				ActiveJitter:       0.1,
				PowerSaveInterval:  5 * time.Minute,
			},

			ACK: ACKProfile{
				DelayedACKTimeout: 40 * time.Millisecond,
				CoalesceMax:       4,
				MessageACK:        ACKBehavior{ImmediateACK: false, DelayMs: 100, BatchSize: 6},
			},

			Media: MediaProfile{
				PhotoChunkSize:       131072, // 128KB - high quality images
				PhotoChunks:          Distribution{Type: "uniform", Params: []float64{10, 80}},
				PhotoUploadInterval:  Distribution{Type: "uniform", Params: []float64{20, 60}},
				VideoChunkSize:       524288,
				VideoBufferSegments:  4,
				VideoSegmentDuration: 4 * time.Second,
				FileChunkSize:        131072,
				FileChunkGap:         Distribution{Type: "uniform", Params: []float64{20, 50}},
			},
		},

		// Timing Model
		Timing: TimingModel{
			IPD: Distribution{Type: "lognormal", Params: []float64{3.5, 1.8}},

			Jitter: JitterModel{
				BaseJitter:    10.0,
				NetworkJitter: 25.0,
				AppJitter:     15.0,
				Distribution:  "gaussian",
			},

			DailyPattern: DailyActivityPattern{
				HourlyActivity: [24]float64{
					0.10, 0.05, 0.03, 0.02, 0.02, 0.05,
					0.10, 0.25, 0.55, 0.70, 0.80, 0.90,
					0.95, 1.0, 0.95, 0.90, 0.85, 0.80,
					0.90, 1.0, 1.05, 1.0, 0.80, 0.40, // Peak evening for Instagram
				},
				WeekendModifier: 1.2, // More active on weekends
				PeakHours:       []int{12, 13, 19, 20, 21, 22},
			},

			HumanNoise: HumanNoiseModel{
				ReadingTimePerChar:  40 * time.Millisecond,
				ThinkingTime:        Distribution{Type: "lognormal", Params: []float64{6.5, 1.0}},
				CorrectionRate:      0.10,
				DistractionRate:     0.12, // High - many distractions
				DistractionDuration: Distribution{Type: "lognormal", Params: []float64{8.0, 1.0}},
				MultitaskingGaps:    Distribution{Type: "pareto", Params: []float64{2000, 1.5}},
			},

			NetworkResponse: NetworkResponseModel{
				RetryIntervals:    []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, 800 * time.Millisecond, 2 * time.Second},
				BackoffMultiplier: 2.0,
				MaxRetries:        4,
				ReconnectDelay:    Distribution{Type: "uniform", Params: []float64{500, 3000}},
			},
		},

		// Context & Ecosystem
		Context: ContextProfile{
			DNS: DNSProfile{
				Servers:    []string{"157.240.1.35", "157.240.199.35"}, // Meta DNS
				QueryTypes: []string{"A", "AAAA", "HTTPS"},
				RespectTTL: true,
				DoHEnabled: false,
			},

			CDN: CDNProfile{
				Domains: []string{
					"instagram.com",
					"www.instagram.com",
					"i.instagram.com",
					"graph.instagram.com",
					"scontent.cdninstagram.com",
					"scontent-arn2-1.cdninstagram.com",
					"static.cdninstagram.com",
				},
				ConnectionsPerDomain: 6,
				PrefetchEnabled:      true,
			},

			Push: PushProfile{
				Technology:        "fcm",
				HeartbeatInterval: 4 * time.Minute,
				WakeupPattern: WakeupPattern{
					Interval:         15 * time.Minute,
					Jitter:           0.25,
					PostWakeActivity: 10 * time.Second,
				},
			},

			Background: BackgroundProfile{
				ConnectionCount: 5,
				Connections: []BackgroundConnection{
					{Purpose: "graphql", Interval: 10 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{128, 512}}},
					{Purpose: "realtime", Interval: 5 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{64, 256}}},
					{Purpose: "stories", Interval: 30 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{256, 1024}}},
					{Purpose: "feed_prefetch", Interval: 20 * time.Second, Size: Distribution{Type: "lognormal", Params: []float64{8, 1}}},
					{Purpose: "presence", Interval: 45 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{32, 64}}},
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
				Name:               "Instagram",
				Version:            "312.0.0.34.111",
				BuildNumber:        "552156820",
				UserAgent:          "Instagram 312.0.0.34.111 Android (34/14; 560dpi; 1440x3088; samsung; SM-S918B; e3q; qcom; ru_RU; 552156820)",
				ForegroundInterval: 5 * time.Second,
				BackgroundInterval: 20 * time.Second,
			},

			Device: DeviceProfile{
				Manufacturer:    "samsung",
				Model:           "SM-S918B",
				ScreenDensity:   3.5,
				CellularCapable: true,
				WiFiPreferred:   true,
				IPv6Supported:   true,
			},

			Network: ClientNetworkProfile{
				TCPNoDelay:    true,
				TCPQuickACK:   true,
				SocketTimeout: 30 * time.Second,
				MaxIdleConns:  10,
				IdleTimeout:   90 * time.Second,
			},
		},
	}
}
