// Package behavioral - Facebook Messenger behavioral profile
package behavioral

import "time"

// FacebookMessengerProfile returns a complete Facebook Messenger behavioral profile
// Based on Facebook Messenger Android app traffic analysis
func FacebookMessengerProfile() *MessengerProfile {
	return &MessengerProfile{
		Name: "Facebook Messenger",

		// L3/L4 Transport
		Transport: TransportProfile{
			PreferredProtocol: "tcp",
			TCP: TCPFingerprint{
				// Meta/Facebook stack
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

		// L5/L6 TLS - Meta stack
		TLS: TLSProfile{
			JA3: "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2",
			JA4: "t13d1517h2_fbmsg7e78f70_meta82dd1658",

			ClientHello: ClientHelloProfile{
				CipherSuites: []uint16{
					0x1302, 0x1303, 0x1301,
					0xc02c, 0xc030, 0x009f,
					0xcca9, 0xcca8, 0xccaa,
					0xc02b, 0xc02f, 0x009e,
					0xc024, 0xc028, 0x006b,
					0xc023, 0xc027, 0x0067,
					0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033,
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

		// L7 Application
		Application: ApplicationProfile{
			Message: MessagePattern{
				TextSizeDistribution:    Distribution{Type: "lognormal", Params: []float64{4.2, 0.9}},
				EmojiSize:               16,
				StickerSizeMin:          8000,
				StickerSizeMax:          40000,
				VoiceDurationMin:        1 * time.Second,
				VoiceDurationMax:        90 * time.Second,
				VoiceBitrate:            64000,
				TypingIndicatorInterval: 5 * time.Second,
				TypingTimeout:           8 * time.Second,
			},

			States: []ActivityState{
				{
					Name:             "idle",
					PacketsPerSecond: Distribution{Type: "exponential", Params: []float64{0.025}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{64, 256}},
					Duration:         Distribution{Type: "exponential", Params: []float64{0.0007}},
					Transitions:      map[string]float64{"idle": 0.55, "typing": 0.25, "receiving": 0.15, "stories": 0.05},
				},
				{
					Name:             "typing",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{2.5, 0.8}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{64, 128}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.6, 0.7}},
					Transitions:      map[string]float64{"sending": 0.6, "idle": 0.3, "typing": 0.1},
				},
				{
					Name:             "sending",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{12.0, 4.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{5.2, 1.1}},
					Duration:         Distribution{Type: "uniform", Params: []float64{100, 1500}},
					Transitions:      map[string]float64{"idle": 0.45, "typing": 0.35, "receiving": 0.2},
				},
				{
					Name:             "receiving",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{8.0, 3.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{5.8, 1.3}},
					Duration:         Distribution{Type: "lognormal", Params: []float64{2.2, 0.6}},
					Transitions:      map[string]float64{"idle": 0.45, "typing": 0.4, "receiving": 0.15},
				},
				{
					Name:             "stories",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{18.0, 6.0}},
					PacketSizes:      Distribution{Type: "lognormal", Params: []float64{9.5, 1.3}},
					Duration:         Distribution{Type: "uniform", Params: []float64{3000, 15000}},
					Transitions:      map[string]float64{"stories": 0.5, "idle": 0.35, "typing": 0.15},
				},
				{
					Name:             "video_call",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{60.0, 15.0}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{500, 1200}}, // Video frames
					Duration:         Distribution{Type: "lognormal", Params: []float64{9.5, 1.5}},
					Transitions:      map[string]float64{"idle": 0.95, "typing": 0.05},
				},
			},

			Bursts: BurstProfile{
				ThreadBurstSize:    Distribution{Type: "pareto", Params: []float64{3, 1.7}},
				ThreadBurstGap:     Distribution{Type: "lognormal", Params: []float64{6.0, 0.9}},
				ThreadCooldown:     Distribution{Type: "exponential", Params: []float64{0.00035}},
				MediaBurstPackets:  Distribution{Type: "uniform", Params: []float64{20, 80}},
				MediaBurstInterval: Distribution{Type: "uniform", Params: []float64{20, 60}},
				GroupReadBurst:     Distribution{Type: "pareto", Params: []float64{8, 2.3}},
				GroupReplyDelay:    Distribution{Type: "lognormal", Params: []float64{7.3, 1.1}},
			},

			Heartbeat: HeartbeatProfile{
				BackgroundInterval: 25 * time.Second,
				BackgroundJitter:   0.15,
				ActiveInterval:     5 * time.Second,
				ActiveJitter:       0.1,
				PowerSaveInterval:  5 * time.Minute,
			},

			ACK: ACKProfile{
				DelayedACKTimeout: 45 * time.Millisecond,
				CoalesceMax:       5,
				MessageACK:        ACKBehavior{ImmediateACK: false, DelayMs: 90, BatchSize: 7},
			},

			Media: MediaProfile{
				PhotoChunkSize:       131072,
				PhotoChunks:          Distribution{Type: "uniform", Params: []float64{8, 60}},
				PhotoUploadInterval:  Distribution{Type: "uniform", Params: []float64{20, 55}},
				VideoChunkSize:       524288,
				VideoBufferSegments:  4,
				VideoSegmentDuration: 4 * time.Second,
				FileChunkSize:        131072,
				FileChunkGap:         Distribution{Type: "uniform", Params: []float64{18, 45}},
			},
		},

		// Timing Model
		Timing: TimingModel{
			IPD: Distribution{Type: "lognormal", Params: []float64{4.0, 1.6}},

			Jitter: JitterModel{
				BaseJitter:    8.0,
				NetworkJitter: 22.0,
				AppJitter:     12.0,
				Distribution:  "gaussian",
			},

			DailyPattern: DailyActivityPattern{
				HourlyActivity: [24]float64{
					0.15, 0.08, 0.05, 0.03, 0.03, 0.05,
					0.10, 0.30, 0.55, 0.70, 0.80, 0.90,
					0.95, 1.0, 0.95, 0.90, 0.85, 0.80,
					0.88, 0.98, 1.05, 1.0, 0.75, 0.40,
				},
				WeekendModifier: 1.15,
				PeakHours:       []int{12, 13, 19, 20, 21, 22},
			},

			HumanNoise: HumanNoiseModel{
				ReadingTimePerChar:  45 * time.Millisecond,
				ThinkingTime:        Distribution{Type: "lognormal", Params: []float64{7.0, 1.0}},
				CorrectionRate:      0.12,
				DistractionRate:     0.09,
				DistractionDuration: Distribution{Type: "lognormal", Params: []float64{8.2, 0.9}},
				MultitaskingGaps:    Distribution{Type: "pareto", Params: []float64{3500, 1.9}},
			},

			NetworkResponse: NetworkResponseModel{
				RetryIntervals:    []time.Duration{100 * time.Millisecond, 250 * time.Millisecond, 600 * time.Millisecond, 1500 * time.Millisecond},
				BackoffMultiplier: 2.0,
				MaxRetries:        4,
				ReconnectDelay:    Distribution{Type: "uniform", Params: []float64{500, 3000}},
			},
		},

		// Context - Meta infrastructure
		Context: ContextProfile{
			DNS: DNSProfile{
				Servers:    []string{"157.240.1.35", "157.240.199.35"},
				QueryTypes: []string{"A", "AAAA", "HTTPS"},
				RespectTTL: true,
				DoHEnabled: false,
			},

			CDN: CDNProfile{
				Domains: []string{
					"messenger.com",
					"www.messenger.com",
					"m.facebook.com",
					"graph.facebook.com",
					"edge-chat.facebook.com",
					"mqtt-mini.facebook.com",
					"scontent.xx.fbcdn.net",
					"static.xx.fbcdn.net",
				},
				ConnectionsPerDomain: 5,
				PrefetchEnabled:      true,
			},

			Push: PushProfile{
				Technology:        "mqtt", // Messenger uses MQTT
				HeartbeatInterval: 3 * time.Minute,
				WakeupPattern: WakeupPattern{
					Interval:         15 * time.Minute,
					Jitter:           0.2,
					PostWakeActivity: 8 * time.Second,
				},
			},

			Background: BackgroundProfile{
				ConnectionCount: 4,
				Connections: []BackgroundConnection{
					{Purpose: "mqtt", Interval: 180 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{32, 64}}},
					{Purpose: "graphql", Interval: 15 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{128, 512}}},
					{Purpose: "realtime", Interval: 30 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{64, 256}}},
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
				Name:               "Messenger",
				Version:            "445.0.0.41.109",
				BuildNumber:        "507629430",
				UserAgent:          "Messenger/445.0.0.41.109 (Android/14; SDK/34; samsung/SM-S918B; arm64-v8a)",
				ForegroundInterval: 5 * time.Second,
				BackgroundInterval: 25 * time.Second,
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
				MaxIdleConns:  8,
				IdleTimeout:   90 * time.Second,
			},
		},
	}
}
