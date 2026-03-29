package behavioral

import "time"

// YouTubeProfile mimics YouTube Android streaming behavior.
// Characteristics: large DASH/HLS segment fetches (500 KB–2 MB per segment),
// adaptive bitrate switching, frequent manifest polls, seeking bursts.
func YouTubeProfile() *MessengerProfile {
	return &MessengerProfile{
		Name: "YouTube",

		Transport: TransportProfile{
			PreferredProtocol: "tcp",
			TCP: TCPFingerprint{
				OptionsOrder:         []string{"mss", "sack_permitted", "timestamps", "nop", "window_scale"},
				InitialWindowSize:    65535,
				MSS:                  1460,
				WindowScale:          9,
				SACKPermitted:        true,
				Timestamps:           true,
				KeepAliveInterval:    60 * time.Second,
				KeepAliveProbes:      9,
				RetransmitMinTimeout: 200 * time.Millisecond,
				RetransmitMaxTimeout: 60 * time.Second,
			},
			UDP: UDPProfile{
				PreferredSizes:     []int{1200, 1350, 1400},
				PMTUDiscovery:      true,
				AllowFragmentation: false,
			},
		},

		TLS: TLSProfile{
			JA3: "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2",
			JA4: "t13d1516h2_8daaf6152771_b0da82dd1658",

			ClientHello: ClientHelloProfile{
				CipherSuites: []uint16{
					0x1302, 0x1303, 0x1301,
					0xc02c, 0xc030, 0x009f,
					0xcca9, 0xcca8, 0xccaa,
					0xc02b, 0xc02f, 0x009e,
					0xc024, 0xc028, 0x006b,
					0xc023, 0xc027, 0x0067,
					0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
				},
				Extensions:          []uint16{0x0000, 0x000b, 0x000a, 0x0023, 0x0016, 0x0017, 0x000d, 0x002b, 0x002d, 0x0033},
				SupportedGroups:     []uint16{0x001d, 0x0017, 0x001e, 0x0019, 0x0018},
				SignatureAlgorithms: []uint16{0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601},
				ALPN:                []string{"h2"},
				SupportedVersions:   []uint16{0x0304, 0x0303},
				KeyShareGroups:      []uint16{0x001d, 0x0017},
				PSKModes:            []uint8{0x01},
				PaddingEnabled:      true,
				PaddingMin:          16,
				PaddingMax:          1024,
			},
			SessionResumption: true,
			SessionTickets:    true,
			ZeroRTT:           true,
			MaxEarlyDataSize:  16384,
		},

		Application: ApplicationProfile{
			Message: MessagePattern{
				// DASH video segments: 1080p ~500 KB–2 MB per 5s segment
				TextSizeDistribution: Distribution{Type: "lognormal", Params: []float64{13.0, 0.8}},
				EmojiSize:            0,
			},

			States: []ActivityState{
				{
					// Steady streaming: filling buffer ahead ~30s
					Name:             "streaming",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{80.0, 20.0}},
					PacketSizes:      Distribution{Type: "gaussian", Params: []float64{1380, 60}},
					Duration:         Distribution{Type: "exponential", Params: []float64{0.0002}},
					Transitions: map[string]float64{
						"streaming":   0.75,
						"buffering":   0.05,
						"seeking":     0.05,
						"manifest":    0.10,
						"paused":      0.05,
					},
				},
				{
					// Buffering: aggressive burst fill after stall or seek
					Name:             "buffering",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{200.0, 40.0}},
					PacketSizes:      Distribution{Type: "gaussian", Params: []float64{1400, 30}},
					Duration:         Distribution{Type: "uniform", Params: []float64{200, 2000}},
					Transitions: map[string]float64{
						"streaming": 0.92,
						"manifest":  0.08,
					},
				},
				{
					// Seeking: brief pause + large burst then resume
					Name:             "seeking",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{150.0, 30.0}},
					PacketSizes:      Distribution{Type: "gaussian", Params: []float64{1380, 50}},
					Duration:         Distribution{Type: "uniform", Params: []float64{300, 1500}},
					Transitions: map[string]float64{
						"streaming": 0.90,
						"buffering": 0.10,
					},
				},
				{
					// Manifest refresh: small DASH/HLS manifest poll
					Name:             "manifest",
					PacketsPerSecond: Distribution{Type: "uniform", Params: []float64{2.0, 5.0}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{256, 2048}},
					Duration:         Distribution{Type: "uniform", Params: []float64{50, 300}},
					Transitions: map[string]float64{
						"streaming": 0.95,
						"buffering": 0.05,
					},
				},
				{
					// Paused: keepalive only
					Name:             "paused",
					PacketsPerSecond: Distribution{Type: "exponential", Params: []float64{0.03}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{64, 256}},
					Duration:         Distribution{Type: "exponential", Params: []float64{0.0001}},
					Transitions: map[string]float64{
						"streaming": 0.75,
						"paused":    0.20,
						"manifest":  0.05,
					},
				},
			},

			Bursts: BurstProfile{
				// Video segment fetch bursts
				ThreadBurstSize: Distribution{Type: "uniform", Params: []float64{5, 15}},
				ThreadBurstGap:  Distribution{Type: "gaussian", Params: []float64{5000, 1000}},
				ThreadCooldown:  Distribution{Type: "exponential", Params: []float64{0.001}},

				MediaBurstPackets:  Distribution{Type: "uniform", Params: []float64{100, 1500}},
				MediaBurstInterval: Distribution{Type: "gaussian", Params: []float64{5000, 1000}},

				GroupReadBurst:  Distribution{Type: "uniform", Params: []float64{1, 3}},
				GroupReplyDelay: Distribution{Type: "uniform", Params: []float64{0, 0}},
			},

			Heartbeat: HeartbeatProfile{
				BackgroundInterval: 30 * time.Second,
				BackgroundJitter:   0.15,
				ActiveInterval:     5 * time.Second,
				ActiveJitter:       0.1,
				PowerSaveInterval:  5 * time.Minute,
			},

			ACK: ACKProfile{
				DelayedACKTimeout: 15 * time.Millisecond,
				CoalesceMax:       4,
				MessageACK: ACKBehavior{
					ImmediateACK: true,
					DelayMs:      0,
					BatchSize:    1,
				},
			},

			Media: MediaProfile{
				// DASH video segments
				PhotoChunkSize:      0,
				PhotoChunks:         Distribution{Type: "uniform", Params: []float64{0, 0}},
				PhotoUploadInterval: Distribution{Type: "uniform", Params: []float64{0, 0}},

				VideoChunkSize:       1048576, // 1 MB per segment (720p ~5s)
				VideoBufferSegments:  6,
				VideoSegmentDuration: 5 * time.Second,

				FileChunkSize: 524288,
				FileChunkGap:  Distribution{Type: "gaussian", Params: []float64{5000, 1000}},
			},
		},

		Timing: TimingModel{
			// Video streaming: very low inter-packet delay during bursts
			IPD: Distribution{Type: "gaussian", Params: []float64{12, 4}},

			Jitter: JitterModel{
				BaseJitter:    1.5,
				NetworkJitter: 6.0,
				AppJitter:     2.0,
				Distribution:  "gaussian",
			},

			DailyPattern: DailyActivityPattern{
				HourlyActivity: [24]float64{
					0.3, 0.2, 0.1, 0.05, 0.05, 0.1,
					0.2, 0.4, 0.55, 0.6, 0.65, 0.7,
					0.75, 0.7, 0.65, 0.7, 0.75, 0.85,
					0.95, 1.0, 1.0, 0.95, 0.8, 0.5,
				},
				WeekendModifier: 1.2,
				PeakHours:       []int{19, 20, 21, 22},
			},

			HumanNoise: HumanNoiseModel{
				ReadingTimePerChar:  0,
				ThinkingTime:        Distribution{Type: "uniform", Params: []float64{0, 0}},
				CorrectionRate:      0,
				DistractionRate:     0.01,
				DistractionDuration: Distribution{Type: "exponential", Params: []float64{0.0001}},
				MultitaskingGaps:    Distribution{Type: "pareto", Params: []float64{60000, 2.0}},
			},

			NetworkResponse: NetworkResponseModel{
				RetryIntervals:    []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, 1 * time.Second, 3 * time.Second},
				BackoffMultiplier: 1.5,
				MaxRetries:        3,
				ReconnectDelay:    Distribution{Type: "uniform", Params: []float64{300, 1500}},
			},
		},

		Context: ContextProfile{
			DNS: DNSProfile{
				Servers:    []string{"8.8.8.8", "8.8.4.4"},
				QueryTypes: []string{"A", "AAAA"},
				RespectTTL: true,
				DoHEnabled: true,
				DoHServer:  "https://dns.google/dns-query",
			},

			CDN: CDNProfile{
				Domains: []string{
					"rr5---sn-i3b7lner.googlevideo.com",
					"rr3---sn-q4flrner.googlevideo.com",
					"manifest.googlevideo.com",
					"i.ytimg.com",
					"www.youtube.com",
				},
				ConnectionsPerDomain: 6,
				PrefetchEnabled:      true,
			},

			Push: PushProfile{
				Technology:        "fcm",
				HeartbeatInterval: 5 * time.Minute,
				WakeupPattern: WakeupPattern{
					Interval:         60 * time.Minute,
					Jitter:           0.2,
					PostWakeActivity: 2 * time.Second,
				},
			},

			Background: BackgroundProfile{
				ConnectionCount: 5,
				Connections: []BackgroundConnection{
					{Purpose: "video_segment", Interval: 5 * time.Second, Size: Distribution{Type: "lognormal", Params: []float64{13.0, 0.8}}},
					{Purpose: "audio_segment", Interval: 5 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{65536, 131072}}},
					{Purpose: "manifest_refresh", Interval: 30 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{512, 4096}}},
					{Purpose: "heartbeat", Interval: 30 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{64, 256}}},
					{Purpose: "telemetry", Interval: 60 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{256, 1024}}},
				},
			},

			Endpoints: []EndpointProfile{
				{Path: "/videoplayback", Method: "GET", RequestSize: Distribution{Type: "uniform", Params: []float64{256, 512}}, ResponseSize: Distribution{Type: "lognormal", Params: []float64{13.0, 0.8}}, CallFrequency: Distribution{Type: "gaussian", Params: []float64{5000, 1000}}},
				{Path: "/api/stats/playback", Method: "POST", RequestSize: Distribution{Type: "uniform", Params: []float64{512, 2048}}, ResponseSize: Distribution{Type: "uniform", Params: []float64{64, 256}}, CallFrequency: Distribution{Type: "uniform", Params: []float64{15000, 30000}}},
			},
		},

		Client: ClientProfile{
			OS: OSProfile{
				Name:             "Android",
				Version:          "14",
				Build:            "UP1A.231005.007",
				SocketBufferSize: 1048576,
				PowerSaveMode:    "normal",
				PowerSaveBehavior: PowerSaveBehavior{
					NetworkSchedule:    10 * time.Minute,
					ReducedHeartbeat:   30 * time.Minute,
					BatchedRequests:    false,
					DeferrableInterval: 60 * time.Minute,
				},
			},

			App: AppProfile{
				Name:               "YouTube",
				Version:            "19.16.39",
				BuildNumber:        "1916039",
				UserAgent:          "com.google.android.youtube/19.16.39 (Linux; U; Android 14; samsung SM-S918B) gzip",
				ForegroundInterval: 5 * time.Second,
				BackgroundInterval: 60 * time.Second,
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
				TCPNoDelay:    false,
				TCPQuickACK:   false,
				SocketTimeout: 30 * time.Second,
				MaxIdleConns:  8,
				IdleTimeout:   120 * time.Second,
			},
		},
	}
}

// VKVideoStreamProfile mimics VK Video (vkvideo.ru) streaming behavior.
func VKVideoStreamProfile() *MessengerProfile {
	p := YouTubeProfile()
	p.Name = "VK Video Stream"

	p.Client.App = AppProfile{
		Name:               "VK Video",
		Version:            "1.45.0",
		BuildNumber:        "14500",
		UserAgent:          "VKAndroidApp/8.78-18078 (Android 14; SDK 34; arm64-v8a; samsung SM-S918B; ru)",
		ForegroundInterval: 5 * time.Second,
		BackgroundInterval: 60 * time.Second,
	}

	p.Context.CDN = CDNProfile{
		Domains: []string{
			"cs1-72v4.vkuservideo.net",
			"cs1-73v4.vkuservideo.net",
			"vkuservideo.net",
			"vkvideo.ru",
			"api.vk.com",
		},
		ConnectionsPerDomain: 4,
		PrefetchEnabled:      true,
	}

	p.Context.DNS = DNSProfile{
		Servers:    []string{"77.88.8.8", "8.8.8.8"},
		QueryTypes: []string{"A", "AAAA"},
		RespectTTL: true,
		DoHEnabled: false,
	}

	// VK Video segments slightly smaller (~720p common)
	p.Application.Media.VideoChunkSize = 786432 // 768 KB

	return p
}
