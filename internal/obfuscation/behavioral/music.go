package behavioral

import "time"

// SpotifyProfile mimics Spotify Android streaming behavior.
// Characteristics: steady ~128–320 kbps audio chunks over HTTPS/HTTP2,
// short periodic API calls (now-playing, seek, heartbeat), CDN prefetch,
// almost no user-interactive typing bursts.
func SpotifyProfile() *MessengerProfile {
	return &MessengerProfile{
		Name: "Spotify",

		Transport: TransportProfile{
			PreferredProtocol: "tcp",
			TCP: TCPFingerprint{
				OptionsOrder:         []string{"mss", "sack_permitted", "timestamps", "nop", "window_scale"},
				InitialWindowSize:    65535,
				MSS:                  1460,
				WindowScale:          8,
				SACKPermitted:        true,
				Timestamps:           true,
				KeepAliveInterval:    60 * time.Second,
				KeepAliveProbes:      9,
				RetransmitMinTimeout: 200 * time.Millisecond,
				RetransmitMaxTimeout: 60 * time.Second,
			},
			UDP: UDPProfile{
				PreferredSizes:     []int{1200, 1400},
				PMTUDiscovery:      true,
				AllowFragmentation: false,
			},
		},

		TLS: TLSProfile{
			// Spotify Android TLS fingerprint (Chrome-derivative)
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
				ALPN:                []string{"h2", "http/1.1"},
				SupportedVersions:   []uint16{0x0304, 0x0303},
				KeyShareGroups:      []uint16{0x001d, 0x0017},
				PSKModes:            []uint8{0x01},
				PaddingEnabled:      true,
				PaddingMin:          8,
				PaddingMax:          512,
			},
			SessionResumption: true,
			SessionTickets:    true,
			ZeroRTT:           true,
			MaxEarlyDataSize:  16384,
		},

		Application: ApplicationProfile{
			Message: MessagePattern{
				// Audio chunk sizes: 128kbps = ~16KB/s, 320kbps = ~40KB/s
				// Segments are ~4s → 64–160 KB per fetch
				TextSizeDistribution: Distribution{Type: "uniform", Params: []float64{65536, 163840}},
				EmojiSize:            0,
				StickerSizeMin:       0,
				StickerSizeMax:       0,
				VoiceDurationMin:     0,
				VoiceDurationMax:     0,
				VoiceBitrate:         0,
				TypingIndicatorInterval: 0,
				TypingTimeout:           0,
			},

			States: []ActivityState{
				{
					// Streaming: continuous audio segment fetches, ~1 fetch every 3-5s
					Name:             "streaming",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{25.0, 5.0}},
					PacketSizes:      Distribution{Type: "gaussian", Params: []float64{1350, 80}},
					Duration:         Distribution{Type: "exponential", Params: []float64{0.00033}},
					Transitions: map[string]float64{
						"streaming": 0.85,
						"buffering": 0.05,
						"api_poll":  0.08,
						"paused":    0.02,
					},
				},
				{
					// Buffering: burst of larger fetches when network recovers
					Name:             "buffering",
					PacketsPerSecond: Distribution{Type: "gaussian", Params: []float64{60.0, 15.0}},
					PacketSizes:      Distribution{Type: "gaussian", Params: []float64{1400, 40}},
					Duration:         Distribution{Type: "uniform", Params: []float64{500, 3000}},
					Transitions: map[string]float64{
						"streaming": 0.95,
						"api_poll":  0.05,
					},
				},
				{
					// API poll: small metadata calls (now-playing, shuffle state, etc.)
					Name:             "api_poll",
					PacketsPerSecond: Distribution{Type: "uniform", Params: []float64{1.0, 3.0}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{200, 800}},
					Duration:         Distribution{Type: "uniform", Params: []float64{100, 400}},
					Transitions: map[string]float64{
						"streaming": 0.90,
						"paused":    0.05,
						"buffering": 0.05,
					},
				},
				{
					// Paused: only heartbeat keepalives
					Name:             "paused",
					PacketsPerSecond: Distribution{Type: "exponential", Params: []float64{0.05}},
					PacketSizes:      Distribution{Type: "uniform", Params: []float64{64, 256}},
					Duration:         Distribution{Type: "exponential", Params: []float64{0.0002}},
					Transitions: map[string]float64{
						"streaming": 0.70,
						"paused":    0.25,
						"api_poll":  0.05,
					},
				},
			},

			Bursts: BurstProfile{
				// Audio segment fetch bursts
				ThreadBurstSize: Distribution{Type: "uniform", Params: []float64{3, 8}},
				ThreadBurstGap:  Distribution{Type: "gaussian", Params: []float64{3000, 500}},
				ThreadCooldown:  Distribution{Type: "exponential", Params: []float64{0.001}},

				MediaBurstPackets:  Distribution{Type: "uniform", Params: []float64{40, 120}},
				MediaBurstInterval: Distribution{Type: "uniform", Params: []float64{3000, 5000}},

				GroupReadBurst:  Distribution{Type: "uniform", Params: []float64{1, 2}},
				GroupReplyDelay: Distribution{Type: "uniform", Params: []float64{0, 0}},
			},

			Heartbeat: HeartbeatProfile{
				BackgroundInterval: 30 * time.Second,
				BackgroundJitter:   0.15,
				ActiveInterval:     10 * time.Second,
				ActiveJitter:       0.1,
				PowerSaveInterval:  2 * time.Minute,
			},

			ACK: ACKProfile{
				DelayedACKTimeout: 20 * time.Millisecond,
				CoalesceMax:       4,
				MessageACK: ACKBehavior{
					ImmediateACK: true,
					DelayMs:      0,
					BatchSize:    1,
				},
			},

			Media: MediaProfile{
				// Audio segments: ~64–160 KB at 128–320 kbps, 4s window
				PhotoChunkSize:      0,
				PhotoChunks:         Distribution{Type: "uniform", Params: []float64{0, 0}},
				PhotoUploadInterval: Distribution{Type: "uniform", Params: []float64{0, 0}},

				VideoChunkSize:       163840, // 160 KB audio segment
				VideoBufferSegments:  5,
				VideoSegmentDuration: 4 * time.Second,

				FileChunkSize: 65536,
				FileChunkGap:  Distribution{Type: "gaussian", Params: []float64{3500, 500}},
			},
		},

		Timing: TimingModel{
			// Audio streaming: very regular packet inter-arrival, low jitter
			IPD: Distribution{Type: "gaussian", Params: []float64{40, 8}},

			Jitter: JitterModel{
				BaseJitter:    2.0,
				NetworkJitter: 8.0,
				AppJitter:     2.0,
				Distribution:  "gaussian",
			},

			DailyPattern: DailyActivityPattern{
				HourlyActivity: [24]float64{
					0.2, 0.1, 0.05, 0.03, 0.04, 0.1,
					0.25, 0.5, 0.65, 0.7, 0.75, 0.8,
					0.85, 0.8, 0.75, 0.8, 0.85, 0.9,
					0.95, 1.0, 0.95, 0.85, 0.6, 0.35,
				},
				WeekendModifier: 1.1,
				PeakHours:       []int{8, 9, 17, 18, 19, 20},
			},

			HumanNoise: HumanNoiseModel{
				ReadingTimePerChar:  0,
				ThinkingTime:        Distribution{Type: "uniform", Params: []float64{0, 0}},
				CorrectionRate:      0,
				DistractionRate:     0.02,
				DistractionDuration: Distribution{Type: "exponential", Params: []float64{0.0002}},
				MultitaskingGaps:    Distribution{Type: "pareto", Params: []float64{30000, 2.0}},
			},

			NetworkResponse: NetworkResponseModel{
				RetryIntervals:    []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, 3 * time.Second},
				BackoffMultiplier: 1.5,
				MaxRetries:        4,
				ReconnectDelay:    Distribution{Type: "uniform", Params: []float64{500, 2000}},
			},
		},

		Context: ContextProfile{
			DNS: DNSProfile{
				Servers:    []string{"8.8.8.8", "1.1.1.1"},
				QueryTypes: []string{"A", "AAAA"},
				RespectTTL: true,
				DoHEnabled: true,
				DoHServer:  "https://cloudflare-dns.com/dns-query",
			},

			CDN: CDNProfile{
				Domains: []string{
					"audio-ak-spotify-com.akamaized.net",
					"audio4-ak-spotify-com.akamaized.net",
					"seektables.spotify.com",
					"api.spotify.com",
					"spclient.wg.spotify.com",
				},
				ConnectionsPerDomain: 4,
				PrefetchEnabled:      true,
			},

			Push: PushProfile{
				Technology:        "fcm",
				HeartbeatInterval: 3 * time.Minute,
				WakeupPattern: WakeupPattern{
					Interval:         30 * time.Minute,
					Jitter:           0.1,
					PostWakeActivity: 3 * time.Second,
				},
			},

			Background: BackgroundProfile{
				ConnectionCount: 4,
				Connections: []BackgroundConnection{
					{Purpose: "cdn_audio", Interval: 4 * time.Second, Size: Distribution{Type: "gaussian", Params: []float64{131072, 20000}}},
					{Purpose: "api_heartbeat", Interval: 30 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{64, 256}}},
					{Purpose: "lyrics_sync", Interval: 10 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{256, 1024}}},
					{Purpose: "now_playing", Interval: 5 * time.Second, Size: Distribution{Type: "uniform", Params: []float64{128, 512}}},
				},
			},

			Endpoints: []EndpointProfile{
				{Path: "/v1/me/player", Method: "GET", RequestSize: Distribution{Type: "uniform", Params: []float64{64, 128}}, ResponseSize: Distribution{Type: "uniform", Params: []float64{512, 2048}}, CallFrequency: Distribution{Type: "uniform", Params: []float64{5000, 10000}}},
				{Path: "/v1/me/player/next", Method: "POST", RequestSize: Distribution{Type: "uniform", Params: []float64{64, 128}}, ResponseSize: Distribution{Type: "uniform", Params: []float64{64, 128}}, CallFrequency: Distribution{Type: "exponential", Params: []float64{0.0005}}},
				{Path: "/audio4/", Method: "GET", RequestSize: Distribution{Type: "uniform", Params: []float64{256, 512}}, ResponseSize: Distribution{Type: "gaussian", Params: []float64{131072, 32768}}, CallFrequency: Distribution{Type: "gaussian", Params: []float64{4000, 500}}},
			},
		},

		Client: ClientProfile{
			OS: OSProfile{
				Name:             "Android",
				Version:          "14",
				Build:            "UP1A.231005.007",
				SocketBufferSize: 524288,
				PowerSaveMode:    "normal",
				PowerSaveBehavior: PowerSaveBehavior{
					NetworkSchedule:    5 * time.Minute,
					ReducedHeartbeat:   10 * time.Minute,
					BatchedRequests:    false,
					DeferrableInterval: 30 * time.Minute,
				},
			},

			App: AppProfile{
				Name:               "Spotify",
				Version:            "8.9.58.602",
				BuildNumber:        "89058602",
				UserAgent:          "Spotify/8.9.58.602 Android/34 (samsung SM-S918B)",
				ForegroundInterval: 10 * time.Second,
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
				TCPNoDelay:    false,
				TCPQuickACK:   false,
				SocketTimeout: 30 * time.Second,
				MaxIdleConns:  6,
				IdleTimeout:   120 * time.Second,
			},
		},
	}
}

// YandexMusicProfile mimics Yandex Music Android streaming behavior.
// Characteristics: similar to Spotify but with Yandex CDN domains and
// slightly more variable chunk sizes (64–192 KB), lower active user noise.
func YandexMusicProfile() *MessengerProfile {
	p := SpotifyProfile()
	p.Name = "Yandex Music"

	p.Client.App = AppProfile{
		Name:               "Yandex Music",
		Version:            "2024.03.1",
		BuildNumber:        "20240301",
		UserAgent:          "com.yandex.music/2024.03.1 (Android 14; samsung SM-S918B)",
		ForegroundInterval: 10 * time.Second,
		BackgroundInterval: 30 * time.Second,
	}

	p.Context.CDN = CDNProfile{
		Domains: []string{
			"storage.mds.yandex.net",
			"strm.yandex.ru",
			"music.yandex.ru",
			"api.music.yandex.net",
			"download.scdn.co",
		},
		ConnectionsPerDomain: 3,
		PrefetchEnabled:      true,
	}

	p.Context.DNS = DNSProfile{
		Servers:    []string{"77.88.8.8", "77.88.8.1"},
		QueryTypes: []string{"A", "AAAA"},
		RespectTTL: true,
		DoHEnabled: false,
	}

	// Slightly larger chunk variance
	p.Application.Media.VideoChunkSize = 196608 // 192 KB
	p.Application.Media.FileChunkSize = 65536

	return p
}

// VKMusicProfile mimics VK Music (part of VK app) streaming behavior.
func VKMusicProfile() *MessengerProfile {
	p := SpotifyProfile()
	p.Name = "VK Music"

	p.Client.App = AppProfile{
		Name:               "VK",
		Version:            "8.78",
		BuildNumber:        "18078",
		UserAgent:          "VKAndroidApp/8.78-18078 (Android 14; SDK 34; arm64-v8a; samsung SM-S918B; ru)",
		ForegroundInterval: 5 * time.Second,
		BackgroundInterval: 30 * time.Second,
	}

	p.Context.CDN = CDNProfile{
		Domains: []string{
			"cs1-72v4.vkuseraudio.net",
			"cs1-73v4.vkuseraudio.net",
			"vkuseraudio.net",
			"api.vk.com",
			"sun1-95.userapi.com",
		},
		ConnectionsPerDomain: 3,
		PrefetchEnabled:      true,
	}

	p.Context.DNS = DNSProfile{
		Servers:    []string{"77.88.8.8", "8.8.8.8"},
		QueryTypes: []string{"A", "AAAA"},
		RespectTTL: true,
		DoHEnabled: false,
	}

	return p
}
