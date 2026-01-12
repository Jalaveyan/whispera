// Package behavioral - iOS device profiles
package behavioral

import "time"

// TelegramIOSProfile returns Telegram profile for iOS devices
func TelegramIOSProfile() *MessengerProfile {
	profile := TelegramProfile()
	profile.Name = "Telegram iOS"

	// iOS-specific TLS settings
	profile.TLS.JA3 = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-157-156-61-60-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	profile.TLS.JA4 = "t13d1516h2_ios_tg_849294fa"

	profile.TLS.ClientHello.CipherSuites = []uint16{
		0x1302, 0x1303, 0x1301, // TLS 1.3
		0xc02c, 0xc030, 0x009f,
		0xcca9, 0xcca8, 0xccaa,
		0xc02b, 0xc02f, 0x009e,
		0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
	}

	// iOS client profile
	profile.Client = ClientProfile{
		OS: OSProfile{
			Name:             "iOS",
			Version:          "17.2",
			Build:            "21C62",
			SocketBufferSize: 262144,
			PowerSaveMode:    "auto",
			PowerSaveBehavior: PowerSaveBehavior{
				NetworkSchedule:    10 * time.Minute,
				ReducedHeartbeat:   10 * time.Minute, // iOS aggressive background throttling
				BatchedRequests:    true,
				DeferrableInterval: 15 * time.Minute,
			},
		},
		App: AppProfile{
			Name:               "Telegram",
			Version:            "10.5.4",
			BuildNumber:        "28291",
			UserAgent:          "Telegram/10.5.4 (iPhone; iOS 17.2; Scale/3.00)",
			ForegroundInterval: 5 * time.Second,
			BackgroundInterval: 180 * time.Second, // iOS limits background
		},
		Device: DeviceProfile{
			Manufacturer:    "Apple",
			Model:           "iPhone15,3", // iPhone 14 Pro Max
			ScreenDensity:   3.0,
			CellularCapable: true,
			WiFiPreferred:   true,
			IPv6Supported:   true,
		},
		Network: ClientNetworkProfile{
			TCPNoDelay:    true,
			TCPQuickACK:   false, // iOS doesn't use Quick ACK
			SocketTimeout: 30 * time.Second,
			MaxIdleConns:  4,
			IdleTimeout:   60 * time.Second,
		},
	}

	// iOS APNS push
	profile.Context.Push = PushProfile{
		Technology:        "apns", // Apple Push Notification Service
		HeartbeatInterval: 8 * time.Minute,
		WakeupPattern: WakeupPattern{
			Interval:         30 * time.Minute, // iOS aggressive background limits
			Jitter:           0.3,
			PostWakeActivity: 3 * time.Second,
		},
	}

	return profile
}

// VKMessengerIOSProfile returns VK Messenger profile for iOS
func VKMessengerIOSProfile() *MessengerProfile {
	profile := VKMessengerProfile()
	profile.Name = "VK Messenger iOS"

	profile.TLS.JA3 = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-157-156-61-60-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	profile.TLS.JA4 = "t13d1516h2_ios_vk_7a8c3d2e"

	profile.Client = ClientProfile{
		OS: OSProfile{
			Name:             "iOS",
			Version:          "17.2",
			Build:            "21C62",
			SocketBufferSize: 262144,
			PowerSaveMode:    "auto",
			PowerSaveBehavior: PowerSaveBehavior{
				NetworkSchedule:    10 * time.Minute,
				ReducedHeartbeat:   10 * time.Minute,
				BatchedRequests:    true,
				DeferrableInterval: 15 * time.Minute,
			},
		},
		App: AppProfile{
			Name:               "VK",
			Version:            "8.72",
			BuildNumber:        "19234",
			UserAgent:          "com.vk.vkclient/8172 (iPhone, iOS 17.2, iPhone15,3, Scale/3.00)",
			ForegroundInterval: 5 * time.Second,
			BackgroundInterval: 180 * time.Second,
		},
		Device: DeviceProfile{
			Manufacturer:    "Apple",
			Model:           "iPhone15,3",
			ScreenDensity:   3.0,
			CellularCapable: true,
			WiFiPreferred:   true,
			IPv6Supported:   true,
		},
		Network: ClientNetworkProfile{
			TCPNoDelay:    true,
			TCPQuickACK:   false,
			SocketTimeout: 25 * time.Second,
			MaxIdleConns:  6,
			IdleTimeout:   60 * time.Second,
		},
	}

	profile.Context.Push.Technology = "apns"

	return profile
}

// InstagramIOSProfile returns Instagram profile for iOS
func InstagramIOSProfile() *MessengerProfile {
	profile := InstagramProfile()
	profile.Name = "Instagram iOS"

	profile.TLS.JA3 = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-157-156-61-60-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	profile.TLS.JA4 = "t13d1516h2_ios_ig_5f6e7d8c"

	profile.Client = ClientProfile{
		OS: OSProfile{
			Name:             "iOS",
			Version:          "17.2",
			Build:            "21C62",
			SocketBufferSize: 262144,
			PowerSaveMode:    "auto",
			PowerSaveBehavior: PowerSaveBehavior{
				NetworkSchedule:    15 * time.Minute,
				ReducedHeartbeat:   10 * time.Minute,
				BatchedRequests:    true,
				DeferrableInterval: 15 * time.Minute,
			},
		},
		App: AppProfile{
			Name:               "Instagram",
			Version:            "312.0.0.34.111",
			BuildNumber:        "552156820",
			UserAgent:          "Instagram 312.0.0.34.111 (iPhone15,3; iOS 17_2; en_US; en-US; scale=3.00; 1290x2796; 552156820)",
			ForegroundInterval: 5 * time.Second,
			BackgroundInterval: 180 * time.Second,
		},
		Device: DeviceProfile{
			Manufacturer:    "Apple",
			Model:           "iPhone15,3",
			ScreenDensity:   3.0,
			CellularCapable: true,
			WiFiPreferred:   true,
			IPv6Supported:   true,
		},
		Network: ClientNetworkProfile{
			TCPNoDelay:    true,
			TCPQuickACK:   false,
			SocketTimeout: 30 * time.Second,
			MaxIdleConns:  8,
			IdleTimeout:   90 * time.Second,
		},
	}

	profile.Context.Push.Technology = "apns"

	return profile
}

// FacebookMessengerIOSProfile returns Facebook Messenger profile for iOS
func FacebookMessengerIOSProfile() *MessengerProfile {
	profile := FacebookMessengerProfile()
	profile.Name = "Facebook Messenger iOS"

	profile.TLS.JA3 = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-157-156-61-60-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	profile.TLS.JA4 = "t13d1516h2_ios_fbm_9a8b7c6d"

	profile.Client = ClientProfile{
		OS: OSProfile{
			Name:             "iOS",
			Version:          "17.2",
			Build:            "21C62",
			SocketBufferSize: 262144,
			PowerSaveMode:    "auto",
			PowerSaveBehavior: PowerSaveBehavior{
				NetworkSchedule:    15 * time.Minute,
				ReducedHeartbeat:   10 * time.Minute,
				BatchedRequests:    true,
				DeferrableInterval: 15 * time.Minute,
			},
		},
		App: AppProfile{
			Name:               "Messenger",
			Version:            "445.0.0.41.109",
			BuildNumber:        "507629430",
			UserAgent:          "Messenger/445.0.0.41.109 (iPhone; iOS 17.2; Scale/3.00)",
			ForegroundInterval: 5 * time.Second,
			BackgroundInterval: 180 * time.Second,
		},
		Device: DeviceProfile{
			Manufacturer:    "Apple",
			Model:           "iPhone15,3",
			ScreenDensity:   3.0,
			CellularCapable: true,
			WiFiPreferred:   true,
			IPv6Supported:   true,
		},
		Network: ClientNetworkProfile{
			TCPNoDelay:    true,
			TCPQuickACK:   false,
			SocketTimeout: 30 * time.Second,
			MaxIdleConns:  8,
			IdleTimeout:   90 * time.Second,
		},
	}

	profile.Context.Push.Technology = "apns"

	return profile
}

// WeChatIOSProfile returns WeChat profile for iOS
func WeChatIOSProfile() *MessengerProfile {
	profile := WeChatProfile()
	profile.Name = "WeChat iOS"

	profile.TLS.JA3 = "771,4866-4867-4865-49196-49200-159-52393-49195-49199-158-49188-49192-107-49187-49191-103-157-156-61-60-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	profile.TLS.JA4 = "t13d1516h2_ios_wx_3e4d5c6b"

	profile.Client = ClientProfile{
		OS: OSProfile{
			Name:             "iOS",
			Version:          "17.2",
			Build:            "21C62",
			SocketBufferSize: 262144,
			PowerSaveMode:    "auto",
			PowerSaveBehavior: PowerSaveBehavior{
				NetworkSchedule:    15 * time.Minute,
				ReducedHeartbeat:   10 * time.Minute,
				BatchedRequests:    true,
				DeferrableInterval: 15 * time.Minute,
			},
		},
		App: AppProfile{
			Name:               "WeChat",
			Version:            "8.0.44",
			BuildNumber:        "18490",
			UserAgent:          "MicroMessenger/8.0.44(0x18002c2e) NetType/WIFI Language/en Scale/3.00",
			ForegroundInterval: 5 * time.Second,
			BackgroundInterval: 180 * time.Second,
		},
		Device: DeviceProfile{
			Manufacturer:    "Apple",
			Model:           "iPhone15,3",
			ScreenDensity:   3.0,
			CellularCapable: true,
			WiFiPreferred:   true,
			IPv6Supported:   true,
		},
		Network: ClientNetworkProfile{
			TCPNoDelay:    true,
			TCPQuickACK:   false,
			SocketTimeout: 30 * time.Second,
			MaxIdleConns:  6,
			IdleTimeout:   120 * time.Second,
		},
	}

	profile.Context.Push.Technology = "apns"

	return profile
}
