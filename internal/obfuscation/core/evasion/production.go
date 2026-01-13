package evasion

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"time"
)

// secureRandInt generates a random integer from 0 to max (exclusive) using crypto/rand
func secureRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// applyProductionVKontakteEvasion применяет эвазию для ВКонтакте
func (m *Marionette) applyProductionVKontakteEvasion(data []byte) ([]byte, time.Duration, error) {
	// 1. Calculate realistic VK packet size
	pe := &ProductionEvasion{}
	targetSize := pe.calculateVKPacketSize(len(data))

	// 2. Create realistic VK HTTP request
	request := pe.createVKHTTPRequest(data, targetSize)

	// 3. Format as VK API request
	formatted := pe.formatVKRequest(request)

	// 4. Add VK-specific padding
	padded := pe.addVKPadding(formatted, targetSize)

	// Реалистичная задержка для VK API (50-150ms)
	delay := time.Millisecond * time.Duration(50+secureRandInt(100))
	return padded, delay, nil
}

// applyProductionYandexEvasion применяет эвазию для Яндекс
func (m *Marionette) applyProductionYandexEvasion(data []byte) ([]byte, time.Duration, error) {
	start := time.Now()
	obfuscatedData := make([]byte, len(data))
	copy(obfuscatedData, data)

	// Добавляем заголовки Яндекс
	yandexHeaders := []byte{0x59, 0x61, 0x6E, 0x64, 0x65, 0x78} // Yandex
	obfuscatedData = append(yandexHeaders, obfuscatedData...)

	// Yandex search patterns logic ported from production_evasion.go
	targetSize := 300 + secureRandInt(500)
	request := "GET /search/?text=test HTTP/1.1\r\nHost: yandex.ru\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\r\n"

	requestStr := request + string(data)
	if len(requestStr) < targetSize {
		padding := make([]byte, targetSize-len(requestStr))
		for i := range padding {
			padding[i] = byte(32 + secureRandInt(95))
		}
		requestStr += string(padding)
	}

	return []byte(requestStr), time.Since(start), nil
}

// applyProductionMailruEvasion применяет эвазию для Mail.ru
func (m *Marionette) applyProductionMailruEvasion(data []byte) ([]byte, time.Duration, error) {
	start := time.Now()
	targetSize := 400 + secureRandInt(600)
	request := "POST /api/v1/messages HTTP/1.1\r\nHost: e.mail.ru\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\r\n"
	request += string(data)

	if len(request) < targetSize {
		padding := make([]byte, targetSize-len(request))
		for i := range padding {
			padding[i] = byte(32 + secureRandInt(95))
		}
		request += string(padding)
	}

	return []byte(request), time.Since(start), nil
}

// applyProductionRutubeEvasion применяет эвазию для Rutube
func (m *Marionette) applyProductionRutubeEvasion(data []byte) ([]byte, time.Duration, error) {
	start := time.Now()
	targetSize := 500 + secureRandInt(1000)
	request := "GET /api/v1/videos/123456 HTTP/1.1\r\nHost: rutube.ru\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\r\n"
	request += string(data)

	if len(request) < targetSize {
		padding := make([]byte, targetSize-len(request))
		for i := range padding {
			padding[i] = byte(32 + secureRandInt(95))
		}
		request += string(padding)
	}

	return []byte(request), time.Since(start), nil
}

// applyProductionOzonEvasion применяет эвазию для Ozon
func (m *Marionette) applyProductionOzonEvasion(data []byte) ([]byte, time.Duration, error) {
	start := time.Now()
	targetSize := 600 + secureRandInt(800)
	request := "GET /api/composer-api.bx/page/json/v2?url=/ HTTP/1.1\r\nHost: www.ozon.ru\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\r\n"
	request += string(data)

	if len(request) < targetSize {
		padding := make([]byte, targetSize-len(request))
		for i := range padding {
			padding[i] = byte(32 + secureRandInt(95))
		}
		request += string(padding)
	}

	return []byte(request), time.Since(start), nil
}

// Helper struct and methods from production_evasion.go to support above functionality
type ProductionEvasion struct{}

func (pe *ProductionEvasion) calculateVKPacketSize(originalSize int) int {
	if originalSize < 100 {
		return 200 + secureRandInt(300)
	} else if originalSize < 1000 {
		return 500 + secureRandInt(1000)
	}
	return 1500 + secureRandInt(1000)
}

func (pe *ProductionEvasion) createVKHTTPRequest(data []byte, targetSize int) []byte {
	userAgent := "VKAndroidApp/7.0-1234 (Android 14; SDK 34; arm64-v8a; samsung SM-G991B; ru)"
	apiMethod := "messages.get"
	request := fmt.Sprintf("POST /method/%s HTTP/1.1\r\n", apiMethod)
	request += "Host: api.vk.com\r\n"
	request += fmt.Sprintf("User-Agent: %s\r\n", userAgent)
	request += "Content-Type: application/x-www-form-urlencoded\r\n"
	request += fmt.Sprintf("Content-Length: %d\r\n", len(data))
	request += "X-VK-Android-App: 7.0-1234\r\n"
	request += "X-VK-Language: ru\r\n"
	request += "X-VK-Token: vk1.a.1234567890abcdef\r\n"
	request += "X-VK-User-ID: 12345678\r\n"
	request += "\r\n"
	request += string(data)

	if len(request) < targetSize {
		padding := make([]byte, targetSize-len(request))
		for i := range padding {
			padding[i] = byte(32 + secureRandInt(95))
		}
		request += string(padding)
	}
	return []byte(request)
}

func (pe *ProductionEvasion) formatVKRequest(request []byte) []byte {
	jsonPattern := `{"response":{"count":123,"items":[{"id":123456,"date":1640995200,"out":1,"user_id":12345678,"read_state":1,"title":"","body":"Test message","emoji":1,"important":false,"deleted":false,"random_id":0,"chat_id":0,"chat_active":[],"push_settings":{"sound":true,"disabled_until":0},"users":[{"id":12345678,"first_name":"Test","last_name":"User","is_closed":false,"can_access_closed":true,"sex":2,"screen_name":"testuser","photo_50":"https://pp.userapi.com/c123456/v123456/abc/def.jpg","photo_100":"https://pp.userapi.com/c123456/v123456/abc/def.jpg","online":1,"online_app":"2274003","online_mobile":1,"verified":0,"trending":0,"friend_status":3,"can_write_private_message":1,"can_send_friend_request":1,"is_favorite":false,"is_hidden_from_feed":false,"can_be_invited_group":true}],"profiles":[],"groups":[],"conversations":[],"unread_count":0,"important_count":0,"unread_count_ts":1640995200},"ts":1640995200}`
	jsonBytes := []byte(jsonPattern)
	combined := make([]byte, 0, len(request)+len(jsonBytes))
	combined = append(combined, request...)
	combined = append(combined, jsonBytes...)
	return combined
}

func (pe *ProductionEvasion) addVKPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data
	}
	padding := make([]byte, targetSize-len(data))
	for i := range padding {
		switch i % 3 {
		case 0:
			padding[i] = byte(32 + secureRandInt(95))
		case 1:
			padding[i] = byte(97 + secureRandInt(26))
		default:
			padding[i] = byte(48 + secureRandInt(10))
		}
	}
	return append(data, padding...)
}
