package qos

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// DiscordDetector автоматически обнаруживает Discord VoIP трафик
type DiscordDetector struct {
	mu                sync.RWMutex
	activeFlows       map[string]*DiscordFlow
	detectionCriteria *DetectionCriteria
	autoOptimizeVoIP  bool
	lastCleanupTime   time.Time
}

// DiscordFlow отслеживает Discord VoIP поток
type DiscordFlow struct {
	SSRC             uint32
	LocalPort        uint16
	RemoteAddr       net.Addr
	FirstPacketTime  time.Time
	LastPacketTime   time.Time
	PacketCount      int64
	BytesTransferred int64
	IsVoice          bool
	CodecHint        string // opus, pcm, etc
	ConfidenceScore  float64
	IsActive         bool
}

// DetectionCriteria определяет параметры для обнаружения Discord voice
type DetectionCriteria struct {
	// Port-based detection
	PortRangeStart uint16 // Usually 50000
	PortRangeEnd   uint16 // Usually 65000

	// Packet size heuristics
	MinVoicePacketSize   int // ~40 bytes (Opus)
	MaxVoicePacketSize   int // ~400 bytes
	TypicalVoicePackSize int // ~120-200 bytes

	// RTP payload type hints
	OpusPayloadType uint8 // 111 (dynamic), 0-20 (static)

	// Flow characteristics
	MinPacketsPerSecond int           // 50 packets/sec (20ms frame)
	MaxPacketsPerSecond int           // 100 packets/sec
	MinFlowDuration     time.Duration // 2 seconds

	// Bitrate bounds
	MinVoiceBitrate int64 // 20 kbps
	MaxVoiceBitrate int64 // 320 kbps
}

// NewDiscordDetector создает новый детектор Discord
func NewDiscordDetector() *DiscordDetector {
	return &DiscordDetector{
		activeFlows: make(map[string]*DiscordFlow),
		detectionCriteria: &DetectionCriteria{
			PortRangeStart:       50000,
			PortRangeEnd:         65000,
			MinVoicePacketSize:   30,
			MaxVoicePacketSize:   500,
			TypicalVoicePackSize: 120,
			OpusPayloadType:      111,
			MinPacketsPerSecond:  40,
			MaxPacketsPerSecond:  120,
			MinFlowDuration:      2 * time.Second,
			MinVoiceBitrate:      20000,  // 20 kbps
			MaxVoiceBitrate:      320000, // 320 kbps
		},
		autoOptimizeVoIP: true,
		lastCleanupTime:  time.Now(),
	}
}

// AnalyzePacket анализирует пакет для обнаружения Discord VoIP
func (dd *DiscordDetector) AnalyzePacket(pkt []byte, srcAddr, dstAddr net.Addr) *DiscordFlow {
	if len(pkt) < 28 { // Минимум RTP заголовок 12 + IP + UDP
		return nil
	}

	dd.mu.Lock()
	defer dd.mu.Unlock()

	// Проверяем порт (Discord обычно использует 50000-65000)
	dstUDP, ok := dstAddr.(*net.UDPAddr)
	if !ok {
		return nil
	}

	port := uint16(dstUDP.Port)
	if !dd.isDiscordPort(port) {
		return nil
	}

	// Извлекаем RTP заголовок
	rtpHeader := pkt[:12]
	version := (rtpHeader[0] >> 6) & 0x3
	if version != 2 {
		return nil // Не RTP версия 2
	}

	// Извлекаем ключевые поля RTP
	payloadType := rtpHeader[1] & 0x7F
	ssrc := binary.BigEndian.Uint32(rtpHeader[8:12])
	// seqNum := binary.BigEndian.Uint16(rtpHeader[2:4]) // Unused

	flowKey := dd.getFlowKey(srcAddr, port, ssrc)

	flow, exists := dd.activeFlows[flowKey]
	if !exists {
		flow = &DiscordFlow{
			SSRC:            ssrc,
			LocalPort:       port,
			RemoteAddr:      srcAddr,
			FirstPacketTime: time.Now(),
			LastPacketTime:  time.Now(),
			IsActive:        true,
		}
		dd.activeFlows[flowKey] = flow
	}

	flow.LastPacketTime = time.Now()
	flow.PacketCount++
	flow.BytesTransferred += int64(len(pkt))

	// Проверяем характеристики голоса
	packetSize := len(pkt) - 12 // Вычитаем RTP заголовок
	flow.IsVoice = dd.isVoicePacket(packetSize, payloadType)

	if payloadType == dd.detectionCriteria.OpusPayloadType ||
		(payloadType <= 20) {
		flow.CodecHint = "opus"
	}

	// Вычисляем confidence score
	flow.ConfidenceScore = dd.calculateConfidenceScore(flow)

	return flow
}

// IsDiscordVoIP определяет, является ли это Discord VoIP трафиком
func (dd *DiscordDetector) IsDiscordVoIP(flowKey string) bool {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	flow, exists := dd.activeFlows[flowKey]
	if !exists {
		return false
	}

	// Требуется высокий confidence score (> 0.7) и как минимум несколько пакетов
	return flow.ConfidenceScore > 0.7 &&
		flow.PacketCount >= 10 &&
		flow.IsVoice
}

// GetAllActiveFlows возвращает все активные потоки
func (dd *DiscordDetector) GetAllActiveFlows() map[string]*DiscordFlow {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	result := make(map[string]*DiscordFlow)
	for k, v := range dd.activeFlows {
		result[k] = v
	}
	return result
}

// CleanupInactiveFlows удаляет неактивные потоки
func (dd *DiscordDetector) CleanupInactiveFlows(timeout time.Duration) {
	dd.mu.Lock()
	defer dd.mu.Unlock()

	now := time.Now()
	for key, flow := range dd.activeFlows {
		if now.Sub(flow.LastPacketTime) > timeout {
			delete(dd.activeFlows, key)
		}
	}
	dd.lastCleanupTime = now
}

// --- Private methods ---

// isDiscordPort проверяет, находится ли порт в диапазоне Discord
func (dd *DiscordDetector) isDiscordPort(port uint16) bool {
	return port >= dd.detectionCriteria.PortRangeStart &&
		port <= dd.detectionCriteria.PortRangeEnd
}

// isVoicePacket проверяет, похож ли пакет на голос
func (dd *DiscordDetector) isVoicePacket(size int, payloadType uint8) bool {
	// Проверяем размер пакета
	if size < dd.detectionCriteria.MinVoicePacketSize ||
		size > dd.detectionCriteria.MaxVoicePacketSize {
		return false
	}

	// Проверяем тип payload
	if payloadType == dd.detectionCriteria.OpusPayloadType {
		return true // Opus для голоса
	}

	// Типы 0-20 могут быть голосом (зависит от конфигурации)
	if payloadType >= 0 && payloadType <= 20 {
		return true
	}

	return false
}

// calculateConfidenceScore вычисляет уверенность в том, что это голос
func (dd *DiscordDetector) calculateConfidenceScore(flow *DiscordFlow) float64 {
	if flow.PacketCount == 0 {
		return 0.0
	}

	score := 0.0

	// Размер и характеристики пакетов (30%)
	avgPacketSize := flow.BytesTransferred / flow.PacketCount
	if avgPacketSize >= int64(dd.detectionCriteria.MinVoicePacketSize) &&
		avgPacketSize <= int64(dd.detectionCriteria.MaxVoicePacketSize) {
		score += 0.3
	}

	// Темп пакетов (30%)
	if flow.PacketCount > 0 {
		duration := flow.LastPacketTime.Sub(flow.FirstPacketTime)
		if duration > 0 {
			pps := int(flow.PacketCount) / int(duration.Seconds())
			if pps >= dd.detectionCriteria.MinPacketsPerSecond &&
				pps <= dd.detectionCriteria.MaxPacketsPerSecond {
				score += 0.3
			}
		}
	}

	// Длительность потока (20%)
	duration := flow.LastPacketTime.Sub(flow.FirstPacketTime)
	if duration >= dd.detectionCriteria.MinFlowDuration {
		score += 0.2
	}

	// Codec hint (20%)
	if flow.CodecHint == "opus" {
		score += 0.2
	}

	return score
}

// getFlowKey генерирует уникальный ключ для потока
func (dd *DiscordDetector) getFlowKey(addr net.Addr, port uint16, ssrc uint32) string {
	return fmt.Sprintf("%s:%d:%d", addr.String(), port, ssrc)
}

// RecommendOptimization рекомендует применить оптимизацию для потока
func (dd *DiscordDetector) RecommendOptimization(flowKey string) bool {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	flow, exists := dd.activeFlows[flowKey]
	if !exists {
		return false
	}

	// Применить оптимизацию, если:
	// 1. Это похоже на голос
	// 2. High confidence score
	// 3. Достаточно данных
	return flow.IsVoice &&
		flow.ConfidenceScore > 0.7 &&
		flow.PacketCount > 20 &&
		dd.autoOptimizeVoIP
}

// GetFlowStats возвращает статистику потока
func (dd *DiscordDetector) GetFlowStats(flowKey string) *DiscordFlowStats {
	dd.mu.RLock()
	defer dd.mu.RUnlock()

	flow, exists := dd.activeFlows[flowKey]
	if !exists {
		return nil
	}

	duration := flow.LastPacketTime.Sub(flow.FirstPacketTime)
	bitrate := int64(0)
	if duration > 0 {
		bitrate = (flow.BytesTransferred * 8) / int64(duration.Seconds())
	}

	return &DiscordFlowStats{
		SSRC:             flow.SSRC,
		PacketCount:      flow.PacketCount,
		BytesTransferred: flow.BytesTransferred,
		Duration:         duration,
		Bitrate:          bitrate,
		IsVoice:          flow.IsVoice,
		Confidence:       flow.ConfidenceScore,
	}
}

// DiscordFlowStats статистика потока
type DiscordFlowStats struct {
	SSRC             uint32
	PacketCount      int64
	BytesTransferred int64
	Duration         time.Duration
	Bitrate          int64
	IsVoice          bool
	Confidence       float64
}
