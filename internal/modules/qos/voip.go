package qos

import (
	"context"
	"net"
	"sync"
	"time"
)

// VoIPQoS оптимизирует качество связи для VoIP приложений (Discord, Telegram, etc)
type VoIPQoS struct {
	mu               sync.RWMutex
	enabled          bool
	priorityQueue    *PriorityPacketQueue
	rtpDetector      *RTPDetector
	jitterBuffer     *JitterBuffer
	latencyTracker   *LatencyTracker
	bandwidthLimiter *BandwidthLimiter

	// Metrics
	metrics *VoIPMetrics
}

// VoIPMetrics хранит метрики VoIP сессии
type VoIPMetrics struct {
	mu                sync.RWMutex
	AverageLatency    time.Duration
	JitterMs          float64
	PacketLossPercent float64
	CurrentBitrate    int64
	TargetBitrate     int64
	ActiveConnections int
	DroppedPackets    int64
	ReorderedPackets  int64
	RTCPReportCount   int64
}

// PriorityPacketQueue управляет приоритетной очередью пакетов
type PriorityPacketQueue struct {
	mu           sync.Mutex
	rtpQueue     chan *QueuedPacket
	defaultQueue chan *QueuedPacket
	controlQueue chan *QueuedPacket
	maxRTPSize   int
	maxOtherSize int
}

// QueuedPacket представляет пакет в очереди
type QueuedPacket struct {
	Data      []byte
	Dest      net.Addr
	Timestamp time.Time
	Priority  PacketPriority
	RTTHint   time.Duration
}

// PacketPriority определяет приоритет пакета
type PacketPriority int

const (
	PriorityRTPVoice PacketPriority = iota
	PriorityRTPVideo
	PriorityRTCP
	PriorityData
	PriorityDefault
)

// RTPDetector определяет RTP пакеты и их характеристики
type RTPDetector struct {
	mu                sync.RWMutex
	rtpFlows          map[string]*RTPFlow
	discordSignatures map[uint16]bool
}

// RTPFlow отслеживает RTP поток
type RTPFlow struct {
	SSRC           uint32
	PayloadType    uint8
	SequenceNumber uint16
	Timestamp      uint32
	PacketCount    int64
	OctetCount     int64
	JitterBuf      *JitterBuffer
	LastPacketTime time.Time
	IsActive       bool
}

// JitterBuffer буфер джиттера для коррекции задержек
type JitterBuffer struct {
	mu             sync.Mutex
	buffer         map[uint16]*RTPPacket
	minJitter      time.Duration
	maxJitter      time.Duration
	currentJitter  time.Duration
	targetJitter   time.Duration
	lastSeqNum     uint16
	packetLoss     int64
	reorderedCount int64
}

// RTPPacket представляет RTP пакет в буфере
type RTPPacket struct {
	Data      []byte
	SeqNum    uint16
	Timestamp uint32
	RecvTime  time.Time
}

// LatencyTracker отслеживает задержку
type LatencyTracker struct {
	mu               sync.RWMutex
	samples          []time.Duration
	lastMeasure      time.Time
	averageLatency   time.Duration
	minLatency       time.Duration
	maxLatency       time.Duration
	measurementCount int64
}

// BandwidthLimiter ограничивает пропускную способность для VoIP
type BandwidthLimiter struct {
	mu           sync.RWMutex
	maxBitrate   int64
	currentRate  int64
	window       time.Duration
	lastReset    time.Time
	tokensPerSec int64
	tokens       int64
}

// NewVoIPQoS создает новый VoIP QoS модуль
func NewVoIPQoS() *VoIPQoS {
	return &VoIPQoS{
		enabled:       true,
		priorityQueue: NewPriorityPacketQueue(1000, 500),
		rtpDetector:   NewRTPDetector(),
		jitterBuffer:  NewJitterBuffer(),
		latencyTracker: &LatencyTracker{
			samples:    make([]time.Duration, 0, 100),
			minLatency: time.Hour,
		},
		bandwidthLimiter: &BandwidthLimiter{
			maxBitrate:   100 * 1024 * 1024, // 100 Mbps (effectively disabled)
			tokensPerSec: 100 * 1024 * 1024 / 8,
			window:       time.Second,
		},
		metrics: &VoIPMetrics{
			TargetBitrate: 512000, // 512 kbps target
		},
	}
}

// NewPriorityPacketQueue создает новую приоритетную очередь
func NewPriorityPacketQueue(rtpCapacity, otherCapacity int) *PriorityPacketQueue {
	return &PriorityPacketQueue{
		rtpQueue:     make(chan *QueuedPacket, rtpCapacity),
		defaultQueue: make(chan *QueuedPacket, otherCapacity),
		controlQueue: make(chan *QueuedPacket, 100),
		maxRTPSize:   rtpCapacity,
		maxOtherSize: otherCapacity,
	}
}

// Enqueue adds a packet to the appropriate queue
func (pq *PriorityPacketQueue) Enqueue(pkt *QueuedPacket) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	var targetQueue chan *QueuedPacket

	switch pkt.Priority {
	case PriorityRTPVoice, PriorityRTPVideo, PriorityRTCP:
		targetQueue = pq.rtpQueue
	case PriorityData, PriorityDefault:
		targetQueue = pq.defaultQueue
	default:
		targetQueue = pq.defaultQueue
	}

	// Non-blocking write to avoid stalling
	select {
	case targetQueue <- pkt:
	default:
		// Drop if full (Tail Drop)
		// For RTP we might want Head Drop but Tail Drop is simpler for now
	}
}

// Dequeue reads the next packet based on priority
func (pq *PriorityPacketQueue) Dequeue(ctx context.Context) (*QueuedPacket, error) {
	// Strict Priority: RTP > Default
	// We use select to prioritize

	// First check RTP (non-blocking)
	select {
	case pkt := <-pq.rtpQueue:
		return pkt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// WRR or strict priority?
	// Let's do a blocking wait on both, but prioritize RTP in the select
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case pkt := <-pq.rtpQueue:
		return pkt, nil
	case pkt := <-pq.defaultQueue:
		return pkt, nil
	}
}

// NewRTPDetector создает новый RTP детектор
func NewRTPDetector() *RTPDetector {
	return &RTPDetector{
		rtpFlows:          make(map[string]*RTPFlow),
		discordSignatures: makeDiscordSignatures(),
	}
}

// makeDiscordSignatures создает сигнатуры Discord
func makeDiscordSignatures() map[uint16]bool {
	// Discord использует порты в диапазоне 50000-65000 для RTP
	signatures := make(map[uint16]bool)
	for port := uint16(50000); port <= 65000; port++ {
		signatures[port] = true
	}
	return signatures
}

// NewJitterBuffer создает новый буфер джиттера
func NewJitterBuffer() *JitterBuffer {
	return &JitterBuffer{
		buffer:        make(map[uint16]*RTPPacket),
		minJitter:     5 * time.Millisecond,
		maxJitter:     50 * time.Millisecond,
		targetJitter:  20 * time.Millisecond,
		currentJitter: 15 * time.Millisecond,
	}
}

// ProcessPacket обрабатывает пакет с применением VoIP QoS
// pkt - данные для отправки (весь фрейм)
// inspectionData - данные для анализа (payload), если nil, используется pkt
func (v *VoIPQoS) ProcessPacket(ctx context.Context, pkt []byte, inspectionData []byte, dest net.Addr) (*QueuedPacket, error) {
	v.mu.RLock()
	if !v.enabled {
		v.mu.RUnlock()
		return &QueuedPacket{
			Data:      pkt,
			Dest:      dest,
			Timestamp: time.Now(),
			Priority:  PriorityDefault,
		}, nil
	}
	v.mu.RUnlock()

	dataToInspect := inspectionData
	if dataToInspect == nil {
		dataToInspect = pkt
	}

	// Определяем тип пакета
	priority := v.classifyPacket(dataToInspect, dest)

	// Детектируем RTP поток
	if priority == PriorityRTPVoice || priority == PriorityRTPVideo {
		v.rtpDetector.TrackFlow(dataToInspect)
	}

	// Измеряем задержку
	v.latencyTracker.Record(time.Since(time.Now()))

	// Проверяем bandwidth limit
	if !v.bandwidthLimiter.TryConsume(int64(len(pkt))) {
		v.metrics.mu.Lock()
		v.metrics.DroppedPackets++
		v.metrics.mu.Unlock()
		return nil, ErrBandwidthExceeded
	}

	queued := &QueuedPacket{
		Data:      pkt,
		Dest:      dest,
		Timestamp: time.Now(),
		Priority:  priority,
	}

	return queued, nil
}

// EnqueuePacket добавляет пакет в очередь
func (v *VoIPQoS) EnqueuePacket(pkt *QueuedPacket) {
	v.priorityQueue.Enqueue(pkt)
}

// ReadPacket читает пакет из очереди (блокирует до появления пакета)
func (v *VoIPQoS) ReadPacket(ctx context.Context) (*QueuedPacket, error) {
	return v.priorityQueue.Dequeue(ctx)
}

// classifyPacket классифицирует тип пакета
func (v *VoIPQoS) classifyPacket(pkt []byte, dest net.Addr) PacketPriority {
	if len(pkt) < 12 {
		return PriorityDefault
	}

	// Проверяем RTP маркер (версия 2, заголовок 12 байт)
	if (pkt[0] & 0xC0) == 0x80 { // RTP версия 2
		payloadType := pkt[1] & 0x7F

		// Discord voice обычно использует PT 111 (dynamic) для Opus
		// или PT 0-20 для других кодеков
		if payloadType >= 0 && payloadType <= 20 {
			return PriorityRTPVoice
		} else if payloadType >= 96 && payloadType <= 127 {
			// Dynamic payload types - обычно voice/video
			return PriorityRTPVoice
		}
	}

	// Проверяем RTCP (проверка флага P и RC)
	if (pkt[0]&0xC0) == 0x80 && len(pkt) >= 8 {
		pt := pkt[1] & 0x7F
		if pt >= 200 && pt <= 204 { // RTCP типы
			return PriorityRTCP
		}
	}

	// Проверяем UDP портам Discord
	if udpAddr, ok := dest.(*net.UDPAddr); ok {
		if v.rtpDetector.discordSignatures[uint16(udpAddr.Port)] {
			return PriorityRTPVoice
		}
	}

	return PriorityDefault
}

// GetMetrics возвращает текущие метрики VoIP
func (v *VoIPQoS) GetMetrics() *VoIPMetrics {
	v.metrics.mu.Lock()
	defer v.metrics.mu.Unlock()

	// Обновляем средние значения
	v.metrics.AverageLatency = v.latencyTracker.GetAverageLatency()
	v.metrics.JitterMs = v.latencyTracker.GetJitter()

	return v.metrics
}

// SetBandwidthLimit устанавливает лимит пропускной способности (в bps)
func (v *VoIPQoS) SetBandwidthLimit(bitrate int64) {
	v.bandwidthLimiter.mu.Lock()
	defer v.bandwidthLimiter.mu.Unlock()
	v.bandwidthLimiter.maxBitrate = bitrate
	v.bandwidthLimiter.tokensPerSec = bitrate / 8
}

// Enable включает VoIP QoS
func (v *VoIPQoS) Enable() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.enabled = true
}

// Disable отключает VoIP QoS
func (v *VoIPQoS) Disable() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.enabled = false
}

// --- RTPDetector methods ---

// TrackFlow отслеживает RTP поток
func (rd *RTPDetector) TrackFlow(pkt []byte) {
	if len(pkt) < 12 {
		return
	}

	rd.mu.Lock()
	defer rd.mu.Unlock()

	// Извлекаем SSRC (bytes 8-11)
	ssrc := uint32(pkt[8])<<24 | uint32(pkt[9])<<16 | uint32(pkt[10])<<8 | uint32(pkt[11])

	flowKey := string(pkt[:12]) // Use header as key
	if flow, exists := rd.rtpFlows[flowKey]; exists {
		flow.PacketCount++
		flow.OctetCount += int64(len(pkt))
		flow.LastPacketTime = time.Now()
	} else {
		rd.rtpFlows[flowKey] = &RTPFlow{
			SSRC:           ssrc,
			PayloadType:    pkt[1] & 0x7F,
			SequenceNumber: uint16(pkt[2])<<8 | uint16(pkt[3]),
			Timestamp:      uint32(pkt[4])<<24 | uint32(pkt[5])<<16 | uint32(pkt[6])<<8 | uint32(pkt[7]),
			PacketCount:    1,
			OctetCount:     int64(len(pkt)),
			IsActive:       true,
			LastPacketTime: time.Now(),
		}
	}
}

// --- LatencyTracker methods ---

// Record записывает измерение задержки
func (lt *LatencyTracker) Record(latency time.Duration) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	lt.samples = append(lt.samples, latency)
	if len(lt.samples) > 100 {
		lt.samples = lt.samples[1:]
	}

	if latency < lt.minLatency {
		lt.minLatency = latency
	}
	if latency > lt.maxLatency {
		lt.maxLatency = latency
	}

	lt.measurementCount++
}

// GetAverageLatency возвращает среднюю задержку
func (lt *LatencyTracker) GetAverageLatency() time.Duration {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	if len(lt.samples) == 0 {
		return 0
	}

	var sum time.Duration
	for _, sample := range lt.samples {
		sum += sample
	}
	return sum / time.Duration(len(lt.samples))
}

// GetJitter возвращает джиттер в миллисекундах
func (lt *LatencyTracker) GetJitter() float64 {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	if len(lt.samples) < 2 {
		return 0
	}

	var variance float64
	avg := lt.GetAverageLatency()
	avgMs := float64(avg.Milliseconds())

	for _, sample := range lt.samples {
		sampleMs := float64(sample.Milliseconds())
		diff := sampleMs - avgMs
		variance += diff * diff
	}
	variance /= float64(len(lt.samples))

	return variance
}

// --- BandwidthLimiter methods ---

// TryConsume пытается потребить токены для пакета
func (bl *BandwidthLimiter) TryConsume(bytes int64) bool {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	now := time.Now()
	if now.Sub(bl.lastReset) >= bl.window {
		bl.tokens = bl.tokensPerSec
		bl.lastReset = now
		bl.currentRate = 0
	}

	// Token bucket algorithm
	tokensNeeded := (bytes * 8) // Convert to bits
	if bl.tokens >= tokensNeeded {
		bl.tokens -= tokensNeeded
		bl.currentRate += tokensNeeded
		return true
	}
	return false
}
