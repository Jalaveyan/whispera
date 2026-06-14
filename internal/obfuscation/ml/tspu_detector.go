package ml

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DPITypeNone           = 0
	DPITypeHTTPInspection = 1
	DPITypeTLSInspection  = 2
	DPITypeDeepPacket     = 3
	DPITypeProtocolFP     = 4
	DPITypeOKRuFP         = 5
	DPITypeTSPURST        = 6
	DPITypeTSPUThrottle   = 7
	DPITypeTSPUReplay     = 8
	DPITypeZombieTCP      = 9

	TSPUHistoryWindow    = 100
	TSPURSTThresholdMs   = 10
	TSPUThrottleBWKbps   = 200
	TSPUReplayWindowSec  = 60
	ZombieHistoryWindow  = 20
	ZombieTCPThresholdMs = 200
	ZombieTLSMinMs       = 3000
)

type TSPUDetector struct {
	mu sync.Mutex

	rstEvents []rstEvent
	rstIdx    int
	rstFull   bool

	bwSamples []bwSample
	bwIdx     int
	bwFull    bool

	seenHellos   map[uint64]time.Time
	helloCleanup time.Time

	zombieEvents []zombieEvent
	zombieIdx    int
	zombieFull   bool

	rstDetections      int64
	throttleDetections int64
	replayDetections   int64
	zombieDetections   int64
	totalChecks        int64
}

type zombieEvent struct {
	SNI       string
	TCPDur    time.Duration
	TLSDur    time.Duration
	Timestamp time.Time
	Confirmed bool
}

type rstEvent struct {
	SNI       string
	TimeToRST time.Duration
	Timestamp time.Time
	Blocked   bool
}

type bwSample struct {
	Transport   string
	BytesPerSec float64
	Timestamp   time.Time
}

func NewTSPUDetector() *TSPUDetector {
	return &TSPUDetector{
		rstEvents:    make([]rstEvent, TSPUHistoryWindow),
		bwSamples:    make([]bwSample, TSPUHistoryWindow),
		seenHellos:   make(map[uint64]time.Time),
		zombieEvents: make([]zombieEvent, ZombieHistoryWindow),
	}
}

func (d *TSPUDetector) RecordZombieTCP(sni string, tcpDur, tlsDur time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	confirmed := tcpDur < ZombieTCPThresholdMs*time.Millisecond &&
		tlsDur >= ZombieTLSMinMs*time.Millisecond

	d.zombieEvents[d.zombieIdx] = zombieEvent{
		SNI:       sni,
		TCPDur:    tcpDur,
		TLSDur:    tlsDur,
		Timestamp: time.Now(),
		Confirmed: confirmed,
	}
	d.zombieIdx = (d.zombieIdx + 1) % ZombieHistoryWindow
	if d.zombieIdx == 0 {
		d.zombieFull = true
	}

	if confirmed {
		atomic.AddInt64(&d.zombieDetections, 1)
	}
	atomic.AddInt64(&d.totalChecks, 1)
}

func (d *TSPUDetector) RecordRST(sni string, timeToRST time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	blocked := timeToRST < time.Duration(TSPURSTThresholdMs)*time.Millisecond
	d.rstEvents[d.rstIdx] = rstEvent{
		SNI:       sni,
		TimeToRST: timeToRST,
		Timestamp: time.Now(),
		Blocked:   blocked,
	}
	d.rstIdx = (d.rstIdx + 1) % TSPUHistoryWindow
	if d.rstIdx == 0 {
		d.rstFull = true
	}

	if blocked {
		atomic.AddInt64(&d.rstDetections, 1)
	}
	atomic.AddInt64(&d.totalChecks, 1)
}

func (d *TSPUDetector) RecordBandwidth(transport string, bytesPerSec float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.bwSamples[d.bwIdx] = bwSample{
		Transport:   transport,
		BytesPerSec: bytesPerSec,
		Timestamp:   time.Now(),
	}
	d.bwIdx = (d.bwIdx + 1) % TSPUHistoryWindow
	if d.bwIdx == 0 {
		d.bwFull = true
	}

	if bytesPerSec < TSPUThrottleBWKbps*1024/8 {
		atomic.AddInt64(&d.throttleDetections, 1)
	}
}

func (d *TSPUDetector) RecordClientHello(helloHash uint64, fromServer bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if now.Sub(d.helloCleanup) > time.Minute {
		cutoff := now.Add(-time.Duration(TSPUReplayWindowSec) * time.Second)
		for k, t := range d.seenHellos {
			if t.Before(cutoff) {
				delete(d.seenHellos, k)
			}
		}
		d.helloCleanup = now
	}

	if fromServer {
		if _, exists := d.seenHellos[helloHash]; exists {
			atomic.AddInt64(&d.replayDetections, 1)
			return true
		}
	} else {
		d.seenHellos[helloHash] = now
	}
	return false
}

func (d *TSPUDetector) DetectTSPU() (dpiType int, confidence float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	window := 5 * time.Minute

	rstCount := 0
	rstTotal := 0
	size := d.rstIdx
	if d.rstFull {
		size = TSPUHistoryWindow
	}
	for i := 0; i < size; i++ {
		ev := d.rstEvents[i]
		if now.Sub(ev.Timestamp) > window {
			continue
		}
		rstTotal++
		if ev.Blocked {
			rstCount++
		}
	}
	if rstTotal >= 3 && float64(rstCount)/float64(rstTotal) > 0.5 {
		conf := math.Min(float64(rstCount)/float64(rstTotal), 0.95)
		return DPITypeTSPURST, conf
	}

	throttled := 0
	bwTotal := 0
	bwSize := d.bwIdx
	if d.bwFull {
		bwSize = TSPUHistoryWindow
	}
	for i := 0; i < bwSize; i++ {
		s := d.bwSamples[i]
		if now.Sub(s.Timestamp) > window {
			continue
		}
		bwTotal++
		if s.BytesPerSec < TSPUThrottleBWKbps*1024/8 {
			throttled++
		}
	}
	if bwTotal >= 5 && float64(throttled)/float64(bwTotal) > 0.6 {
		conf := math.Min(float64(throttled)/float64(bwTotal), 0.90)
		return DPITypeTSPUThrottle, conf
	}

	replayCount := atomic.LoadInt64(&d.replayDetections)
	if replayCount > 0 {
		conf := math.Min(0.7+float64(replayCount)*0.05, 0.95)
		return DPITypeTSPUReplay, conf
	}

	zombieConfirmed := 0
	zombieTotal := 0
	zSize := d.zombieIdx
	if d.zombieFull {
		zSize = ZombieHistoryWindow
	}
	for i := 0; i < zSize; i++ {
		ev := d.zombieEvents[i]
		if now.Sub(ev.Timestamp) > window {
			continue
		}
		zombieTotal++
		if ev.Confirmed {
			zombieConfirmed++
		}
	}
	if zombieTotal >= 2 && float64(zombieConfirmed)/float64(zombieTotal) > 0.5 {
		conf := math.Min(0.6+float64(zombieConfirmed)*0.08, 0.95)
		return DPITypeZombieTCP, conf
	}

	return DPITypeNone, 0
}

func (d *TSPUDetector) GetTSPUFeatures() []float64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	features := make([]float64, 6)
	now := time.Now()
	window := 5 * time.Minute

	rstCount, rstTotal := 0, 0
	size := d.rstIdx
	if d.rstFull {
		size = TSPUHistoryWindow
	}
	for i := 0; i < size; i++ {
		if now.Sub(d.rstEvents[i].Timestamp) <= window {
			rstTotal++
			if d.rstEvents[i].Blocked {
				rstCount++
			}
		}
	}
	if rstTotal > 0 {
		features[0] = float64(rstCount) / float64(rstTotal)
	}

	if rstCount > 0 {
		var avgRST float64
		for i := 0; i < size; i++ {
			if d.rstEvents[i].Blocked && now.Sub(d.rstEvents[i].Timestamp) <= window {
				avgRST += float64(d.rstEvents[i].TimeToRST.Milliseconds())
			}
		}
		avgRST /= float64(rstCount)
		features[1] = 1.0 - math.Min(avgRST/100.0, 1.0)
	}

	throttled, bwTotal := 0, 0
	bwSize := d.bwIdx
	if d.bwFull {
		bwSize = TSPUHistoryWindow
	}
	for i := 0; i < bwSize; i++ {
		if now.Sub(d.bwSamples[i].Timestamp) <= window {
			bwTotal++
			if d.bwSamples[i].BytesPerSec < TSPUThrottleBWKbps*1024/8 {
				throttled++
			}
		}
	}
	if bwTotal > 0 {
		features[2] = float64(throttled) / float64(bwTotal)
	}

	if bwTotal > 0 {
		var avgBW float64
		for i := 0; i < bwSize; i++ {
			if now.Sub(d.bwSamples[i].Timestamp) <= window {
				avgBW += d.bwSamples[i].BytesPerSec
			}
		}
		avgBW /= float64(bwTotal)
		features[3] = math.Min(avgBW/(10*1024*1024), 1.0)
	}

	features[4] = math.Min(float64(atomic.LoadInt64(&d.replayDetections))/10.0, 1.0)

	features[5] = math.Min(features[0]*0.4+features[2]*0.3+features[4]*0.3, 1.0)

	zombieConfirmed, zombieTotal := 0, 0
	zSize := d.zombieIdx
	if d.zombieFull {
		zSize = ZombieHistoryWindow
	}
	for i := 0; i < zSize; i++ {
		if now.Sub(d.zombieEvents[i].Timestamp) <= window {
			zombieTotal++
			if d.zombieEvents[i].Confirmed {
				zombieConfirmed++
			}
		}
	}
	features = append(features, 0, 0)
	if zombieTotal > 0 {
		features[6] = float64(zombieConfirmed) / float64(zombieTotal)
	}
	if zombieConfirmed > 0 {
		var avgTCP float64
		n := 0
		for i := 0; i < zSize; i++ {
			ev := d.zombieEvents[i]
			if ev.Confirmed && now.Sub(ev.Timestamp) <= window {
				avgTCP += float64(ev.TCPDur.Milliseconds())
				n++
			}
		}
		if n > 0 {
			features[7] = 1.0 - math.Min(avgTCP/float64(n)/float64(ZombieTCPThresholdMs), 1.0)
		}
	}

	return features
}

func (d *TSPUDetector) Stats() map[string]interface{} {
	return map[string]interface{}{
		"rst_detections":      atomic.LoadInt64(&d.rstDetections),
		"throttle_detections": atomic.LoadInt64(&d.throttleDetections),
		"replay_detections":   atomic.LoadInt64(&d.replayDetections),
		"zombie_detections":   atomic.LoadInt64(&d.zombieDetections),
		"total_checks":        atomic.LoadInt64(&d.totalChecks),
	}
}

func TSPUCountermeasure(dpiType int) string {
	switch dpiType {
	case DPITypeTSPURST:
		return "cdn-ws"
	case DPITypeTSPUThrottle:
		return "vkvideo"
	case DPITypeTSPUReplay:
		return "reality"
	case DPITypeZombieTCP:
		return "meek"
	default:
		return ""
	}
}

func DPITypeName(dpiType int) string {
	switch dpiType {
	case DPITypeHTTPInspection:
		return "http_inspection"
	case DPITypeTLSInspection:
		return "tls_inspection"
	case DPITypeDeepPacket:
		return "deep_packet_inspection"
	case DPITypeProtocolFP:
		return "protocol_fingerprint"
	case DPITypeOKRuFP:
		return "ok_ru_fingerprint"
	case DPITypeTSPURST:
		return "tspu_rst_injection"
	case DPITypeTSPUThrottle:
		return "tspu_throttling"
	case DPITypeTSPUReplay:
		return "tspu_replay_probe"
	case DPITypeZombieTCP:
		return "zombie_tcp"
	default:
		return ""
	}
}
