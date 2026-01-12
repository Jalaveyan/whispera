// Package behavioral - Cover Traffic Generator
// Generates realistic cover traffic to mask real VPN activity
package behavioral

import (
	"crypto/rand"
	"sync"
	"sync/atomic"
	"time"
)

// CoverTrafficGenerator generates realistic cover traffic based on messenger profiles
type CoverTrafficGenerator struct {
	profile  *MessengerProfile
	engine   *BehaviorEngine
	mu       sync.RWMutex
	running  atomic.Bool
	stopCh   chan struct{}
	packetCh chan CoverPacket

	// Statistics
	stats CoverStats
}

// CoverPacket represents a generated cover packet
type CoverPacket struct {
	Data      []byte
	Size      int
	Delay     time.Duration
	Direction string // "inbound" or "outbound"
	Purpose   string // "heartbeat", "ack", "presence", "cover"
}

// CoverStats holds cover traffic statistics
type CoverStats struct {
	PacketsGenerated uint64
	BytesGenerated   uint64
	HeartbeatsSent   uint64
	CoverSent        uint64
}

// NewCoverTrafficGenerator creates a new cover traffic generator
func NewCoverTrafficGenerator(profile *MessengerProfile) *CoverTrafficGenerator {
	return &CoverTrafficGenerator{
		profile:  profile,
		engine:   NewBehaviorEngine(profile),
		stopCh:   make(chan struct{}),
		packetCh: make(chan CoverPacket, 100),
	}
}

// Start starts the cover traffic generation
func (g *CoverTrafficGenerator) Start() {
	if g.running.Swap(true) {
		return // Already running
	}

	go g.generateLoop()
	go g.heartbeatLoop()
	go g.backgroundConnectionsLoop()
}

// Stop stops the cover traffic generation
func (g *CoverTrafficGenerator) Stop() {
	if !g.running.Swap(false) {
		return // Not running
	}
	close(g.stopCh)
}

// GetPacketChannel returns the channel for receiving cover packets
func (g *CoverTrafficGenerator) GetPacketChannel() <-chan CoverPacket {
	return g.packetCh
}

// GetStats returns current statistics
func (g *CoverTrafficGenerator) GetStats() CoverStats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.stats
}

// generateLoop is the main cover traffic generation loop
func (g *CoverTrafficGenerator) generateLoop() {
	for {
		select {
		case <-g.stopCh:
			return
		default:
		}

		// Get next delay from behavioral engine
		delay := g.engine.NextPacketDelay()

		select {
		case <-g.stopCh:
			return
		case <-time.After(delay):
			// Check if we should generate cover traffic based on state
			state := g.engine.GetCurrentState()
			if g.shouldGenerateCover(state) {
				packet := g.generateCoverPacket()
				g.sendPacket(packet)
			}

			// Advance state machine
			g.engine.TransitionState()
		}
	}
}

// heartbeatLoop generates periodic heartbeat packets
func (g *CoverTrafficGenerator) heartbeatLoop() {
	g.mu.RLock()
	hbConfig := g.profile.Application.Heartbeat
	g.mu.RUnlock()

	// Calculate interval with jitter
	interval := hbConfig.BackgroundInterval
	jitterRange := float64(interval) * hbConfig.BackgroundJitter

	for {
		// Add jitter
		jitter := time.Duration(sampleUniform(-jitterRange, jitterRange))
		actualInterval := interval + jitter
		if actualInterval < time.Second {
			actualInterval = time.Second
		}

		select {
		case <-g.stopCh:
			return
		case <-time.After(actualInterval):
			packet := g.generateHeartbeatPacket()
			g.sendPacket(packet)

			g.mu.Lock()
			g.stats.HeartbeatsSent++
			g.mu.Unlock()
		}
	}
}

// backgroundConnectionsLoop simulates background connections
func (g *CoverTrafficGenerator) backgroundConnectionsLoop() {
	g.mu.RLock()
	bgConfig := g.profile.Context.Background
	g.mu.RUnlock()

	for _, conn := range bgConfig.Connections {
		go g.simulateBackgroundConnection(conn)
	}

	<-g.stopCh
}

// simulateBackgroundConnection simulates a single background connection
func (g *CoverTrafficGenerator) simulateBackgroundConnection(conn BackgroundConnection) {
	for {
		select {
		case <-g.stopCh:
			return
		case <-time.After(conn.Interval):
			size := int(conn.Size.Sample())
			if size < 16 {
				size = 16
			}

			packet := CoverPacket{
				Data:      g.generateRandomData(size),
				Size:      size,
				Delay:     0,
				Direction: "outbound",
				Purpose:   conn.Purpose,
			}
			g.sendPacket(packet)
		}
	}
}

// shouldGenerateCover determines if cover traffic should be generated
func (g *CoverTrafficGenerator) shouldGenerateCover(state string) bool {
	// Generate cover during idle states to maintain traffic patterns
	switch state {
	case "idle":
		// 30% chance during idle
		return sampleUniform(0, 1) < 0.30
	case "typing":
		// 10% chance during typing (most traffic is real)
		return sampleUniform(0, 1) < 0.10
	case "receiving":
		// 20% chance during receiving
		return sampleUniform(0, 1) < 0.20
	default:
		// Low chance for other states
		return sampleUniform(0, 1) < 0.05
	}
}

// generateCoverPacket generates a realistic cover packet
func (g *CoverTrafficGenerator) generateCoverPacket() CoverPacket {
	// Get recommended size from behavioral engine
	size := g.engine.NextPacketSize()
	if size < 16 {
		size = 16
	}
	if size > 4096 {
		size = 4096
	}

	return CoverPacket{
		Data:      g.generateRandomData(size),
		Size:      size,
		Delay:     0,
		Direction: "outbound",
		Purpose:   "cover",
	}
}

// generateHeartbeatPacket generates a heartbeat packet
func (g *CoverTrafficGenerator) generateHeartbeatPacket() CoverPacket {
	// Heartbeats are typically small
	size := 32 + int(sampleUniform(0, 32))

	return CoverPacket{
		Data:      g.generateRandomData(size),
		Size:      size,
		Delay:     0,
		Direction: "outbound",
		Purpose:   "heartbeat",
	}
}

// generateRandomData generates random bytes for cover traffic
func (g *CoverTrafficGenerator) generateRandomData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// sendPacket sends a packet to the channel
func (g *CoverTrafficGenerator) sendPacket(packet CoverPacket) {
	select {
	case g.packetCh <- packet:
		g.mu.Lock()
		g.stats.PacketsGenerated++
		g.stats.BytesGenerated += uint64(packet.Size)
		if packet.Purpose == "cover" {
			g.stats.CoverSent++
		}
		g.mu.Unlock()
	default:
		// Channel full, drop packet
	}
}

// =============================================================================
// DAILY PATTERN COVER TRAFFIC
// =============================================================================

// DailyPatternGenerator generates cover traffic following daily activity patterns
type DailyPatternGenerator struct {
	*CoverTrafficGenerator
	hourlyMultiplier float64
}

// NewDailyPatternGenerator creates a cover generator with daily patterns
func NewDailyPatternGenerator(profile *MessengerProfile) *DailyPatternGenerator {
	return &DailyPatternGenerator{
		CoverTrafficGenerator: NewCoverTrafficGenerator(profile),
		hourlyMultiplier:      1.0,
	}
}

// Start starts with daily pattern awareness
func (g *DailyPatternGenerator) Start() {
	g.CoverTrafficGenerator.Start()
	go g.updateHourlyMultiplierLoop()
}

// updateHourlyMultiplierLoop updates the hourly activity multiplier
func (g *DailyPatternGenerator) updateHourlyMultiplierLoop() {
	for {
		select {
		case <-g.stopCh:
			return
		case <-time.After(time.Minute):
			hour := time.Now().Hour()

			g.mu.Lock()
			g.hourlyMultiplier = g.profile.Timing.DailyPattern.HourlyActivity[hour]

			// Apply weekend modifier
			weekday := time.Now().Weekday()
			if weekday == time.Saturday || weekday == time.Sunday {
				g.hourlyMultiplier *= g.profile.Timing.DailyPattern.WeekendModifier
			}
			g.mu.Unlock()
		}
	}
}

// GetActivityMultiplier returns current activity level
func (g *DailyPatternGenerator) GetActivityMultiplier() float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.hourlyMultiplier
}

// =============================================================================
// ADAPTIVE COVER TRAFFIC
// =============================================================================

// AdaptiveCoverGenerator adjusts cover traffic based on real traffic
type AdaptiveCoverGenerator struct {
	*DailyPatternGenerator

	// Real traffic tracking
	realPacketsPerMin  float64
	coverRatio         float64 // Desired cover:real ratio
	lastRealPacketTime time.Time
}

// NewAdaptiveCoverGenerator creates an adaptive cover generator
func NewAdaptiveCoverGenerator(profile *MessengerProfile, coverRatio float64) *AdaptiveCoverGenerator {
	if coverRatio <= 0 {
		coverRatio = 0.3 // Default 30% cover traffic
	}

	return &AdaptiveCoverGenerator{
		DailyPatternGenerator: NewDailyPatternGenerator(profile),
		coverRatio:            coverRatio,
		lastRealPacketTime:    time.Now(),
	}
}

// OnRealPacket notifies the generator of real traffic
func (g *AdaptiveCoverGenerator) OnRealPacket() {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(g.lastRealPacketTime).Minutes()
	if elapsed > 0 {
		// Exponential moving average
		g.realPacketsPerMin = 0.9*g.realPacketsPerMin + 0.1*(1.0/elapsed)
	}
	g.lastRealPacketTime = now
}

// GetTargetCoverRate returns the target cover packets per minute
func (g *AdaptiveCoverGenerator) GetTargetCoverRate() float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	targetRate := g.realPacketsPerMin * g.coverRatio * g.hourlyMultiplier

	// Clamp to reasonable bounds
	if targetRate < 0.1 {
		targetRate = 0.1 // Minimum 0.1 packets/min
	}
	if targetRate > 60 {
		targetRate = 60 // Maximum 60 packets/min
	}

	return targetRate
}
