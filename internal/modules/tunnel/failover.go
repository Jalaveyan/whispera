package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type FailoverStrategy int

const (
	StrategyDirect FailoverStrategy = iota
	StrategyDomainFront
	StrategyCDNWorker
	StrategyAlternateIP
	StrategyTorBridge
	StrategyVKWebRTC
	StrategyMeek
	StrategySplitHTTP
	StrategyTGBot
)

func (s FailoverStrategy) String() string {
	switch s {
	case StrategyDirect:
		return "direct"
	case StrategyDomainFront:
		return "domain_front"
	case StrategyCDNWorker:
		return "cdn_worker"
	case StrategyAlternateIP:
		return "alternate_ip"
	case StrategyTorBridge:
		return "tor_bridge"
	case StrategyVKWebRTC:
		return "vk_webrtc"
	case StrategyMeek:
		return "meek"
	case StrategySplitHTTP:
		return "split_http"
	case StrategyTGBot:
		return "tg_bot"
	default:
		return "unknown"
	}
}

type BlockDetectionState int

const (
	BlockNone BlockDetectionState = iota
	BlockSuspected
	BlockConfirmed
	BlockRecovering
)

type FailoverConfig struct {
	Enabled           bool
	ProbeInterval     time.Duration
	ProbeTimeout      time.Duration
	FailThreshold     int
	RecoveryThreshold int
	AlternateIPs      []string
	CDNWorkerURLs     []string
	DomainFrontHosts  []string
	MeekURLs          []string
	Strategies        []FailoverStrategy
	MaxParallelProbes int
}

func DefaultFailoverConfig() *FailoverConfig {
	return &FailoverConfig{
		Enabled:       true,
		ProbeInterval: 30 * time.Second,
		ProbeTimeout:  5 * time.Second,
		FailThreshold: 3,
		RecoveryThreshold: 2,
		Strategies: []FailoverStrategy{
			StrategyDomainFront,
			StrategyCDNWorker,
			StrategyAlternateIP,
			StrategyMeek,
			StrategySplitHTTP,
		},
		MaxParallelProbes: 3,
	}
}

type FailoverManager struct {
	mu     sync.RWMutex
	config *FailoverConfig

	blockState      BlockDetectionState
	activeStrategy  FailoverStrategy
	failCount       int
	successCount    int
	lastProbe       time.Time
	lastBlockTime   time.Time
	strategyIdx     int
	strategyResults map[FailoverStrategy]*strategyStats

	probeTarget string

	stopCh   chan struct{}
	stopOnce sync.Once

	totalFailovers   uint64
	totalProbes      uint64
	totalBlocks      uint64
	currentLatency   int64
}

type strategyStats struct {
	attempts  int
	successes int
	avgMs     float64
	lastUsed  time.Time
	lastOk    bool
}

func NewFailoverManager(cfg *FailoverConfig) *FailoverManager {
	if cfg == nil {
		cfg = DefaultFailoverConfig()
	}

	fm := &FailoverManager{
		config:          cfg,
		blockState:      BlockNone,
		activeStrategy:  StrategyDirect,
		strategyResults: make(map[FailoverStrategy]*strategyStats),
		stopCh:          make(chan struct{}),
	}

	for _, s := range cfg.Strategies {
		fm.strategyResults[s] = &strategyStats{}
	}

	return fm
}

func (fm *FailoverManager) Start(probeTarget string) {
	fm.mu.Lock()
	fm.probeTarget = probeTarget
	fm.mu.Unlock()

	if fm.config.Enabled && probeTarget != "" {
		go fm.probeLoop()
	}
}

func (fm *FailoverManager) Stop() {
	fm.stopOnce.Do(func() { close(fm.stopCh) })
}

func (fm *FailoverManager) GetBlockState() BlockDetectionState {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return fm.blockState
}

func (fm *FailoverManager) GetActiveStrategy() FailoverStrategy {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return fm.activeStrategy
}

func (fm *FailoverManager) ReportSuccess() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.failCount = 0
	fm.successCount++

	if fm.blockState == BlockRecovering && fm.successCount >= fm.config.RecoveryThreshold {
		fm.blockState = BlockNone
		fm.activeStrategy = StrategyDirect
		log.Info("Block recovery confirmed, reverting to direct connection")
	}
}

func (fm *FailoverManager) ReportFailure() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.successCount = 0
	fm.failCount++

	if fm.failCount >= fm.config.FailThreshold {
		switch fm.blockState {
		case BlockNone:
			fm.blockState = BlockSuspected
			log.Warn("IP block suspected after %d failures", fm.failCount)
		case BlockSuspected:
			fm.blockState = BlockConfirmed
			fm.lastBlockTime = time.Now()
			atomic.AddUint64(&fm.totalBlocks, 1)
			log.Warn("IP block confirmed, initiating failover")
			fm.activateNextStrategy()
		case BlockConfirmed, BlockRecovering:
		}
	}
}

func (fm *FailoverManager) GetDialOverride(ctx context.Context, tunnelMgr *Manager) (string, string, bool) {
	fm.mu.RLock()
	state := fm.blockState
	strategy := fm.activeStrategy
	fm.mu.RUnlock()

	if state == BlockNone || strategy == StrategyDirect {
		return "", "", false
	}

	switch strategy {
	case StrategyAlternateIP:
		if len(fm.config.AlternateIPs) > 0 {
			ip := fm.pickAlternateIP()
			return ip, "tcp", true
		}
	case StrategyDomainFront:
		if len(fm.config.DomainFrontHosts) > 0 {
			host := fm.pickDomainFrontHost()
			tunnelMgr.config.DomainFrontHost = host
			tunnelMgr.config.Transport = "domainfront"
			return "", "", false
		}
	case StrategyCDNWorker:
		if len(fm.config.CDNWorkerURLs) > 0 {
			url := fm.pickCDNWorkerURL()
			tunnelMgr.config.CDNWorkerURL = url
			tunnelMgr.config.Transport = "cdnworker"
			return "", "", false
		}
	case StrategyMeek:
		if len(fm.config.MeekURLs) > 0 {
			tunnelMgr.config.Transport = "meek"
			return "", "", false
		}
	case StrategySplitHTTP:
		tunnelMgr.config.Transport = "splithttp"
		return "", "", false
	case StrategyTGBot:
		tunnelMgr.config.Transport = "tgbot"
		return "", "", false
	case StrategyVKWebRTC:
		tunnelMgr.config.Transport = "vkwebrtc"
		return "", "", false
	case StrategyDirect, StrategyTorBridge:
	}

	return "", "", false
}

func (fm *FailoverManager) activateNextStrategy() {
	if len(fm.config.Strategies) == 0 {
		return
	}

	best := fm.pickBestStrategy()
	fm.activeStrategy = best
	atomic.AddUint64(&fm.totalFailovers, 1)

	stats := fm.strategyResults[best]
	stats.lastUsed = time.Now()
	stats.attempts++

	log.Info("Failover activated: strategy=%s (attempts=%d, success_rate=%.1f%%)",
		best, stats.attempts, fm.strategySuccessRate(stats))
}

func (fm *FailoverManager) pickBestStrategy() FailoverStrategy {
	var best FailoverStrategy
	bestScore := -1.0

	for _, s := range fm.config.Strategies {
		if s == StrategyDirect {
			continue
		}
		stats := fm.strategyResults[s]
		score := fm.scoreStrategy(s, stats)
		if score > bestScore {
			bestScore = score
			best = s
		}
	}

	if bestScore < 0 {
		fm.strategyIdx = (fm.strategyIdx + 1) % len(fm.config.Strategies)
		return fm.config.Strategies[fm.strategyIdx]
	}

	return best
}

func (fm *FailoverManager) scoreStrategy(s FailoverStrategy, stats *strategyStats) float64 {
	score := 50.0

	if stats.attempts > 0 {
		rate := float64(stats.successes) / float64(stats.attempts)
		score += rate * 30
	}

	if stats.avgMs > 0 && stats.avgMs < 5000 {
		score += (1.0 - stats.avgMs/5000) * 20
	}

	switch s {
	case StrategyDomainFront:
		score += 10
	case StrategyCDNWorker:
		score += 8
	case StrategyMeek:
		score += 5
	case StrategyAlternateIP:
		score += 7
	case StrategySplitHTTP:
		score += 6
	case StrategyVKWebRTC:
		score += 4
	case StrategyTGBot:
		score += 3
	case StrategyDirect, StrategyTorBridge:
	}

	if !stats.lastUsed.IsZero() {
		elapsed := time.Since(stats.lastUsed)
		if elapsed < 5*time.Minute {
			if !stats.lastOk {
				score -= 20
			}
		}
	}

	return score
}

func (fm *FailoverManager) strategySuccessRate(stats *strategyStats) float64 {
	if stats.attempts == 0 {
		return 0
	}
	return float64(stats.successes) / float64(stats.attempts) * 100
}

func (fm *FailoverManager) RecordStrategyResult(s FailoverStrategy, ok bool, latencyMs float64) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	stats, exists := fm.strategyResults[s]
	if !exists {
		stats = &strategyStats{}
		fm.strategyResults[s] = stats
	}

	stats.attempts++
	stats.lastUsed = time.Now()
	stats.lastOk = ok

	if ok {
		stats.successes++
		if stats.avgMs == 0 {
			stats.avgMs = latencyMs
		} else {
			stats.avgMs = stats.avgMs*0.7 + latencyMs*0.3
		}
		atomic.StoreInt64(&fm.currentLatency, int64(latencyMs))
	}
}

func (fm *FailoverManager) probeLoop() {
	ticker := time.NewTicker(fm.config.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-fm.stopCh:
			return
		case <-ticker.C:
			fm.runProbe()
		}
	}
}

func (fm *FailoverManager) runProbe() {
	fm.mu.RLock()
	target := fm.probeTarget
	state := fm.blockState
	fm.mu.RUnlock()

	if target == "" {
		return
	}

	atomic.AddUint64(&fm.totalProbes, 1)

	reachable := fm.probeTarget_(target)

	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.lastProbe = time.Now()

	if reachable {
		if state == BlockConfirmed || state == BlockSuspected {
			fm.blockState = BlockRecovering
			fm.successCount = 1
			log.Info("Direct connectivity restored, entering recovery")
		}
	} else {
		if state == BlockNone {
			fm.failCount++
			if fm.failCount >= fm.config.FailThreshold {
				fm.blockState = BlockSuspected
				log.Warn("Probe detected potential block (fail_count=%d)", fm.failCount)
			}
		}
	}
}

func (fm *FailoverManager) probeTarget_(target string) bool {
	results := make(chan bool, fm.config.MaxParallelProbes)
	ctx, cancel := context.WithTimeout(context.Background(), fm.config.ProbeTimeout)
	defer cancel()

	go func() {
		conn, err := (&net.Dialer{Timeout: fm.config.ProbeTimeout}).DialContext(ctx, "tcp", target)
		if err != nil {
			results <- false
			return
		}
		conn.Close()
		results <- true
	}()

	go func() {
		conn, err := (&net.Dialer{Timeout: fm.config.ProbeTimeout}).DialContext(ctx, "tcp", target)
		if err != nil {
			results <- false
			return
		}

		conn.SetDeadline(time.Now().Add(2 * time.Second))
		hello := buildProbeHello(target)
		_, err = conn.Write(hello)
		if err != nil {
			conn.Close()
			results <- false
			return
		}

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		conn.Close()
		results <- err == nil && n > 0
	}()

	successes := 0
	failures := 0
	needed := 1

	for i := 0; i < 2; i++ {
		select {
		case ok := <-results:
			if ok {
				successes++
			} else {
				failures++
			}
		case <-ctx.Done():
			failures++
		}
	}

	return successes >= needed
}

func buildProbeHello(target string) []byte {
	hello := make([]byte, 0, 128)
	hello = append(hello, 0x16, 0x03, 0x01)

	body := []byte{0x01, 0x00, 0x00, 0x00, 0x03, 0x03}
	random := make([]byte, 32)
	rand.Read(random)
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)

	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	sni := []byte(host)
	sniLen := len(sni)
	listLen := 3 + sniLen
	extLen := 2 + listLen
	ext := []byte{0x00, 0x00}
	ext = append(ext, byte(extLen>>8), byte(extLen))
	ext = append(ext, byte(listLen>>8), byte(listLen))
	ext = append(ext, 0x00)
	ext = append(ext, byte(sniLen>>8), byte(sniLen))
	ext = append(ext, sni...)

	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)-4))
	hello = append(hello, byte(len(body)>>8), byte(len(body)))
	hello = append(hello, body...)

	return hello
}

func (fm *FailoverManager) pickAlternateIP() string {
	ips := fm.config.AlternateIPs
	if len(ips) == 0 {
		return ""
	}
	return ips[cryptoRandN(len(ips))]
}

func (fm *FailoverManager) pickDomainFrontHost() string {
	hosts := fm.config.DomainFrontHosts
	if len(hosts) == 0 {
		return ""
	}
	return hosts[cryptoRandN(len(hosts))]
}

func (fm *FailoverManager) pickCDNWorkerURL() string {
	urls := fm.config.CDNWorkerURLs
	if len(urls) == 0 {
		return ""
	}
	return urls[cryptoRandN(len(urls))]
}

func (fm *FailoverManager) ForceStrategy(s FailoverStrategy) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.activeStrategy = s
	if s != StrategyDirect {
		fm.blockState = BlockConfirmed
	}
	log.Info("Forced failover strategy: %s", s)
}

func (fm *FailoverManager) ResetBlock() {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.blockState = BlockNone
	fm.activeStrategy = StrategyDirect
	fm.failCount = 0
	fm.successCount = 0
	log.Info("Block state reset to normal")
}

func (fm *FailoverManager) Stats() map[string]interface{} {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	stratStats := make(map[string]interface{})
	for s, stats := range fm.strategyResults {
		stratStats[s.String()] = map[string]interface{}{
			"attempts":     stats.attempts,
			"successes":    stats.successes,
			"avg_ms":       stats.avgMs,
			"last_ok":      stats.lastOk,
			"success_rate": fm.strategySuccessRate(stats),
		}
	}

	return map[string]interface{}{
		"block_state":     fm.blockState,
		"active_strategy": fm.activeStrategy.String(),
		"fail_count":      fm.failCount,
		"success_count":   fm.successCount,
		"total_failovers": atomic.LoadUint64(&fm.totalFailovers),
		"total_probes":    atomic.LoadUint64(&fm.totalProbes),
		"total_blocks":    atomic.LoadUint64(&fm.totalBlocks),
		"current_latency": atomic.LoadInt64(&fm.currentLatency),
		"strategies":      stratStats,
	}
}

func cryptoRandN(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(binary.LittleEndian.Uint32(b)) % n
}
