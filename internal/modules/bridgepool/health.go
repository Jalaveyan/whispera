package bridgepool

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

type HealthMonitor struct {
	registry      *Registry
	checkInterval time.Duration
	timeout       time.Duration
	stop          chan struct{}
	wg            sync.WaitGroup
	running       bool
	mu            sync.Mutex
}

func NewHealthMonitor(registry *Registry, checkInterval time.Duration) *HealthMonitor {
	return &HealthMonitor{
		registry:      registry,
		checkInterval: checkInterval,
		timeout:       5 * time.Second,
		stop:          make(chan struct{}),
	}
}

func (h *HealthMonitor) Start() {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.running = true
	h.stop = make(chan struct{})
	h.mu.Unlock()

	h.wg.Add(1)
	go h.loop()
}

func (h *HealthMonitor) Stop() {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	h.running = false
	h.mu.Unlock()

	close(h.stop)
	h.wg.Wait()
}

func (h *HealthMonitor) loop() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.checkInterval)
	defer ticker.Stop()

	h.checkAll()

	for {
		select {
		case <-ticker.C:
			h.checkAll()
		case <-h.stop:
			return
		}
	}
}

func (h *HealthMonitor) checkAll() {
	bridges := h.registry.GetAllBridges()
	if len(bridges) == 0 {
		return
	}

	firstAlive := make(chan *BridgeInfo, 1)
	sem := make(chan struct{}, 10)

	for _, bridge := range bridges {
		sem <- struct{}{}
		go func(b *BridgeInfo) {
			defer func() { <-sem }()
			h.checkBridge(b)
			if b.IsAlive {
				select {
				case firstAlive <- b:
				default:
				}
			}
		}(bridge)
	}
}

func (h *HealthMonitor) checkBridge(b *BridgeInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	start := time.Now()
	isAlive := false
	latency := 0

	dialer := &net.Dialer{Timeout: h.timeout}
	conn, err := (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{
		InsecureSkipVerify: true,
	}}).DialContext(ctx, "tcp", b.Address)

	if err != nil {
		var d net.Dialer
		tcpConn, tcpErr := d.DialContext(ctx, "tcp", b.Address)
		if tcpErr == nil {
			isAlive = true
			latency = int(time.Since(start).Milliseconds())
			tcpConn.Close()
		}
	} else {
		isAlive = true
		latency = int(time.Since(start).Milliseconds())
		conn.Close()
	}

	h.registry.UpdateBridgeStatus(b.ID, isAlive, latency)
}

func (h *HealthMonitor) CheckSingle(bridgeID string) (bool, int, error) {
	bridge, err := h.registry.GetBridge(bridgeID)
	if err != nil {
		return false, 0, err
	}

	h.checkBridge(bridge)
	return bridge.IsAlive, bridge.Latency, nil
}
