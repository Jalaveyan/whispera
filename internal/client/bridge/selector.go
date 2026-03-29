package bridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

var globalTLSSessionCache = tls.NewLRUClientSessionCache(100)

type BridgeMode int

const (
	ModeDirect BridgeMode = iota

	ModeAuto

	ModeManual
)

type Config struct {
	Mode BridgeMode `yaml:"mode" json:"mode"`

	DiscoveryURL string `yaml:"discovery_url" json:"discovery_url"`

	ManualBridge string `yaml:"manual_bridge" json:"manual_bridge"`

	EnableFailover bool `yaml:"enable_failover" json:"enable_failover"`

	TestTimeout time.Duration `yaml:"test_timeout" json:"test_timeout"`

	MaxRetries int `yaml:"max_retries" json:"max_retries"`

	// RefreshInterval controls how often the bridge list is re-fetched from the server.
	// 0 means no periodic refresh (fetch only on first Connect).
	RefreshInterval time.Duration `yaml:"refresh_interval" json:"refresh_interval"`
}

func DefaultConfig() *Config {
	return &Config{
		Mode:            ModeDirect,
		EnableFailover:  true,
		TestTimeout:     5 * time.Second,
		MaxRetries:      3,
		RefreshInterval: 5 * time.Minute,
	}
}

type BridgeInfo struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Provider string `json:"provider"`
	Latency  int    `json:"latency_ms"`
	Failed   bool   `json:"-"`
}

type Selector struct {
	config    *Config
	bridges   []*BridgeInfo
	current   *BridgeInfo
	failedIDs map[string]time.Time
	mu        sync.RWMutex
}

func NewSelector(cfg *Config) *Selector {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Selector{
		config:    cfg,
		bridges:   make([]*BridgeInfo, 0),
		failedIDs: make(map[string]time.Time),
	}
}

func NewSelectorWithURL(discoveryURL string) *Selector {
	return NewSelector(&Config{
		Mode:            ModeAuto,
		DiscoveryURL:    discoveryURL,
		EnableFailover:  true,
		TestTimeout:     5 * time.Second,
		MaxRetries:      3,
		RefreshInterval: 5 * time.Minute,
	})
}

// StartRefresh launches a background goroutine that re-fetches the bridge list
// every Config.RefreshInterval. It stops when ctx is canceled.
func (s *Selector) StartRefresh(ctx context.Context) {
	if s.config.RefreshInterval <= 0 || s.config.DiscoveryURL == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(s.config.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.FetchBridges(ctx); err != nil {
					log.Printf("[BridgeSelector] Refresh failed: %v", err)
				} else {
					log.Printf("[BridgeSelector] Refreshed bridge list (%d bridges)", len(s.GetAvailableBridges()))
				}
			}
		}
	}()
}

func (s *Selector) SetMode(mode BridgeMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Mode = mode
}

func (s *Selector) SetManualBridge(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.ManualBridge = address
	s.config.Mode = ModeManual
}

func (s *Selector) GetMode() BridgeMode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Mode
}

func (s *Selector) GetAvailableBridges() []*BridgeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*BridgeInfo, len(s.bridges))
	copy(result, s.bridges)
	return result
}

func (s *Selector) FetchBridges(ctx context.Context) error {
	fetchTimeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", s.config.DiscoveryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch bridges: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var bridges []*BridgeInfo
	if err := json.NewDecoder(resp.Body).Decode(&bridges); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	s.mu.Lock()
	s.bridges = bridges
	s.mu.Unlock()

	log.Printf("[BridgeSelector] Fetched %d bridges", len(bridges))
	return nil
}

func (s *Selector) TestLatency(ctx context.Context, b *BridgeInfo) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, s.config.TestTimeout)
	defer cancel()

	start := time.Now()

	dialer := &net.Dialer{}
	conn, err := (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: globalTLSSessionCache,
	}}).DialContext(ctx, "tcp", b.Address)

	if err != nil {
		d := net.Dialer{}
		tcpConn, tcpErr := d.DialContext(ctx, "tcp", b.Address)
		if tcpErr != nil {
			return 0, tcpErr
		}
		tcpConn.Close()
	} else {
		conn.Close()
	}

	return time.Since(start), nil
}

func (s *Selector) TestAllBridges(ctx context.Context) {
	s.mu.RLock()
	bridges := make([]*BridgeInfo, len(s.bridges))
	copy(bridges, s.bridges)
	s.mu.RUnlock()

	if len(bridges) == 0 {
		return
	}

	log.Printf("[BridgeSelector] Testing latency to %d bridges (lazy mode)...", len(bridges))

	firstReady := make(chan *BridgeInfo, 1)

	for _, b := range bridges {
		go func(bridge *BridgeInfo) {
			latency, err := s.TestLatency(ctx, bridge)
			if err != nil {
				log.Printf("[BridgeSelector] Bridge %s (%s): FAILED - %v", bridge.ID, bridge.Address, err)
				s.MarkFailed(bridge.ID)
			} else {
				bridge.Latency = int(latency.Milliseconds())
				log.Printf("[BridgeSelector] Bridge %s (%s): %dms", bridge.ID, bridge.Address, bridge.Latency)

				select {
				case firstReady <- bridge:
				default:
				}
			}
		}(b)
	}

	select {
	case first := <-firstReady:
		log.Printf("[BridgeSelector] First bridge ready: %s (%dms) - continuing in background", first.ID, first.Latency)
	case <-ctx.Done():
		log.Printf("[BridgeSelector] Bridge test canceled")
	case <-time.After(s.config.TestTimeout):
		log.Printf("[BridgeSelector] Bridge test timeout, using any available")
	}
}

func (s *Selector) SelectBest() *BridgeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	available := make([]*BridgeInfo, 0)
	for _, b := range s.bridges {
		if !s.isFailed(b.ID) {
			available = append(available, b)
		}
	}

	if len(available) == 0 {
		return nil
	}

	sort.Slice(available, func(i, j int) bool {
		return available[i].Latency < available[j].Latency
	})

	return available[0]
}

func (s *Selector) GetNextBridge() *BridgeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, b := range s.bridges {
		if !s.isFailed(b.ID) {
			return b
		}
	}

	s.mu.RUnlock()
	s.resetFailed()
	s.mu.RLock()

	if len(s.bridges) > 0 {
		return s.bridges[0]
	}

	return nil
}

func (s *Selector) MarkFailed(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failedIDs[id] = time.Now()
}

func (s *Selector) isFailed(id string) bool {
	failedAt, exists := s.failedIDs[id]
	if !exists {
		return false
	}

	if time.Since(failedAt) > 5*time.Minute {
		delete(s.failedIDs, id)
		return false
	}

	return true
}

func (s *Selector) resetFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failedIDs = make(map[string]time.Time)
}

func (s *Selector) GetCurrent() *BridgeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *Selector) SetCurrent(b *BridgeInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = b
}

func (s *Selector) ConnectWithMode(ctx context.Context, directAddr string) (net.Conn, *BridgeInfo, error) {
	mode := s.GetMode()

	switch mode {
	case ModeDirect:
		log.Printf("[BridgeSelector] Mode: DIRECT - connecting to %s", directAddr)
		conn, err := s.dialDirect(ctx, directAddr)
		return conn, nil, err

	case ModeManual:

		s.mu.RLock()
		manualAddr := s.config.ManualBridge
		s.mu.RUnlock()

		if manualAddr == "" {
			return nil, nil, errors.New("manual mode but no bridge address specified")
		}

		log.Printf("[BridgeSelector] Mode: MANUAL - connecting via %s", manualAddr)
		bridge := &BridgeInfo{ID: "manual", Address: manualAddr}
		conn, err := s.dialBridge(ctx, bridge)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to manual bridge %s: %w", manualAddr, err)
		}
		s.SetCurrent(bridge)
		return conn, bridge, nil

	case ModeAuto:

		log.Printf("[BridgeSelector] Mode: AUTO - selecting best bridge")
		return s.Connect(ctx)

	default:
		return nil, nil, errors.New("unknown bridge mode")
	}
}

func (s *Selector) dialDirect(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: s.config.TestTimeout,
		},
		Config: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

func (s *Selector) Connect(ctx context.Context) (net.Conn, *BridgeInfo, error) {
	if len(s.bridges) == 0 {
		if err := s.FetchBridges(ctx); err != nil {
			return nil, nil, fmt.Errorf("failed to fetch bridges: %w", err)
		}
	}

	s.TestAllBridges(ctx)

	for attempt := 0; attempt < s.config.MaxRetries; attempt++ {
		bridge := s.SelectBest()
		if bridge == nil {
			return nil, nil, errors.New("no available bridges")
		}

		log.Printf("[BridgeSelector] Attempting connection via %s (%s)", bridge.ID, bridge.Address)

		conn, err := s.dialBridge(ctx, bridge)
		if err != nil {
			log.Printf("[BridgeSelector] Failed to connect via %s: %v", bridge.ID, err)
			s.MarkFailed(bridge.ID)
			continue
		}

		s.SetCurrent(bridge)
		log.Printf("[BridgeSelector] Connected via bridge %s (%s)", bridge.ID, bridge.Address)
		return conn, bridge, nil
	}

	return nil, nil, errors.New("all bridge connection attempts failed")
}

func (s *Selector) dialBridge(ctx context.Context, b *BridgeInfo) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: s.config.TestTimeout,
		},
		Config: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return dialer.DialContext(ctx, "tcp", b.Address)
}

func (s *Selector) HasBridges() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bridges) > 0
}

func (s *Selector) BridgeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bridges)
}

type ClusterMasterInfo struct {
	MasterAddress string `json:"master_address"`
	MasterID      string `json:"master_id"`
	Term          uint64 `json:"term"`
}

func (s *Selector) GetClusterMaster(ctx context.Context) *ClusterMasterInfo {
	s.mu.RLock()
	bridges := make([]*BridgeInfo, len(s.bridges))
	copy(bridges, s.bridges)
	s.mu.RUnlock()

	client := &http.Client{Timeout: 3 * time.Second}
	type masterResp struct {
		MasterID      string `json:"master_id"`
		MasterAddress string `json:"master_address"`
		Term          uint64 `json:"term"`
	}

	for _, b := range bridges {
		if b.Address == "" {
			continue
		}
		scheme := "http"
		reqURL := scheme + "://" + b.Address + "/cluster/master"
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var mr masterResp
		if err := json.NewDecoder(resp.Body).Decode(&mr); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		if mr.MasterAddress != "" {
			return &ClusterMasterInfo{
				MasterAddress: mr.MasterAddress,
				MasterID:      mr.MasterID,
				Term:          mr.Term,
			}
		}
	}
	return nil
}
