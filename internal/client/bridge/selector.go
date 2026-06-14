package bridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
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

var dohResolvers = []string{
	"https://dns.google/resolve",
	"https://cloudflare-dns.com/dns-query",
	"https://dns.yandex.ru/resolve",
	"https://doh.opendns.com/dns-query",
}

type Config struct {
	Mode BridgeMode `yaml:"mode" json:"mode"`

	DiscoveryURL          string        `yaml:"discovery_url" json:"discovery_url"`
	FallbackDiscoveryURLs []string      `yaml:"fallback_discovery_urls" json:"fallback_discovery_urls"`
	DNSDiscoveryDomain    string        `yaml:"dns_discovery_domain" json:"dns_discovery_domain"`
	BootstrapBridges      []*BridgeInfo `yaml:"bootstrap_bridges" json:"bootstrap_bridges"`

	ManualBridge string `yaml:"manual_bridge" json:"manual_bridge"`

	EnableFailover  bool          `yaml:"enable_failover" json:"enable_failover"`
	TestTimeout     time.Duration `yaml:"test_timeout" json:"test_timeout"`
	MaxRetries      int           `yaml:"max_retries" json:"max_retries"`
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

func (s *Selector) GetAvailableBridges() []*BridgeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*BridgeInfo, len(s.bridges))
	copy(result, s.bridges)
	return result
}

func (s *Selector) FetchBridges(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	type result struct {
		bridges []*BridgeInfo
		source  string
	}
	ch := make(chan result, 8)

	launch := func(src string, fn func() ([]*BridgeInfo, error)) {
		go func() {
			if b, err := fn(); err == nil && len(b) > 0 {
				ch <- result{b, src}
			}
		}()
	}

	if s.config.DiscoveryURL != "" {
		u := s.config.DiscoveryURL
		launch("primary", func() ([]*BridgeInfo, error) { return s.fetchFromURL(ctx, u) })
	}
	for _, u := range s.config.FallbackDiscoveryURLs {
		u := u
		launch("fallback:"+u, func() ([]*BridgeInfo, error) { return s.fetchFromURL(ctx, u) })
	}
	if s.config.DNSDiscoveryDomain != "" {
		d := s.config.DNSDiscoveryDomain
		launch("dns", func() ([]*BridgeInfo, error) { return s.fetchFromDNS(ctx, d) })
	}

	select {
	case r := <-ch:
		s.mu.Lock()
		s.bridges = r.bridges
		s.mu.Unlock()
		log.Printf("[BridgeSelector] Fetched %d bridges via %s", len(r.bridges), r.source)
		return nil
	case <-ctx.Done():
	}

	if len(s.config.BootstrapBridges) > 0 {
		s.mu.Lock()
		s.bridges = s.config.BootstrapBridges
		s.mu.Unlock()
		log.Printf("[BridgeSelector] All discovery failed — using %d bootstrap bridges", len(s.config.BootstrapBridges))
		return nil
	}

	return errors.New("bridge discovery failed: all methods timed out and no bootstrap bridges configured")
}

func (s *Selector) fetchFromURL(ctx context.Context, rawURL string) ([]*BridgeInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)

	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var bridges []*BridgeInfo

	if err := json.NewDecoder(resp.Body).Decode(&bridges); err != nil {
		return nil, err
	}

	return bridges, nil
}

func (s *Selector) fetchFromDNS(ctx context.Context, domain string) ([]*BridgeInfo, error) {
	type dohAnswer struct {
		Data string `json:"data"`
	}
	type dohResp struct {
		Answer []dohAnswer `json:"Answer"`
	}

	httpClient := &http.Client{Timeout: 8 * time.Second}
	ch := make(chan []*BridgeInfo, len(dohResolvers))

	for _, resolver := range dohResolvers {
		resolver := resolver
		go func() {
			u, _ := url.Parse(resolver)
			q := u.Query()

			q.Set("name", domain)
			q.Set("type", "TXT")

			u.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
			if err != nil {
				return
			}

			req.Header.Set("Accept", "application/dns-json")
			resp, err := httpClient.Do(req)

			if err != nil {
				return
			}

			defer resp.Body.Close()

			var dr dohResp
			if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
				return
			}

			for _, ans := range dr.Answer {

				data := strings.Trim(ans.Data, `"`)

				if !strings.HasPrefix(data, "v=whispera-bridges") {
					continue
				}

				idx := strings.Index(data, " ")

				if idx < 0 {
					continue
				}

				jsonPart := data[idx+1:]
				var bridges []*BridgeInfo

				if err := json.Unmarshal([]byte(jsonPart), &bridges); err == nil && len(bridges) > 0 {
					ch <- bridges
					return
				}
			}
		}()
	}

	select {
	case b := <-ch:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
					return
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

func (s *Selector) HasBridges() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bridges) > 0
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
