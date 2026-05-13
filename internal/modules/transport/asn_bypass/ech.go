package asn_bypass

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

type ECHProvider struct {
	mu          sync.RWMutex
	configs     map[string]*ECHDomainConfig
	httpClient  *http.Client
	cacheExpiry time.Duration
}

type ECHDomainConfig struct {
	Domain      string    `json:"domain"`
	PublicName  string    `json:"public_name"`
	ECHConfig   []byte    `json:"ech_config"`
	PublicKey   []byte    `json:"public_key"`
	ConfigID    uint8     `json:"config_id"`
	MaxNameLen  uint16    `json:"max_name_len"`
	LastFetched time.Time `json:"last_fetched"`
	Valid       bool      `json:"valid"`
}

func NewECHProvider() *ECHProvider {
	return &ECHProvider{
		configs:     make(map[string]*ECHDomainConfig),
		cacheExpiry: 24 * time.Hour,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (p *ECHProvider) GetConfig(ctx context.Context, domain string) (*ECHDomainConfig, error) {
	p.mu.RLock()
	cfg, exists := p.configs[domain]
	p.mu.RUnlock()

	if exists && cfg.Valid && time.Since(cfg.LastFetched) < p.cacheExpiry {
		return cfg, nil
	}

	return p.fetchConfig(ctx, domain)
}

func (p *ECHProvider) fetchConfig(ctx context.Context, domain string) (*ECHDomainConfig, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	type fetchResult struct {
		cfg *ECHDomainConfig
		err error
	}

	resultCh := make(chan fetchResult, 4)

	fetchMethods := []struct {
		name string
		fn   func(context.Context, string) (*ECHDomainConfig, error)
	}{
		{"DNS", p.fetchFromDNS},
		{"WellKnown", p.fetchFromWellKnown},
		{"Cloudflare", p.fetchFromCloudflare},
		{"CloudflareECH", p.tryCloudflareECH},
	}

	for _, method := range fetchMethods {
		go func(name string, fetchFn func(context.Context, string) (*ECHDomainConfig, error)) {
			select {
			case <-raceCtx.Done():
				return
			default:
			}

			cfg, err := fetchFn(raceCtx, domain)
			if err == nil && cfg != nil && cfg.Valid {
				select {
				case resultCh <- fetchResult{cfg: cfg}:
				default:
				}
			}
		}(method.name, method.fn)
	}

	select {
	case res := <-resultCh:
		return res.cfg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("failed to fetch ECH config for %s: all methods timed out", domain)
	}
}

func (e *ECHProvider) fetchFromCloudflare(_ context.Context, domain string) (*ECHDomainConfig, error) {
	dohURL := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=HTTPS", domain)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, dohURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DNS query failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var dohResp struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, err
	}

	for _, answer := range dohResp.Answer {
		if echConfig := extractECHFromHTTPS(answer.Data); echConfig != nil {
			cfg := &ECHDomainConfig{
				Domain:      domain,
				ECHConfig:   echConfig,
				LastFetched: time.Now(),
				Valid:       true,
			}
			e.cacheConfig(domain, cfg)
			return cfg, nil
		}
	}

	return nil, errors.New("no ECH config in Cloudflare DNS response")
}

func (p *ECHProvider) fetchFromDNS(ctx context.Context, domain string) (*ECHDomainConfig, error) {
	dohURL := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=HTTPS", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", dohURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DNS query failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var dohResp struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, err
	}

	for _, answer := range dohResp.Answer {
		if echConfig := extractECHFromHTTPS(answer.Data); echConfig != nil {
			cfg := &ECHDomainConfig{
				Domain:      domain,
				ECHConfig:   echConfig,
				LastFetched: time.Now(),
				Valid:       true,
			}
			p.cacheConfig(domain, cfg)
			return cfg, nil
		}
	}

	return nil, errors.New("no ECH config in DNS response")
}

func (p *ECHProvider) fetchFromWellKnown(ctx context.Context, domain string) (*ECHDomainConfig, error) {
	url := fmt.Sprintf("https://%s/.well-known/origin-svcb", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("well-known fetch failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	echConfig := extractECHFromSVCB(body)
	if echConfig == nil {
		return nil, errors.New("no ECH config found")
	}

	cfg := &ECHDomainConfig{
		Domain:      domain,
		ECHConfig:   echConfig,
		LastFetched: time.Now(),
		Valid:       true,
	}
	p.cacheConfig(domain, cfg)
	return cfg, nil
}

func (p *ECHProvider) tryCloudflareECH(_ context.Context, domain string) (*ECHDomainConfig, error) {
	cnames, err := net.DefaultResolver.LookupCNAME(context.Background(), domain)
	if err != nil {
		return nil, err
	}

	isCloudflare := strings.Contains(cnames, "cloudflare") ||
		strings.Contains(cnames, "cdn-cgi")

	if !isCloudflare {
		return nil, errors.New("not a Cloudflare domain")
	}

	cfg := &ECHDomainConfig{
		Domain:      domain,
		PublicName:  "cloudflare-ech.com",
		ECHConfig:   nil,
		LastFetched: time.Now(),
		Valid:       false,
	}

	return cfg, nil
}

func (p *ECHProvider) cacheConfig(domain string, cfg *ECHDomainConfig) {
	p.mu.Lock()
	p.configs[domain] = cfg
	p.mu.Unlock()
}

func extractECHFromHTTPS(data string) []byte {
	parts := strings.Split(data, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "ech=") {
			echB64 := strings.TrimPrefix(part, "ech=")
			echB64 = strings.Trim(echB64, "\"")
			if decoded, err := base64.StdEncoding.DecodeString(echB64); err == nil {
				return decoded
			}
		}
	}
	return nil
}

func extractECHFromSVCB(data []byte) []byte {
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0x00 && data[i+1] == 0x05 {
			length := int(data[i+2])<<8 | int(data[i+3])
			if i+4+length <= len(data) {
				return data[i+4 : i+4+length]
			}
		}
	}
	return nil
}

type ECHWrapper struct {
	provider *ECHProvider
}

func NewECHWrapper() *ECHWrapper {
	return &ECHWrapper{
		provider: NewECHProvider(),
	}
}

// WrapConnection upgrades conn to a uTLS connection with ECH if the domain
// has a published ECH config. Falls back to plain conn on any error so the
// caller can still proceed without ECH.
func (w *ECHWrapper) WrapConnection(ctx context.Context, conn net.Conn, domain string) (net.Conn, error) {
	cfg, err := w.provider.GetConfig(ctx, domain)
	if err != nil || !cfg.Valid || cfg.ECHConfig == nil {
		return conn, nil
	}

	publicName := cfg.PublicName
	if publicName == "" {
		publicName = "cloudflare-ech.com"
	}

	tlsCfg := &utls.Config{
		// Outer SNI is the ECH public name (visible to DPI).
		ServerName:                     publicName,
		// ECHConfigList causes uTLS to encrypt the real ServerName in the inner ClientHello.
		EncryptedClientHelloConfigList: cfg.ECHConfig,
		InsecureSkipVerify:             false,
		MinVersion:                     utls.VersionTLS13,
	}

	uconn := utls.UClient(conn, tlsCfg, utls.HelloChrome_Auto)
	// Handshake must complete within the parent context deadline.
	if deadline, ok := ctx.Deadline(); ok {
		uconn.SetDeadline(deadline)
	}
	if err := uconn.Handshake(); err != nil {
		uconn.Close()
		return conn, nil // fall back to plain conn
	}
	uconn.SetDeadline(time.Time{})

	log.Info("ECH handshake succeeded for %s via public name %s (ECHAccepted=%v)",
		domain, publicName, uconn.ConnectionState().ECHAccepted)
	return uconn, nil
}

func (w *ECHWrapper) IsECHAvailable(ctx context.Context, domain string) bool {
	cfg, err := w.provider.GetConfig(ctx, domain)
	if err != nil {
		return false
	}
	return cfg.Valid && cfg.ECHConfig != nil
}
