// Package asn_bypass provides ECH (Encrypted Client Hello) support
// ECH encrypts the SNI field in TLS ClientHello, making it impossible
// for middleboxes to see which domain the client is connecting to.
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
)

// ECHProvider manages ECH configurations and applies them to connections
type ECHProvider struct {
	mu          sync.RWMutex
	configs     map[string]*ECHDomainConfig
	httpClient  *http.Client
	cacheExpiry time.Duration
}

// ECHDomainConfig holds ECH configuration for a domain
type ECHDomainConfig struct {
	Domain      string    `json:"domain"`
	PublicName  string    `json:"public_name"`  // The "outer" SNI (CDN domain)
	ECHConfig   []byte    `json:"ech_config"`   // The ECH config blob
	PublicKey   []byte    `json:"public_key"`   // HPKE public key
	ConfigID    uint8     `json:"config_id"`    // ECH config ID
	MaxNameLen  uint16    `json:"max_name_len"` // Max inner name length
	LastFetched time.Time `json:"last_fetched"`
	Valid       bool      `json:"valid"`
}

// NewECHProvider creates a new ECH provider
func NewECHProvider() *ECHProvider {
	return &ECHProvider{
		configs:     make(map[string]*ECHDomainConfig),
		cacheExpiry: 24 * time.Hour,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetConfig returns ECH config for a domain
func (p *ECHProvider) GetConfig(ctx context.Context, domain string) (*ECHDomainConfig, error) {
	p.mu.RLock()
	cfg, exists := p.configs[domain]
	p.mu.RUnlock()

	if exists && cfg.Valid && time.Since(cfg.LastFetched) < p.cacheExpiry {
		return cfg, nil
	}

	// Fetch new config
	return p.fetchConfig(ctx, domain)
}

// fetchConfig fetches ECH config for a domain using parallel sources
func (p *ECHProvider) fetchConfig(ctx context.Context, domain string) (*ECHDomainConfig, error) {
	// Create a cancellable context for racing
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	type fetchResult struct {
		cfg *ECHDomainConfig
		err error
	}

	resultCh := make(chan fetchResult, 4)

	// Launch all fetch methods in parallel
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

	// Wait for first successful result or timeout
	select {
	case res := <-resultCh:
		return res.cfg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("failed to fetch ECH config for %s: all methods timed out", domain)
	}
}

// fetchFromCloudflare fetches ECH config from Cloudflare's DoH service
func (e *ECHProvider) fetchFromCloudflare(_ context.Context, domain string) (*ECHDomainConfig, error) {
	// Use DoH (DNS over HTTPS) to fetch HTTPS records
	dohURL := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=HTTPS", domain)

	req, err := http.NewRequest("GET", dohURL, nil) // No context needed if not cancelling
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

	// Parse DoH JSON response
	var dohResp struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, err
	}

	// Look for ECH config in HTTPS record
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

// fetchFromDNS fetches ECH config from DNS HTTPS record
func (p *ECHProvider) fetchFromDNS(ctx context.Context, domain string) (*ECHDomainConfig, error) {
	// DNS HTTPS record query
	// In practice, this would use miekg/dns or similar library

	// Use DoH (DNS over HTTPS) to fetch HTTPS records
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

	// Parse DoH JSON response
	var dohResp struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, err
	}

	// Look for ECH config in HTTPS record
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

// fetchFromWellKnown fetches ECH config from .well-known URL
func (p *ECHProvider) fetchFromWellKnown(ctx context.Context, domain string) (*ECHDomainConfig, error) {
	// Some servers publish ECH configs at well-known URLs
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

	// Parse SVCB record format
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

// tryCloudflareECH tries Cloudflare's known ECH configuration
func (p *ECHProvider) tryCloudflareECH(_ context.Context, domain string) (*ECHDomainConfig, error) {
	// Cloudflare domains typically use cloudflare-ech.com as the public_name
	// Check if domain is behind Cloudflare

	// Try to resolve through CF's DNS first
	cnames, err := net.LookupCNAME(domain)
	if err != nil {
		return nil, err
	}

	isCloudflare := strings.Contains(cnames, "cloudflare") ||
		strings.Contains(cnames, "cdn-cgi")

	if !isCloudflare {
		return nil, errors.New("not a Cloudflare domain")
	}

	// Use generic CF ECH config
	// Note: This is a placeholder - real config should be fetched
	cfg := &ECHDomainConfig{
		Domain:      domain,
		PublicName:  "cloudflare-ech.com",
		ECHConfig:   nil, // Would contain actual ECH config bytes
		LastFetched: time.Now(),
		Valid:       false, // Mark as invalid until we have real config
	}

	return cfg, nil
}

func (p *ECHProvider) cacheConfig(domain string, cfg *ECHDomainConfig) {
	p.mu.Lock()
	p.configs[domain] = cfg
	p.mu.Unlock()
}

// Helper functions to parse DNS/SVCB formats

func extractECHFromHTTPS(data string) []byte {
	// HTTPS record format: priority target svc-params
	// ECH is in svc-params as ech="base64..."

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
	// Parse SVCB record wire format
	// This is simplified - real parsing would be more complex

	// Look for ECH SvcParamKey (0x0005)
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0x00 && data[i+1] == 0x05 {
			// Found ECH param
			length := int(data[i+2])<<8 | int(data[i+3])
			if i+4+length <= len(data) {
				return data[i+4 : i+4+length]
			}
		}
	}
	return nil
}

// ECHWrapper provides ECH-enabled connection wrapping
type ECHWrapper struct {
	provider *ECHProvider
}

// NewECHWrapper creates a new ECH wrapper
func NewECHWrapper() *ECHWrapper {
	return &ECHWrapper{
		provider: NewECHProvider(),
	}
}

// WrapConnection wraps a connection with ECH if available
func (w *ECHWrapper) WrapConnection(ctx context.Context, conn net.Conn, domain string) (net.Conn, error) {
	cfg, err := w.provider.GetConfig(ctx, domain)
	if err != nil {
		// ECH not available, return original connection
		return conn, nil
	}

	if !cfg.Valid || cfg.ECHConfig == nil {
		return conn, nil
	}

	// Apply ECH to the connection
	// This requires uTLS with ECH support
	// The actual implementation would use:
	// - uconn.ApplyPreset() with ECH-enabled preset
	// - or manually configure ECH extension

	log.Info("ECH available for %s via %s", domain, cfg.PublicName)
	return conn, nil // Placeholder - actual ECH wrapping would happen here
}

// IsECHAvailable checks if ECH is available for a domain
func (w *ECHWrapper) IsECHAvailable(ctx context.Context, domain string) bool {
	cfg, err := w.provider.GetConfig(ctx, domain)
	if err != nil {
		return false
	}
	return cfg.Valid && cfg.ECHConfig != nil
}
