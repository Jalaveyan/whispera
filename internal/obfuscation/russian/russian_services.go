package russian

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"whispera/internal/obfuscation"
	ftepkg "whispera/internal/obfuscation/fte"
	"whispera/internal/util"
)

const (
	serviceVKontakte = "VKontakte"
	serviceYandex    = "Yandex"
	serviceMailru    = "Mail.ru"
	serviceRutube    = "Rutube"
	serviceOzon      = "Ozon"

	// Russian Messengers
	serviceMax             = "Max"
	serviceVKMessenger     = "VK Messenger"
	serviceTamTam          = "TamTam"
	serviceYandexMessenger = "Yandex Messenger"
)

// RussianService represents a whitelisted Russian service
type RussianService struct {
	Name        string
	Domain      string
	Port        int
	Protocol    string // "https", "http"
	Endpoints   []string
	Headers     map[string]string
	Obfuscation *ServiceObfuscation
}

// ServiceObfuscation defines how to mask traffic for specific service
type ServiceObfuscation struct {
	FTEProfile        string
	MarionetteProfile string
	CustomHeaders     map[string]string
	TimingProfile     string
}

// RussianTunneler implements tunneling through Russian whitelisted services
type RussianTunneler struct {
	services   map[string]*RussianService
	active     string
	fte        *ftepkg.FTE
	marionette *obfuscation.MarionetteAdapter
}

// NewRussianTunneler creates a new Russian service tunneler
func NewRussianTunneler() *RussianTunneler {
	t := &RussianTunneler{
		services:   make(map[string]*RussianService),
		fte:        ftepkg.NewFTE(),
		marionette: obfuscation.NewMarionetteAdapter(),
	}

	t.initRussianServices()
	return t
}

// TunnelThroughService tunnels data through a Russian service
func (t *RussianTunneler) TunnelThroughService(service string, data []byte) ([]byte, error) {
	svc, exists := t.services[service]
	if !exists {
		return nil, fmt.Errorf("service %s not found", service)
	}

	// Применяем реальную обфускацию для сервиса
	obfuscatedData, err := t.applyServiceObfuscation(svc, data)
	if err != nil {
		return nil, fmt.Errorf("obfuscation failed: %w", err)
	}

	// Создаем реальный HTTP запрос к сервису
	httpData, err := t.createServiceRequest(svc, obfuscatedData)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	return httpData, nil
}

// applyServiceObfuscation применяет реальную обфускацию для сервиса
func (t *RussianTunneler) applyServiceObfuscation(svc *RussianService, data []byte) ([]byte, error) {
	// Применяем FTE обфускацию
	fteData, err := t.fte.ApplyRealDPIEvasion(data, svc.Name)
	if err != nil {
		return nil, fmt.Errorf("FTE obfuscation failed: %w", err)
	}

	// Применяем Marionette обфускацию
	marionetteData, _, err := t.marionette.ApplyProductionDPIEvasion(fteData, svc.Name)
	if err != nil {
		return nil, fmt.Errorf("Marionette obfuscation failed: %w", err)
	}

	return marionetteData, nil
}

// createServiceRequest создает реальный HTTP запрос к сервису
//
//nolint:unparam // Error kept for interface compatibility
func (t *RussianTunneler) createServiceRequest(svc *RussianService, data []byte) ([]byte, error) {
	// Создаем реальный HTTP запрос
	request := fmt.Sprintf("POST %s HTTP/1.1\r\n", svc.Endpoints[0])
	request += fmt.Sprintf("Host: %s\r\n", svc.Domain)

	// Добавляем реальные заголовки
	for key, value := range svc.Headers {
		request += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	// Добавляем заголовки обфускации
	for key, value := range svc.Obfuscation.CustomHeaders {
		request += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	request += fmt.Sprintf("Content-Length: %d\r\n", len(data))
	request += "\r\n"

	// Добавляем данные
	requestBytes := []byte(request)
	requestBytes = append(requestBytes, data...)

	return requestBytes, nil
}

// initRussianServices initializes whitelisted Russian services
//
//nolint:funlen // Function initializes multiple services
func (t *RussianTunneler) initRussianServices() {
	// VKontakte (VK) - production configuration for largest Russian social network
	t.services["vk"] = &RussianService{
		Name:     serviceVKontakte,
		Domain:   "vk.com",
		Port:     8443,
		Protocol: "https",
		Endpoints: []string{
			"/api/method/messages.get",
			"/api/method/users.get",
			"/api/method/wall.get",
			"/api/method/photos.get",
			"/api/method/video.get",
			"/api/method/friends.get",
			"/api/method/groups.get",
			"/api/method/audio.get",
		},
		Headers: map[string]string{
			"User-Agent":       "VKAndroidApp/7.15.1-1234 (Android 11; SDK 30; arm64-v8a; samsung SM-G991B; ru)",
			"Accept":           "application/json, text/plain, */*",
			"Accept-Language":  "ru-RU,ru;q=0.9,en;q=0.8",
			"Accept-Encoding":  "gzip, deflate, br",
			"X-Requested-With": "XMLHttpRequest",
			"X-VK-Android":     "7.15.1-1234",
			"Origin":           "https://vk.com",
			"Referer":          "https://vk.com/feed",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "vk",
			MarionetteProfile: "vk",
			CustomHeaders: map[string]string{
				"Content-Type":     "application/json",
				"X-VK-Android":     "7.0-1234",
				"X-VK-API-Version": "5.131",
			},
			TimingProfile: "vk",
		},
	}

	// Yandex - production configuration for Russian search engine and ecosystem
	t.services["yandex"] = &RussianService{
		Name:     serviceYandex,
		Domain:   "yandex.ru",
		Port:     8443,
		Protocol: "https",
		Endpoints: []string{
			"/search/",
			"/images/search",
			"/video/search",
			"/maps/",
			"/mail/",
			"/disk/",
			"/translate/",
			"/news/",
		},
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
				"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"Accept-Language":  "ru-RU,ru;q=0.9,en;q=0.8",
			"Accept-Encoding":  "gzip, deflate, br",
			"X-Yandex-API-Key": "yandex-api-key",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "yandex",
			MarionetteProfile: "yandex",
			CustomHeaders: map[string]string{
				"Content-Type":     "text/html; charset=utf-8",
				"X-Yandex-API-Key": "yandex-api-key",
				"X-Yandex-Client":  "yandex-browser",
			},
			TimingProfile: "yandex",
		},
	}

	// Mail.ru - production configuration for Russian email and services
	t.services["mailru"] = &RussianService{
		Name:     serviceMailru,
		Domain:   "mail.ru",
		Port:     8443,
		Protocol: "https",
		Endpoints: []string{
			"/api/v1/messages",
			"/api/v1/contacts",
			"/api/v1/calendar",
			"/api/v1/cloud",
			"/api/v1/disk",
			"/cgi-bin/",
			"/ajax/",
			"/my/",
		},
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
				"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Accept":           "application/json, text/javascript, */*; q=0.01",
			"Accept-Language":  "ru-RU,ru;q=0.9,en;q=0.8",
			"X-Requested-With": "XMLHttpRequest",
			"X-Mailru-API":     "mailru-api-key",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "mailru",
			MarionetteProfile: "mailru",
			CustomHeaders: map[string]string{
				"Content-Type":    "application/json",
				"X-Mailru-API":    "mailru-api-key",
				"X-Mailru-Client": "mailru-android",
			},
			TimingProfile: "mailru",
		},
	}

	// Rutube - видеосервис
	t.services["rutube"] = &RussianService{
		Name:     serviceRutube,
		Domain:   "rutube.ru",
		Port:     8443,
		Protocol: "https",
		Endpoints: []string{
			"/api/",
			"/video/",
			"/play/",
			"/embed/",
		},
		Headers: map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "ru-RU,ru;q=0.9",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "websocket",
			MarionetteProfile: "websocket",
			CustomHeaders: map[string]string{
				"Content-Type":    "video/mp4",
				"X-Rutube-Player": "html5",
			},
			TimingProfile: "video_streaming",
		},
	}

	// Ozon - маркетплейс
	t.services["ozon"] = &RussianService{
		Name:     serviceOzon,
		Domain:   "ozon.ru",
		Port:     8443,
		Protocol: "https",
		Endpoints: []string{
			"/api/",
			"/search/",
			"/product/",
			"/cart/",
		},
		Headers: map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Accept":          "application/json, text/plain, */*",
			"Accept-Language": "ru-RU,ru;q=0.9",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "http2",
			MarionetteProfile: "quic",
			CustomHeaders: map[string]string{
				"Content-Type":  "application/json",
				"X-Ozon-Client": "web",
			},
			TimingProfile: "ecommerce",
		},
	}

	// ========================================
	// RUSSIAN MESSENGERS
	// ========================================

	// Max - национальный мессенджер (VK/Ростелеком)
	t.services["max"] = &RussianService{
		Name:     serviceMax,
		Domain:   "max.ru",
		Port:     8443,
		Protocol: "https",
		Endpoints: []string{
			"/api/v1/messages",
			"/api/v1/chats",
			"/api/v1/users",
			"/api/v1/bots",
			"/api/v1/subscriptions",
			"/wss/events",
		},
		Headers: map[string]string{
			"User-Agent":    "Max/1.0.0 (Android 14; samsung SM-S918B; ru)",
			"Accept":        "application/json",
			"Content-Type":  "application/json",
			"X-Max-Client":  "android",
			"X-Max-Version": "1.0.0",
			"Connection":    "keep-alive",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "max",
			MarionetteProfile: "websocket",
			CustomHeaders: map[string]string{
				"Sec-WebSocket-Version":  "13",
				"Sec-WebSocket-Protocol": "max-im",
			},
			TimingProfile: "messenger_realtime",
		},
	}

	// VK Messenger - мессенджер ВКонтакте
	t.services["vk_messenger"] = &RussianService{
		Name:     serviceVKMessenger,
		Domain:   "vk.com",
		Port:     8443,
		Protocol: "https",
		Endpoints: []string{
			"/messaging/api/v1/messages",
			"/messaging/api/v1/conversations",
			"/messaging/api/v1/typing",
			"/messaging/api/v1/read",
			"/im/event",
			"/wss/im",
		},
		Headers: map[string]string{
			"User-Agent":       "VK Messenger/8.32 (Android 14; SDK 34; arm64-v8a; samsung SM-G991B; ru)",
			"Accept":           "application/json",
			"Accept-Language":  "ru-RU,ru;q=0.9",
			"X-VK-Client":      "messenger",
			"X-VK-App-ID":      "7913379",
			"X-VK-API-Version": "5.199",
			"Connection":       "keep-alive",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "vk_messenger",
			MarionetteProfile: "websocket",
			CustomHeaders: map[string]string{
				"Sec-WebSocket-Version":  "13",
				"Sec-WebSocket-Protocol": "vk-im",
			},
			TimingProfile: "messenger_realtime",
		},
	}

	// TamTam - мессенджер Mail.ru Group
	t.services["tamtam"] = &RussianService{
		Name:     serviceTamTam,
		Domain:   "tamtam.chat",
		Port:     8443,
		Protocol: "https",
		Endpoints: []string{
			"/api/v1/messages",
			"/api/v1/chats",
			"/api/v1/subscriptions",
			"/api/v1/uploads",
			"/ws/chats",
		},
		Headers: map[string]string{
			"User-Agent":      "TamTam/3.12.0 (Android 14; samsung SM-S918B; ru)",
			"Accept":          "application/json",
			"Content-Type":    "application/json",
			"X-TamTam-Client": "android",
			"Accept-Language": "ru-RU,ru;q=0.9",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "tamtam",
			MarionetteProfile: "mailru",
			CustomHeaders: map[string]string{
				"X-TamTam-Version": "3.12.0",
			},
			TimingProfile: "messenger_polling",
		},
	}

	// Яндекс Мессенджер
	t.services["yandex_messenger"] = &RussianService{
		Name:     serviceYandexMessenger,
		Domain:   "messenger.yandex.ru",
		Port:     8443,
		Protocol: "https",
		Endpoints: []string{
			"/api/v2/messages",
			"/api/v2/chats",
			"/api/v2/users",
			"/push/subscribe",
			"/wss/push",
		},
		Headers: map[string]string{
			"User-Agent":           "YandexMessenger/2.15.0 (Android 14; samsung SM-S918B; ru)",
			"Accept":               "application/json",
			"Content-Type":         "application/json",
			"X-Yandex-Client-Type": "messenger-android",
			"Accept-Language":      "ru-RU,ru;q=0.9",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "yandex",
			MarionetteProfile: "websocket",
			CustomHeaders: map[string]string{
				"X-Yandex-Messenger-Version": "2.15.0",
			},
			TimingProfile: "messenger_realtime",
		},
	}
}

// SetActiveService sets the active Russian service for tunneling
func (t *RussianTunneler) SetActiveService(name string) error {
	service, exists := t.services[name]
	if !exists {
		return fmt.Errorf("service %s not found", name)
	}

	t.active = name

	// Configure obfuscation for this service
	if service.Obfuscation != nil {
		if err := t.fte.SetActiveProfile(service.Obfuscation.FTEProfile); err != nil {
			return fmt.Errorf("failed to set FTE profile: %v", err)
		}

		if err := t.marionette.SetActiveProfile(service.Obfuscation.MarionetteProfile); err != nil {
			return fmt.Errorf("failed to set Marionette profile: %v", err)
		}
	}

	return nil
}

// CreateTunnel creates a tunnel through the active Russian service
// If cdnEndpoint is provided, tunnel will route through CDN instead of direct service
func (t *RussianTunneler) CreateTunnel(ctx context.Context, cdnEndpoint string) (*ServiceTunnel, error) {
	if t.active == "" {
		return nil, fmt.Errorf("no active service set")
	}

	service := t.services[t.active]
	dnsResolver := NewDNSResolver()

	// Resolve CDN endpoint if provided
	var cdnIP string
	var cdnPort string
	var targetDomain string
	if cdnEndpoint != "" {
		// Parse CDN endpoint (can be hostname:port or IP:port)
		host, port, err := net.SplitHostPort(cdnEndpoint)
		if err != nil {
			// If no port, assume default HTTPS port
			host = cdnEndpoint
			port = "8443"
		}
		cdnPort = port

		// Resolve hostname to IP with fallback
		resolvedIP, err := dnsResolver.ResolveWithFallback(host, 5*time.Second)
		if err != nil {
			log.Warn("Failed to resolve CDN endpoint %s: %v, will try direct connection", host, err)
			// Try to use host as-is (might be IP address)
			if net.ParseIP(host) != nil {
				resolvedIP = host
			} else {
				return nil, fmt.Errorf("failed to resolve CDN endpoint %s: %w", host, err)
			}
		}

		cdnIP = resolvedIP
		targetDomain = service.Domain // Keep original domain for TLS SNI and headers
		log.Debug("CDN endpoint resolved: %s -> %s:%s (using domain %s for TLS)", cdnEndpoint, cdnIP, cdnPort, targetDomain)
	} else {
		targetDomain = service.Domain
	}

	// Create HTTP client with secure TLS configuration
	// Все сервисы используют HTTPS (Port 443, Protocol "https")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         targetDomain, // Use original service domain for SNI
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: false,
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
			PreferServerCipherSuites: true,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	// If using CDN, override DialContext to connect to CDN IP
	// Store full CDN address (IP:port) for DialContext
	var cdnAddr string
	if cdnIP != "" && cdnPort != "" {
		cdnAddr = net.JoinHostPort(cdnIP, cdnPort)
		// Override DialContext to connect to CDN IP instead of original domain
		// This allows us to connect to CDN IP while keeping original domain in Host header and TLS SNI
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Replace address with CDN IP:port
			// The original addr (service.Domain:port) is replaced with CDN IP:port
			addr = cdnAddr
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, addr)
		}
		log.Debug("DialContext overridden: connecting to %s (but using %s in Host/TLS SNI)", cdnAddr, targetDomain)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	tunnel := &ServiceTunnel{
		Service:       service,
		Client:        client,
		FTE:           t.fte,
		Marionette:    t.marionette,
		Context:       ctx,
		CDNEndpoint:   cdnEndpoint,
		CDNIP:         cdnAddr, // Store full address (IP:port)
		DNSResolver:   dnsResolver,
		extractedData: make(chan []byte, 100),
	}

	return tunnel, nil
}

// GetAvailableServices returns list of available Russian services
func (t *RussianTunneler) GetAvailableServices() []string {
	services := make([]string, 0, len(t.services))
	for name := range t.services {
		services = append(services, name)
	}
	return services
}

// GetServiceInfo returns information about a specific service
func (t *RussianTunneler) GetServiceInfo(name string) (*RussianService, error) {
	service, exists := t.services[name]
	if !exists {
		return nil, fmt.Errorf("service %s not found", name)
	}
	return service, nil
}

// DNSResolver handles DNS resolution with fallback and caching
type DNSResolver struct {
	cache      map[string]*dnsCacheEntry
	cacheMu    sync.RWMutex
	dnsServers []string
}

type dnsCacheEntry struct {
	ip        string
	timestamp time.Time
	ttl       time.Duration
}

// NewDNSResolver creates a new DNS resolver with fallback servers
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		cache: make(map[string]*dnsCacheEntry),
		// Fallback DNS servers: Google, Cloudflare, Quad9, Yandex
		dnsServers: []string{
			"8.8.8.8:53",   // Google
			"8.8.4.4:53",   // Google
			"1.1.1.1:53",   // Cloudflare
			"1.0.0.1:53",   // Cloudflare
			"9.9.9.9:53",   // Quad9
			"77.88.8.8:53", // Yandex
			"77.88.8.1:53", // Yandex
		},
	}
}

// ResolveWithFallback resolves a hostname using multiple DNS servers with fallback
func (r *DNSResolver) ResolveWithFallback(hostname string, timeout time.Duration) (string, error) {
	// Check cache first
	r.cacheMu.RLock()
	if entry, exists := r.cache[hostname]; exists {
		if time.Since(entry.timestamp) < entry.ttl {
			ip := entry.ip
			r.cacheMu.RUnlock()
			return ip, nil
		}
	}
	r.cacheMu.RUnlock()

	// Check if hostname is already an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		return hostname, nil
	}

	// Try system DNS first
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Try system resolver first (fastest)
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err == nil && len(ips) > 0 {
		ip := ips[0].IP.String()
		r.updateCache(hostname, ip, 5*time.Minute)
		return ip, nil
	}

	// Fallback to custom DNS servers - try in parallel for faster resolution
	type result struct {
		ip  string
		err error
	}
	resultChan := make(chan result, len(r.dnsServers))

	// Start parallel DNS queries
	for _, dnsServer := range r.dnsServers {
		go func(server string) {
			ip, err := r.resolveWithServer(hostname, server, timeout)
			resultChan <- result{ip: ip, err: err}
		}(dnsServer)
	}

	// Wait for first successful result or all failures
	for i := 0; i < len(r.dnsServers); i++ {
		res := <-resultChan
		if res.err == nil && res.ip != "" {
			r.updateCache(hostname, res.ip, 5*time.Minute)
			return res.ip, nil
		}
		if res.err != nil {
			log.Debug("Failed to resolve %s via DNS server: %v", hostname, res.err)
		}
	}

	return "", fmt.Errorf("failed to resolve %s with all DNS servers", hostname)
}

// resolveWithServer resolves hostname using a specific DNS server
func (r *DNSResolver) resolveWithServer(hostname, dnsServer string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Use custom resolver that connects directly to specified DNS server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: timeout,
			}
			// Override address to use our DNS server
			return d.DialContext(ctx, network, dnsServer)
		},
	}

	ips, err := resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return "", fmt.Errorf("DNS query failed: %w", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for %s", hostname)
	}

	return ips[0].IP.String(), nil
}

// updateCache updates DNS cache
func (r *DNSResolver) updateCache(hostname, ip string, ttl time.Duration) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.cache[hostname] = &dnsCacheEntry{
		ip:        ip,
		timestamp: time.Now(),
		ttl:       ttl,
	}
}

// ServiceTunnel represents an active tunnel through a Russian service
type ServiceTunnel struct {
	Service     *RussianService
	Client      *http.Client
	FTE         *ftepkg.FTE
	Marionette  *obfuscation.MarionetteAdapter
	Context     context.Context
	CDNEndpoint string // CDN endpoint (hostname or IP:port)
	CDNIP       string // Resolved CDN IP address
	DNSResolver *DNSResolver
	// Buffer for extracted data from responses
	extractedData chan []byte
	mu            sync.Mutex
}

// SendData sends data through the tunnel with obfuscation
func (st *ServiceTunnel) SendData(data []byte) error {
	// Apply FTE transformation
	transformed, err := st.FTE.Transform(data)
	if err != nil {
		return fmt.Errorf("FTE transform failed: %v", err)
	}

	// Apply Marionette obfuscation
	processed, delay, err := st.Marionette.ProcessPacket(transformed, "outbound")
	if err != nil {
		return fmt.Errorf("marionette process failed: %v", err)
	}

	// Apply realistic delay based on service type
	if delay > 0 && delay < 5*time.Second {
		// Use context-aware delay (non-blocking)
		select {
		case <-time.After(delay):
		case <-st.Context.Done():
			return st.Context.Err()
		}
	}

	// Embed data in service-specific format (steganography)
	embeddedData, err := st.embedDataInRequest(processed)
	if err != nil {
		return fmt.Errorf("embed data failed: %v", err)
	}

	// Create request to Russian service
	req, err := st.createRequest(embeddedData)
	if err != nil {
		return fmt.Errorf("create request failed: %v", err)
	}

	// Send request with service-specific timing
	resp, err := st.Client.Do(req)
	if err != nil {
		return fmt.Errorf("send request failed: %v", err)
	}
	defer util.SafeClose("resp.Body", resp.Body.Close)

	// Process response (extract tunneled data)
	extracted, err := st.processResponse(resp)
	if err != nil {
		return fmt.Errorf("process response failed: %v", err)
	}

	// Send extracted data to channel for receiver
	select {
	case st.extractedData <- extracted:
	case <-st.Context.Done():
		return st.Context.Err()
	default:
		// Channel full - drop old data or wait
		select {
		case <-st.extractedData: // Remove oldest
			st.extractedData <- extracted
		case <-st.Context.Done():
			return st.Context.Err()
		}
	}

	return nil
}

// ReceiveData receives extracted data from tunnel responses
func (st *ServiceTunnel) ReceiveData(timeout time.Duration) ([]byte, error) {
	select {
	case data := <-st.extractedData:
		return data, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for data")
	case <-st.Context.Done():
		return nil, st.Context.Err()
	}
}

// embedDataInRequest embeds tunneled data into service-specific request format
func (st *ServiceTunnel) embedDataInRequest(data []byte) ([]byte, error) {
	switch st.Service.Name {
	case serviceVKontakte:
		return st.embedInVKRequest(data)
	case serviceYandex:
		return st.embedInYandexRequest(data)
	case serviceMailru:
		return st.embedInMailruRequest(data)
	case serviceRutube:
		return st.embedInRutubeRequest(data)
	case serviceOzon:
		return st.embedInOzonRequest(data)
	default:
		return st.embedGenericRequest(data)
	}
}

// createRequest creates an HTTP request to the Russian service
func (st *ServiceTunnel) createRequest(data []byte) (*http.Request, error) {
	// Select appropriate endpoint based on service type
	endpoint := st.selectEndpoint()

	// Create URL - гарантируем HTTPS
	protocol := st.Service.Protocol
	if protocol != "https" {
		protocol = "https" // Принудительно используем HTTPS
		log.Warn("Forcing HTTPS for %s", st.Service.Domain)
	}
	baseURL := fmt.Sprintf("%s://%s:%d%s",
		protocol, st.Service.Domain, st.Service.Port, endpoint)

	// Use appropriate HTTP method based on service
	method := st.getHTTPMethod()

	req, err := http.NewRequestWithContext(st.Context, method, baseURL, http.NoBody)
	if err != nil {
		return nil, err
	}

	// Ensure Host header is set to original service domain (not CDN IP)
	// This is critical for CDN routing - CDN uses Host header to route to origin
	// Go automatically sets Host from URL, but we explicitly set it to be sure
	req.Host = st.Service.Domain
	if st.CDNIP != "" {
		log.Debug("Request: URL=%s, Host=%s, Connecting to CDN=%s", baseURL, req.Host, st.CDNIP)
	}

	// Set service-specific headers
	for k, v := range st.Service.Headers {
		req.Header.Set(k, v)
	}

	// Set obfuscation headers
	if st.Service.Obfuscation != nil {
		for k, v := range st.Service.Obfuscation.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	// Add tunneled data as request body
	if len(data) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(data))
		req.ContentLength = int64(len(data))
	}

	return req, nil
}

// selectEndpoint selects appropriate endpoint based on service type
func (st *ServiceTunnel) selectEndpoint() string {
	switch st.Service.Name {
	case serviceVKontakte:
		// VK API endpoints
		return "/api/method/messages.get"
	case serviceYandex:
		// Yandex search endpoints
		return "/search/"
	case serviceMailru:
		// Mail.ru API endpoints
		return "/api/v1/messages"
	case serviceRutube:
		// Rutube video endpoints
		return "/api/"
	case serviceOzon:
		// Ozon e-commerce endpoints
		return "/api/"
	default:
		return st.Service.Endpoints[0]
	}
}

// getHTTPMethod returns appropriate HTTP method based on service
func (st *ServiceTunnel) getHTTPMethod() string {
	switch st.Service.Name {
	case serviceVKontakte, serviceMailru:
		// API services use POST
		return "POST"
	case serviceYandex, serviceRutube, serviceOzon:
		// Web services use GET
		return "GET"
	default:
		return "POST"
	}
}

// processResponse processes the response from Russian service and extracts tunneled data
func (st *ServiceTunnel) processResponse(resp *http.Response) ([]byte, error) {
	// Real implementation: extract tunneled data from response
	if resp == nil {
		return nil, fmt.Errorf("response is nil")
	}

	// Check response status
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		// Read body for error details
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("service returned status %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	// Extract tunneled data from response body based on service type
	switch st.Service.Name {
	case serviceVKontakte:
		return st.extractVKData(resp)
	case serviceYandex:
		return st.extractYandexData(resp)
	case serviceMailru:
		return st.extractMailruData(resp)
	case serviceRutube:
		return st.extractRutubeData(resp)
	case serviceOzon:
		return st.extractOzonData(resp)
	default:
		return st.extractGenericData(resp)
	}
}

// extractVKData extracts data from VKontakte response
func (st *ServiceTunnel) extractVKData(resp *http.Response) ([]byte, error) {
	// VK API returns JSON responses
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// Parse JSON response
	var vkResp map[string]interface{}
	if err := json.Unmarshal(body, &vkResp); err != nil {
		// If not JSON, try to extract from HTML or raw body
		return st.extractFromBody(body), nil
	}

	// Extract data from JSON - look for tunneled data in common fields
	if response, ok := vkResp["response"].(map[string]interface{}); ok {
		// Check for embedded data in response fields
		if data, found := response["data"]; found {
			if str, ok := data.(string); ok {
				return st.decodeEmbeddedData(str)
			}
		}
		// Check for items array (common in VK API)
		if items, ok := response["items"].([]interface{}); ok && len(items) > 0 {
			if item, ok := items[0].(map[string]interface{}); ok {
				if text, ok := item["text"].(string); ok {
					return st.decodeEmbeddedData(text)
				}
			}
		}
	}

	// Fallback: extract from raw JSON string
	return st.extractFromBody(body), nil
}

// extractYandexData extracts data from Yandex response
func (st *ServiceTunnel) extractYandexData(resp *http.Response) ([]byte, error) {
	// Yandex returns HTML responses
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// Try to find embedded data in HTML (comments, data attributes, script tags)
	bodyStr := string(body)

	// Look for base64 encoded data in HTML comments
	if idx := strings.Index(bodyStr, "<!-- data:"); idx != -1 {
		start := idx + 10
		end := strings.Index(bodyStr[start:], " -->")
		if end != -1 {
			encoded := bodyStr[start : start+end]
			return base64.StdEncoding.DecodeString(encoded)
		}
	}

	// Look for data in script tags
	if idx := strings.Index(bodyStr, "<script>"); idx != -1 {
		start := idx + 8
		end := strings.Index(bodyStr[start:], "</script>")
		if end != -1 {
			scriptData := bodyStr[start : start+end]
			return st.decodeEmbeddedData(scriptData)
		}
	}

	return st.extractFromBody(body), nil
}

// extractMailruData extracts data from Mail.ru response
func (st *ServiceTunnel) extractMailruData(resp *http.Response) ([]byte, error) {
	// Mail.ru API returns JSON responses
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// Parse JSON response
	var mailruResp map[string]interface{}
	if err := json.Unmarshal(body, &mailruResp); err != nil {
		return st.extractFromBody(body), nil
	}

	// Look for data in common Mail.ru API fields
	if status, ok := mailruResp["status"].(string); ok && status == "ok" {
		if bodyField, ok := mailruResp["body"].(map[string]interface{}); ok {
			if data, found := bodyField["data"]; found {
				if str, ok := data.(string); ok {
					return st.decodeEmbeddedData(str)
				}
			}
		}
	}

	return st.extractFromBody(body), nil
}

// extractRutubeData extracts data from Rutube response
func (st *ServiceTunnel) extractRutubeData(resp *http.Response) ([]byte, error) {
	// Rutube returns video/streaming responses
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// Try JSON first (API responses)
	var rutubeResp map[string]interface{}
	if err := json.Unmarshal(body, &rutubeResp); err == nil {
		if results, ok := rutubeResp["results"].([]interface{}); ok && len(results) > 0 {
			if video, ok := results[0].(map[string]interface{}); ok {
				if description, ok := video["description"].(string); ok {
					return st.decodeEmbeddedData(description)
				}
			}
		}
	}

	return st.extractFromBody(body), nil
}

// extractOzonData extracts data from Ozon response
func (st *ServiceTunnel) extractOzonData(resp *http.Response) ([]byte, error) {
	// Ozon returns e-commerce responses
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// Parse JSON response
	var ozonResp map[string]interface{}
	if err := json.Unmarshal(body, &ozonResp); err != nil {
		return st.extractFromBody(body), nil
	}

	// Look for data in product descriptions or reviews
	if result, ok := ozonResp["result"].([]interface{}); ok && len(result) > 0 {
		if product, ok := result[0].(map[string]interface{}); ok {
			if description, ok := product["description"].(string); ok {
				return st.decodeEmbeddedData(description)
			}
		}
	}

	return st.extractFromBody(body), nil
}

// extractGenericData extracts data from generic response
func (st *ServiceTunnel) extractGenericData(resp *http.Response) ([]byte, error) {
	// Generic data extraction
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return st.extractFromBody(body), nil
}

// Helper functions

// readResponseBody reads and decompresses response body if needed
func (st *ServiceTunnel) readResponseBody(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body

	// Handle gzip compression
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer util.SafeClose("gzip reader", gzReader.Close)
		reader = gzReader
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return body, nil
}

// extractFromBody extracts embedded data from raw body using steganographic methods
func (st *ServiceTunnel) extractFromBody(body []byte) []byte {
	// Look for base64 encoded data markers
	bodyStr := string(body)

	// Pattern 1: Base64 in specific markers
	markers := []string{"data:", "tunnel:", "whisper:"}
	for _, marker := range markers {
		idx := strings.Index(bodyStr, marker)
		if idx != -1 {
			start := idx + len(marker)
			// Find end of base64 string (alphanumeric + / + =)
			end := start
			for end < len(bodyStr) {
				c := bodyStr[end]
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
					(c >= '0' && c <= '9') || c == '/' || c == '+' || c == '=' || c == '\n' || c == '\r') {
					break
				}
				end++
			}
			encoded := strings.TrimSpace(bodyStr[start:end])
			if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
				return decoded
			}
		}
	}

	// Pattern 2: Try to decode entire body as base64 (if small enough)
	if len(body) < 10000 {
		if decoded, err := base64.StdEncoding.DecodeString(string(body)); err == nil && len(decoded) > 0 {
			return decoded
		}
	}

	// Pattern 3: Return body as-is (for future processing)
	return body
}

// decodeEmbeddedData decodes embedded data from various formats
func (st *ServiceTunnel) decodeEmbeddedData(data string) ([]byte, error) {
	// Try base64 first
	if decoded, err := base64.StdEncoding.DecodeString(data); err == nil {
		return decoded, nil
	}

	// Try URL encoding
	if decoded, err := base64.URLEncoding.DecodeString(data); err == nil {
		return decoded, nil
	}

	// Return as bytes
	return []byte(data), nil
}

// Embedding functions for request body

// embedInVKRequest embeds data in VK API request format
func (st *ServiceTunnel) embedInVKRequest(data []byte) ([]byte, error) {
	// Encode data as base64
	encoded := base64.StdEncoding.EncodeToString(data)

	// Embed in VK API JSON format
	requestData := map[string]interface{}{
		"v":            "5.131",
		"access_token": "token",
		"method":       "messages.get",
		"message":      encoded, // Embed in message field
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("marshal VK request: %w", err)
	}

	return jsonData, nil
}

// embedInYandexRequest embeds data in Yandex search request
func (st *ServiceTunnel) embedInYandexRequest(data []byte) ([]byte, error) {
	// Encode as base64 and embed in query parameter format
	encoded := base64.URLEncoding.EncodeToString(data)
	// Yandex uses text in query, so we'll embed it in the body as form data
	formData := fmt.Sprintf("text=%s", encoded)
	return []byte(formData), nil
}

// embedInMailruRequest embeds data in Mail.ru API request
func (st *ServiceTunnel) embedInMailruRequest(data []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(data)
	requestData := map[string]interface{}{
		"method": "messages.send",
		"text":   encoded,
	}
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("marshal Mail.ru request: %w", err)
	}
	return jsonData, nil
}

// embedInRutubeRequest embeds data in Rutube API request
func (st *ServiceTunnel) embedInRutubeRequest(data []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(data)
	requestData := map[string]interface{}{
		"query": encoded,
	}
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("marshal Rutube request: %w", err)
	}
	return jsonData, nil
}

// embedInOzonRequest embeds data in Ozon API request
func (st *ServiceTunnel) embedInOzonRequest(data []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(data)
	requestData := map[string]interface{}{
		"query": encoded,
	}
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("marshal Ozon request: %w", err)
	}
	return jsonData, nil
}

// embedGenericRequest embeds data in generic request format
func (st *ServiceTunnel) embedGenericRequest(data []byte) ([]byte, error) {
	// Simple base64 encoding
	return []byte(base64.StdEncoding.EncodeToString(data)), nil
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// dataReader implements io.ReadCloser for request body
type dataReader struct {
	data []byte
	pos  int
}

func (dr *dataReader) Read(p []byte) (n int, err error) {
	if dr.pos >= len(dr.data) {
		return 0, nil // EOF
	}

	n = copy(p, dr.data[dr.pos:])
	dr.pos += n
	return n, nil
}

func (dr *dataReader) Close() error {
	return nil
}
