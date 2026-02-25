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
	"os"
	"strings"
	"sync"
	"time"

	"whispera/internal/obfuscation"
	"whispera/internal/obfuscation/containers"
	ftepkg "whispera/internal/obfuscation/fte"
	"whispera/internal/util"
)

const (
	serviceVKontakte = "VKontakte"
	serviceYandex    = "Yandex"
	serviceMailru    = "Mail.ru"
	serviceRutube    = "Rutube"
	serviceOzon      = "Ozon"

	serviceMax             = "Max"
	serviceVKMessenger     = "VK Messenger"
	serviceTamTam          = "TamTam"
	serviceYandexMessenger = "Yandex Messenger"

	serviceVKVideo = "VK Video"
)

type RussianService struct {
	Name             string
	Domain           string
	Port             int
	Protocol         string
	Endpoints        []string
	Headers          map[string]string
	Obfuscation      *ServiceObfuscation
	DefaultContainer containers.ContainerType
}

type ServiceObfuscation struct {
	FTEProfile        string
	MarionetteProfile string
	CustomHeaders     map[string]string
	TimingProfile     string
}

type RussianTunneler struct {
	services   map[string]*RussianService
	active     string
	fte        *ftepkg.FTE
	marionette *obfuscation.MarionetteAdapter
}

type ServiceTunnel struct {
	Service     *RussianService
	Client      *http.Client
	FTE         *ftepkg.FTE
	Marionette  *obfuscation.MarionetteAdapter
	Context     context.Context
	CDNEndpoint string
	CDNIP       string
	DNSResolver *DNSResolver
	extractedData chan []byte
	mu            sync.Mutex

	Container containers.ContainerWrapper
	initSent  bool
}

func NewRussianTunneler() *RussianTunneler {
	t := &RussianTunneler{
		services:   make(map[string]*RussianService),
		fte:        ftepkg.NewFTE(),
		marionette: obfuscation.NewMarionetteAdapter(),
	}

	t.initRussianServices()
	return t
}

func (t *RussianTunneler) TunnelThroughService(service string, data []byte) ([]byte, error) {
	svc, exists := t.services[service]
	if !exists {
		return nil, fmt.Errorf("service %s not found", service)
	}

	obfuscatedData, err := t.applyServiceObfuscation(svc, data)
	if err != nil {
		return nil, fmt.Errorf("obfuscation failed: %w", err)
	}

	reqStr := fmt.Sprintf("POST %s HTTP/1.1\r\n", svc.Endpoints[0])
	reqStr += fmt.Sprintf("Host: %s\r\n", svc.Domain)
	for key, value := range svc.Headers {
		reqStr += fmt.Sprintf("%s: %s\r\n", key, value)
	}
	for key, value := range svc.Obfuscation.CustomHeaders {
		reqStr += fmt.Sprintf("%s: %s\r\n", key, value)
	}
	reqStr += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(obfuscatedData))

	result := append([]byte(reqStr), obfuscatedData...)
	return result, nil
}

func (t *RussianTunneler) applyServiceObfuscation(svc *RussianService, data []byte) ([]byte, error) {
	fteData, err := t.fte.ApplyRealDPIEvasion(data, svc.Name)
	if err != nil {
		return nil, fmt.Errorf("FTE obfuscation failed: %w", err)
	}

	marionetteData, _, err := t.marionette.ApplyProductionDPIEvasion(fteData, svc.Name)
	if err != nil {
		return nil, fmt.Errorf("Marionette obfuscation failed: %w", err)
	}

	return marionetteData, nil
}

func (t *RussianTunneler) CreateTunnel(ctx context.Context, cdnEndpoint string) (*ServiceTunnel, error) {
	if t.active == "" {
		return nil, fmt.Errorf("no active service set")
	}

	service := t.services[t.active]
	dnsResolver := NewDNSResolver()

	var cdnIP string
	var cdnPort string
	var targetDomain string
	if cdnEndpoint != "" {
		host, port, err := net.SplitHostPort(cdnEndpoint)
		if err != nil {
			host = cdnEndpoint
			port = "8443"
		}
		cdnPort = port

		resolvedIP, err := dnsResolver.ResolveWithFallback(host, 5*time.Second)
		if err != nil {
			log.Warn("Failed to resolve CDN endpoint %s: %v, will try direct connection", host, err)
			if net.ParseIP(host) != nil {
				resolvedIP = host
			} else {
				return nil, fmt.Errorf("failed to resolve CDN endpoint %s: %w", host, err)
			}
		}

		cdnIP = resolvedIP
		targetDomain = service.Domain
		log.Debug("CDN endpoint resolved: %s -> %s:%s (using domain %s for TLS)", cdnEndpoint, cdnIP, cdnPort, targetDomain)
	} else {
		targetDomain = service.Domain
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         targetDomain,
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

	var cdnAddr string
	if cdnIP != "" && cdnPort != "" {
		cdnAddr = net.JoinHostPort(cdnIP, cdnPort)
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			addr = cdnAddr
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, addr)
		}
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
		CDNIP:         cdnAddr,
		DNSResolver:   dnsResolver,
		extractedData: make(chan []byte, 100),
	}

	switch service.DefaultContainer {
	case containers.FormatMPEGTS:
		tunnel.Container = containers.NewMPEGTSWrapper()
	case containers.FormatFMP4:
		tunnel.Container = containers.NewFMP4Wrapper()
	case containers.FormatWebM:
		tunnel.Container = containers.NewWebMWrapper()
	case containers.FormatAVI:
		tunnel.Container = containers.NewLegacyWrapper(containers.FormatAVI)
	case containers.FormatFLV:
		tunnel.Container = containers.NewLegacyWrapper(containers.FormatFLV)
	}

	return tunnel, nil
}

func (st *ServiceTunnel) SendData(data []byte) error {
	transformed, err := st.FTE.Transform(data)
	if err != nil {
		return fmt.Errorf("FTE transform failed: %v", err)
	}

	processed, delay, err := st.Marionette.ProcessPacket(transformed, "outbound")
	if err != nil {
		return fmt.Errorf("marionette process failed: %v", err)
	}
	if len(processed) == 0 {
		// Marionette filtered this packet (e.g. local discovery / multicast) — skip silently
		return nil
	}

	if delay > 0 && delay < 5*time.Second {
		select {
		case <-time.After(delay):
		case <-st.Context.Done():
			return st.Context.Err()
		}
	}

	var payload []byte
	if !st.initSent && st.Container != nil {
		initSeg, err := st.Container.GetInitSegment()
		if err != nil {
			return fmt.Errorf("failed to generate init segment: %v", err)
		}
		if len(initSeg) > 0 {
			payload = append(payload, initSeg...)
		}
		st.initSent = true
	}

	if st.Container != nil {
		wrapped, err := st.Container.WrapData(processed)
		if err != nil {
			return fmt.Errorf("container wrap failed: %v", err)
		}
		payload = append(payload, wrapped...)
	} else {
		payload = append(payload, processed...)
	}

	req, err := st.createRequest(payload)
	if err != nil {
		return fmt.Errorf("create request failed: %v", err)
	}

	resp, err := st.Client.Do(req)
	if err != nil {
		return fmt.Errorf("send request failed: %v", err)
	}
	defer util.SafeClose("resp.Body", resp.Body.Close)

	extracted, err := st.processResponse(resp)
	if err != nil {
		return fmt.Errorf("process response failed: %v", err)
	}

	select {
	case st.extractedData <- extracted:
	case <-st.Context.Done():
		return st.Context.Err()
	default:
		select {
		case <-st.extractedData:
			st.extractedData <- extracted
		case <-st.Context.Done():
			return st.Context.Err()
		}
	}

	return nil
}

func (st *ServiceTunnel) createRequest(data []byte) (*http.Request, error) {
	svc := st.Service

	url := fmt.Sprintf("%s://%s:%d%s", svc.Protocol, svc.Domain, svc.Port, svc.Endpoints[0])

	req, err := http.NewRequestWithContext(st.Context, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	for k, v := range svc.Headers {
		req.Header.Set(k, v)
	}

	if st.Container != nil {
		req.Header.Set("Content-Type", st.Container.ContentType())
	}

	if svc.Obfuscation != nil {
		for k, v := range svc.Obfuscation.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	return req, nil
}

func (st *ServiceTunnel) ReceiveData(timeout time.Duration) ([]byte, error) {
	select {
	case data := <-st.extractedData:
		return data, nil
	case <-time.After(timeout):
		return nil, os.ErrDeadlineExceeded
	case <-st.Context.Done():
		return nil, st.Context.Err()
	}
}

func (t *RussianTunneler) SetActiveService(name string) error {
	service, exists := t.services[name]
	if !exists {
		return fmt.Errorf("service %s not found", name)
	}

	t.active = name

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

func (t *RussianTunneler) GetAvailableServices() []string {
	services := make([]string, 0, len(t.services))
	for name := range t.services {
		services = append(services, name)
	}
	return services
}

func (t *RussianTunneler) GetServiceInfo(name string) (*RussianService, error) {
	service, exists := t.services[name]
	if !exists {
		return nil, fmt.Errorf("service %s not found", name)
	}
	return service, nil
}

func (t *RussianTunneler) GetServiceDomain(name string) string {
	normalizedName := strings.ToLower(name)

	for svcName, svc := range t.services {
		if strings.ToLower(svcName) == normalizedName {
			return svc.Domain
		}
	}

	switch normalizedName {
	case "vk":
		return "vk.com"
	case "yandex":
		return "yandex.ru"
	case "mailru", "mail":
		return "mail.ru"
	case "rutube":
		return "rutube.ru"
	case "ozon":
		return "ozon.ru"
	}

	return ""
}

func (st *ServiceTunnel) processResponse(resp *http.Response) ([]byte, error) {
	if resp == nil {
		return nil, fmt.Errorf("response is nil")
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("service returned status %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

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

func (st *ServiceTunnel) extractVKData(resp *http.Response) ([]byte, error) {
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, err
	}
	var vkResp map[string]interface{}
	if err := json.Unmarshal(body, &vkResp); err != nil {
		return st.extractFromBody(body), nil
	}
	if response, ok := vkResp["response"].(map[string]interface{}); ok {
		if data, found := response["data"]; found {
			if str, ok := data.(string); ok {
				return st.decodeEmbeddedData(str)
			}
		}
	}
	return st.extractFromBody(body), nil
}

func (st *ServiceTunnel) extractYandexData(resp *http.Response) ([]byte, error) {
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, err
	}
	return st.extractFromBody(body), nil
}

func (st *ServiceTunnel) extractMailruData(resp *http.Response) ([]byte, error) {
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, err
	}
	return st.extractFromBody(body), nil
}

func (st *ServiceTunnel) extractRutubeData(resp *http.Response) ([]byte, error) {
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, err
	}
	return st.extractFromBody(body), nil
}

func (st *ServiceTunnel) extractOzonData(resp *http.Response) ([]byte, error) {
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, err
	}
	return st.extractFromBody(body), nil
}

func (st *ServiceTunnel) extractGenericData(resp *http.Response) ([]byte, error) {
	body, err := st.readResponseBody(resp)
	if err != nil {
		return nil, err
	}
	return st.extractFromBody(body), nil
}

func (st *ServiceTunnel) readResponseBody(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer util.SafeClose("gzip reader", gzReader.Close)
		reader = gzReader
	}
	return io.ReadAll(reader)
}

func (st *ServiceTunnel) extractFromBody(body []byte) []byte {

	bodyStr := string(body)
	markers := []string{"data:", "tunnel:", "whisper:"}
	for _, marker := range markers {
		idx := strings.Index(bodyStr, marker)
		if idx != -1 {
			start := idx + len(marker)
			end := start
			for end < len(bodyStr) {
				c := bodyStr[end]
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '+' || c == '=' || c == '\n' || c == '\r') {
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
	if len(body) < 20000 {
		if decoded, err := base64.StdEncoding.DecodeString(string(body)); err == nil {
			return decoded
		}
	}
	return body
}

func (st *ServiceTunnel) decodeEmbeddedData(data string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(data); err == nil {
		return decoded, nil
	}
	return []byte(data), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type DNSResolver struct {
	cache       map[string]*dnsCacheEntry
	cacheMu     sync.RWMutex
	cleanupStop chan struct{}
}

type dnsCacheEntry struct {
	ip        string
	timestamp time.Time
	ttl       time.Duration
}

const DefaultDNSTTL = 5 * time.Minute

func NewDNSResolver() *DNSResolver {
	r := &DNSResolver{
		cache:       make(map[string]*dnsCacheEntry),
		cleanupStop: make(chan struct{}),
	}
	go r.cleanupLoop()
	return r
}

func (r *DNSResolver) Stop() {
	close(r.cleanupStop)
}

func (r *DNSResolver) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-r.cleanupStop:
			return
		case <-ticker.C:
			r.cacheMu.Lock()
			now := time.Now()
			for hostname, entry := range r.cache {
				if now.Sub(entry.timestamp) > entry.ttl {
					delete(r.cache, hostname)
				}
			}
			r.cacheMu.Unlock()
		}
	}
}

func (r *DNSResolver) Resolve(hostname string, timeout time.Duration) (string, error) {
	r.cacheMu.RLock()
	if entry, ok := r.cache[hostname]; ok {
		if time.Since(entry.timestamp) < entry.ttl {
			r.cacheMu.RUnlock()
			return entry.ip, nil
		}
	}
	r.cacheMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("DNS lookup failed for %s: %w", hostname, err)
	}
	ip := addrs[0]

	r.cacheMu.Lock()
	r.cache[hostname] = &dnsCacheEntry{
		ip:        ip,
		timestamp: time.Now(),
		ttl:       DefaultDNSTTL,
	}
	r.cacheMu.Unlock()

	return ip, nil
}

func (r *DNSResolver) ResolveWithFallback(hostname string, timeout time.Duration) (string, error) {
	return r.Resolve(hostname, timeout)
}

func (t *RussianTunneler) initRussianServices() {
	t.services["vk"] = &RussianService{
		Name:      serviceVKontakte,
		Domain:    "vk.com",
		Port:      443,
		Protocol:  "https",
		Endpoints: []string{"/api/method/messages.get"},
		Headers: map[string]string{
			"User-Agent": "VKAndroidApp/7.15",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "vk",
			MarionetteProfile: "vk",
		},
	}
	t.services["yandex"] = &RussianService{
		Name:      serviceYandex,
		Domain:    "yandex.ru",
		Port:      443,
		Protocol:  "https",
		Endpoints: []string{"/search/"},
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "yandex",
			MarionetteProfile: "yandex",
		},
	}
	t.services["mailru"] = &RussianService{
		Name:        serviceMailru,
		Domain:      "mail.ru",
		Port:        443,
		Protocol:    "https",
		Endpoints:   []string{"/api/v1/messages"},
		Obfuscation: &ServiceObfuscation{FTEProfile: "mailru", MarionetteProfile: "mailru"},
	}

	t.services["rutube"] = &RussianService{
		Name:        serviceRutube,
		Domain:      "rutube.ru",
		Port:        443,
		Protocol:    "https",
		Endpoints:   []string{"/api/"},
		Obfuscation: &ServiceObfuscation{FTEProfile: "websocket", MarionetteProfile: "websocket"},
	}

	t.services["ozon"] = &RussianService{
		Name:        serviceOzon,
		Domain:      "ozon.ru",
		Port:        443,
		Protocol:    "https",
		Endpoints:   []string{"/api/"},
		Obfuscation: &ServiceObfuscation{FTEProfile: "http2", MarionetteProfile: "quic"},
	}

	t.services["max"] = &RussianService{Name: serviceMax, Domain: "max.ru", Port: 443, Protocol: "https", Endpoints: []string{"/api/v1/messages"}, Obfuscation: &ServiceObfuscation{FTEProfile: "max", MarionetteProfile: "websocket"}}
	t.services["vk_messenger"] = &RussianService{Name: serviceVKMessenger, Domain: "vk.com", Port: 443, Protocol: "https", Endpoints: []string{"/im/event"}, Obfuscation: &ServiceObfuscation{FTEProfile: "vk_messenger", MarionetteProfile: "websocket"}}
	t.services["tamtam"] = &RussianService{Name: serviceTamTam, Domain: "tamtam.chat", Port: 443, Protocol: "https", Endpoints: []string{"/api/v1/messages"}, Obfuscation: &ServiceObfuscation{FTEProfile: "tamtam", MarionetteProfile: "mailru"}}
	t.services["yandex_messenger"] = &RussianService{Name: serviceYandexMessenger, Domain: "messenger.yandex.ru", Port: 443, Protocol: "https", Endpoints: []string{"/api/v2/messages"}, Obfuscation: &ServiceObfuscation{FTEProfile: "yandex", MarionetteProfile: "websocket"}}

	t.services["vk_video"] = &RussianService{
		Name:      serviceVKVideo,
		Domain:    "vkuservideo.net",
		Port:      443,
		Protocol:  "https",
		Endpoints: []string{"/u0/video/segment.ts"},
		Headers: map[string]string{
			"User-Agent": "VKAndroidApp/7.15 VideoPlayer/1.0",
		},
		Obfuscation: &ServiceObfuscation{
			FTEProfile:        "vk_video",
			MarionetteProfile: "quic",
			CustomHeaders: map[string]string{
				"X-VK-Video-Quality": "1080p",
			},
		},
		DefaultContainer: containers.FormatFMP4,
	}
}

