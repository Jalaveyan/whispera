package ml

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"

	"golang.org/x/net/http2"
)

const (
	protocolTLS  = "TLS"
	protocolHTTP = "HTTP"
)

var _ = []interface{}{
	(*PythonMLClient).calculateEntropy,
	(*PythonMLClient).detectProtocolSignature,
	(*PythonMLClient).fallbackPrediction,
}

func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// flowProfile кэшируется на уровне потока: ML классифицирует первый пакет,
// все следующие пакеты применяют профиль локально без вызова Python.
type flowProfile struct {
	dpiType    int
	confidence float64
	expires    time.Time
}

// flowCacheTTL — как долго хранить профиль потока.
// 30 секунд: достаточно для TCP-сессии, не слишком долго для смены условий сети.
const flowCacheTTL = 30 * time.Second

// flowSampleEvery — переклассифицировать поток каждые N пакетов
// (для адаптации если сеть изменилась во время сессии).
const flowSampleEvery = 200

type PythonMLClient struct {
	baseURL               string
	httpClient            *http.Client
	fallbackMode          bool
	mlAvailable           bool
	lastMLWarningUnixNano int64
	resultChanPool        sync.Pool
	errorChanPool         sync.Pool

	// flowCache: ключ = protocol+direction+первые4байта → flowProfile
	// Классификация делается только для первого пакета потока (и каждые 200).
	// Все остальные пакеты применяют обфускацию локально в Go — без HTTP round-trip.
	flowCache    sync.Map
	flowCounters sync.Map // ключ → uint64 (счётчик пакетов потока)
}

type MLPredictionResponsePython struct {
	Predictions []types.PredictionResult `json:"predictions"`
	ModelUsed   string                   `json:"model_used"`
	Confidence  float64                  `json:"confidence"`
	Timestamp   string                   `json:"timestamp"`
}

type ModelStatus struct {
	ModelName   string  `json:"model_name"`
	IsTrained   bool    `json:"is_trained"`
	Accuracy    float64 `json:"accuracy"`
	LastUpdated string  `json:"last_updated"`
	Parameters  int     `json:"parameters"`
}

func createSecureHTTPClient(baseURL string, timeout time.Duration) *http.Client {
	isLocalhost := strings.Contains(baseURL, "localhost") ||
		strings.Contains(baseURL, "127.0.0.1") ||
		strings.Contains(baseURL, "::1")

	isHTTPS := strings.HasPrefix(baseURL, "https://")

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	if isHTTPS {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		}

		if !isLocalhost {
			tlsConfig.InsecureSkipVerify = false
		} else {
			tlsConfig.InsecureSkipVerify = true
		}

		transport.TLSClientConfig = tlsConfig

		if err := http2.ConfigureTransport(transport); err != nil {
			log.Warn("Failed to configure HTTP/2 transport: %v (will use HTTP/1.1)", err)
		} else {
			log.Debug("HTTP/2 support enabled for ML requests")
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

func NewPythonMLClient(baseURL string) *PythonMLClient {
	if strings.HasPrefix(baseURL, "http://") {
		if !strings.Contains(baseURL, "localhost") &&
			!strings.Contains(baseURL, "127.0.0.1") &&
			!strings.Contains(baseURL, "::1") {
			log.Warn("Using HTTP for external ML server. Consider HTTPS: %s", baseURL)
		}
	}

	client := &PythonMLClient{
		baseURL:      baseURL,
		httpClient:   createSecureHTTPClient(baseURL, 30*time.Second),
		fallbackMode: true,
		mlAvailable:  false,
	}
	client.resultChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan *types.MLPredictionResponse, 1)
		},
	}
	client.errorChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan error, 1)
		},
	}

	client.checkMLAvailability()

	return client
}

func NewPythonMLClientLocal() *PythonMLClient {
	baseURL := GetEnvOrDefault("WHISPERA_ML_SERVER", "https://127.0.0.1:8000")
	if strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1") {
		baseURL = strings.Replace(baseURL, "localhost", "127.0.0.1", 1)
	}
	if strings.HasPrefix(baseURL, "http://") && !strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1") {
		baseURL = strings.Replace(baseURL, "http://", "https://", 1)
		log.Info("Auto-upgraded ML server URL to HTTPS: %s", baseURL)
	}
	client := &PythonMLClient{
		baseURL:      baseURL,
		httpClient:   createSecureHTTPClient(baseURL, 5*time.Second),
		fallbackMode: false,
		mlAvailable:  false,
	}
	client.resultChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan *types.MLPredictionResponse, 1)
		},
	}
	client.errorChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan error, 1)
		},
	}

	client.checkMLAvailability()

	return client
}

func NewPythonMLClientEnhanced() *PythonMLClient {
	baseURL := GetEnvOrDefault("WHISPERA_ML_SERVER", "http://127.0.0.1:8000")
	if strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1") {
		baseURL = strings.Replace(baseURL, "localhost", "127.0.0.1", 1)
	}
	client := &PythonMLClient{
		baseURL:      baseURL,
		httpClient:   createSecureHTTPClient(baseURL, 10*time.Second),
		fallbackMode: false,
		mlAvailable:  false,
	}
	client.resultChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan *types.MLPredictionResponse, 1)
		},
	}
	client.errorChanPool = sync.Pool{
		New: func() interface{} {
			return make(chan error, 1)
		},
	}

	client.checkMLAvailability()

	client.initializeAdaptiveLearning()

	return client
}

func (client *PythonMLClient) checkMLAvailability() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", client.baseURL+"/health", nil)
		if err != nil {
			return
		}

		resp, err := client.httpClient.Do(req)
		if err != nil {
			client.mlAvailable = false
			return
		}
		defer util.SafeClose("resp.Body", resp.Body.Close)

		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			client.mlAvailable = true
			log.Info("ML service at %s is available", client.baseURL)
		} else {
			client.mlAvailable = false
		}
	}()
}

func (client *PythonMLClient) initializeAdaptiveLearning() {}

func (client *PythonMLClient) PredictTraffic(packetData []byte, protocol, direction string) (*types.MLPredictionResponse, error) {
	isHTTP := client.isHTTPRequest(packetData) || client.isHTTPResponse(packetData)
	isTLS := client.isTLSHandshake(packetData)
	entropy := client.calculateEntropy(packetData)
	protocolSig := client.detectProtocolSignature(packetData)

	if !isTLS && isHTTP && protocolSig == "HTTP" {
	} else if !isTLS && (protocol == "tls" || protocolSig == protocolTLS || entropy > 7.8) {
		isTLS = true
	}

	if !isTLS {
		isTLS = protocol == "tls" || protocol == "dtls" || strings.Contains(protocol, "tls")
	}

	if client.fallbackMode {
		return client.enhancedFallbackPrediction(packetData, protocol, direction), nil
	}

	response, err := client.makePredictionRequest(types.MLPredictionRequest{
		Packets: []types.MLPacketData{{
			Features:  client.prepareFeatures(packetData, isTLS),
			Protocol:  protocol,
			Direction: direction,
			Size:      len(packetData),
		}},
		ModelType: "cnn",
		Task:      "traffic_classification",
	})

	if err != nil {
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "dial tcp") ||
			strings.Contains(err.Error(), "timeout") {
			client.mlAvailable = false
		}

		isConnectionRefused := strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "dial tcp")

		now := time.Now()
		lastWarningNano := atomic.LoadInt64(&client.lastMLWarningUnixNano)
		lastWarning := time.Unix(0, lastWarningNano)
		shouldLog := now.Sub(lastWarning) > 5*time.Minute
		if shouldLog && !isConnectionRefused {
			atomic.StoreInt64(&client.lastMLWarningUnixNano, now.UnixNano())
		} else if shouldLog && isConnectionRefused && !client.mlAvailable {
			atomic.StoreInt64(&client.lastMLWarningUnixNano, now.UnixNano())
		} else {
			shouldLog = false
		}

		if shouldLog {
			if isConnectionRefused {
				log.Info("ML service at %s is not running, using fallback mode (ML still active). To enable ML service, start whispera-ml service.", client.baseURL)
			} else {
				log.Info("ML service temporarily unavailable, using fallback (ML still active): %v (will suppress further warnings for 5m)", err)
			}
		}
		return client.enhancedFallbackPrediction(packetData, protocol, direction), nil
	}

	client.mlAvailable = true
	return response, nil
}

func (client *PythonMLClient) DetectDPI(packetData []byte, protocol, direction string) (*types.MLPredictionResponse, error) {
	isTLS := protocol == "tls" || protocol == "dtls" || strings.Contains(protocol, "tls")
	features := client.prepareFeatures(packetData, isTLS)

	request := types.MLPredictionRequest{
		Packets: []types.MLPacketData{
			{
				Features:  features,
				Protocol:  protocol,
				Direction: direction,
				Size:      len(packetData),
			},
		},
		ModelType: "autoencoder",
		Task:      "dpi_detection",
	}

	return client.makePredictionRequest(request)
}

func (client *PythonMLClient) DetectAnomaly(packetData []byte, protocol, direction string) (*types.MLPredictionResponse, error) {
	isTLS := protocol == "tls" || protocol == "dtls" || strings.Contains(protocol, "tls")
	features := client.prepareFeatures(packetData, isTLS)

	request := types.MLPredictionRequest{
		Packets: []types.MLPacketData{
			{
				Features:  features,
				Protocol:  protocol,
				Direction: direction,
				Size:      len(packetData),
			},
		},
		ModelType: "autoencoder",
		Task:      "anomaly_detection",
	}

	return client.makePredictionRequest(request)
}

type PythonAPIPacketData struct {
	Data      []float64 `json:"data"`
	Protocol  string    `json:"protocol"`
	Direction string    `json:"direction"`
	Size      int       `json:"size"`
}

type PythonAPIPredictionRequest struct {
	Packets   []PythonAPIPacketData `json:"packets"`
	ModelType string                `json:"model_type"`
	Task      string                `json:"task"`
}

func (client *PythonMLClient) makePredictionRequest(request types.MLPredictionRequest) (*types.MLPredictionResponse, error) {
	pyRequest := PythonAPIPredictionRequest{
		Packets:   make([]PythonAPIPacketData, len(request.Packets)),
		ModelType: request.ModelType,
		Task:      request.Task,
	}
	for i, pkt := range request.Packets {
		pyRequest.Packets[i] = PythonAPIPacketData{
			Data:      pkt.Features,
			Protocol:  pkt.Protocol,
			Direction: pkt.Direction,
			Size:      pkt.Size,
		}
	}

	jsonData, err := json.Marshal(pyRequest)
	if err != nil {
		return nil, fmt.Errorf("ошибка сериализации запроса: %w", err)
	}

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "POST", client.baseURL+"/predict/traffic", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса: %w", err)
	}
	defer util.SafeClose("resp.Body", resp.Body.Close)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ошибка API: %d - %s", resp.StatusCode, string(body))
	}

	var response types.MLPredictionResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("ошибка десериализации ответа: %w", err)
	}

	return &response, nil
}

func (client *PythonMLClient) GetModelStatus() (map[string]interface{}, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "GET", client.baseURL+"/models/status", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса: %w", err)
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка запроса статуса: %w", err)
	}
	defer util.SafeClose("resp.Body", resp.Body.Close)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ошибка API: %d - %s", resp.StatusCode, string(body))
	}

	var status map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("ошибка десериализации статуса: %w", err)
	}

	return status, nil
}

func (client *PythonMLClient) HealthCheck() error {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "GET", client.baseURL+"/health", http.NoBody)
	if err != nil {
		return fmt.Errorf("ошибка создания запроса: %w", err)
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ошибка проверки здоровья: %w", err)
	}
	defer util.SafeClose("resp.Body", resp.Body.Close)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ML сервис недоступен: %d", resp.StatusCode)
	}

	return nil
}

// prepareFeatures возвращает сырые байты пакета нормированные в [0,1].
// Python-сервер восстанавливает байты через int(v*255) и сам вычисляет
// правильные 100 фич через _build_features() — ту же функцию что используется
// при обучении. Это гарантирует совпадение признакового пространства.
//
// Максимум 1500 байт (MTU) — Python принимает переменную длину.
func (client *PythonMLClient) prepareFeatures(packetData []byte, _ bool) []float64 {
	n := len(packetData)
	if n == 0 {
		return []float64{}
	}
	if n > 1500 {
		n = 1500
	}
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		out[i] = float64(packetData[i]) / 255.0
	}
	return out
}

func (client *PythonMLClient) LoadModels() error {
	if client.fallbackMode {
		return nil
	}

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "POST", client.baseURL+"/models/load", http.NoBody)
	if err != nil {
		return fmt.Errorf("ошибка создания запроса: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ошибка загрузки моделей: %w", err)
	}
	defer util.SafeClose("resp.Body", resp.Body.Close)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ошибка загрузки моделей: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

func (client *PythonMLClient) fallbackPrediction(packetData []byte, protocol, direction string) *types.MLPredictionResponse {
	classID := 0
	confidence := 0.0
	dpiType := 0
	dpiName := "unknown"
	isAnomaly := false
	anomalyScore := 0.0

	packetSize := len(packetData)
	entropy := client.calculateEntropy(packetData)
	protocolSignature := client.detectProtocolSignature(packetData)

	if protocolSignature == protocolTLS {
		classID = 0
		confidence = 0.85
	} else if protocolSignature == protocolHTTP {
		classID = 1
		confidence = 0.80
	} else if protocolSignature == "DNS" {
		classID = 2
		confidence = 0.90
	} else if entropy > 7.5 {
		classID = 3
		confidence = 0.75
	} else {
		classID = 4
		confidence = 0.60
	}

	if len(packetData) > 20 {
		if bytes.Contains(packetData, []byte{0x17, 0x03, 0x03}) {
			dpiType = 2
			dpiName = "tls_inspection"
		} else if bytes.Contains(packetData, []byte{0x80, 0x00}) {
			dpiType = 1
			dpiName = "http2_inspection"
		} else if bytes.Contains(packetData, []byte{0x47, 0x45, 0x54}) {
			dpiType = 1
			dpiName = "http_inspection"
		}
	}

	if packetSize > 0 {
		zeroBytes := 0
		for _, b := range packetData {
			if b == 0 {
				zeroBytes++
			}
		}

		zeroRatio := float64(zeroBytes) / float64(packetSize)
		if zeroRatio > 0.5 {
			isAnomaly = true
			anomalyScore = zeroRatio
		}
	}

	return &types.MLPredictionResponse{
		Predictions: []types.PredictionResult{
			{
				ClassID:      classID,
				Confidence:   confidence,
				Protocol:     protocol,
				Direction:    direction,
				DPIType:      dpiType,
				DPIName:      dpiName,
				IsAnomaly:    isAnomaly,
				AnomalyScore: anomalyScore,
			},
		},
		ModelUsed:  "realistic_fallback",
		Confidence: confidence,
		Timestamp:  time.Now(),
	}
}

// flowKey строит ключ кэша для потока: protocol+direction+первые4байта.
// Первые байты — это magic bytes протокола (TLS 0x16 0x03, DNS и т.д.),
// поэтому потоки одного типа получат один и тот же ключ — что нам и нужно.
func flowKey(packetData []byte, protocol, direction string) string {
	n := len(packetData)
	if n > 4 {
		n = 4
	}
	return protocol + "|" + direction + "|" + string(packetData[:n])
}

// ProcessTraffic — горячий путь данных.
//
// Схема для скорости:
//   1. Первый пакет потока (или каждый flowSampleEvery-й) → ML классификация
//      через Python (5 мс таймаут), результат кэшируется в flowCache.
//   2. Все остальные пакеты → применяем кэшированный профиль локально в Go,
//      без HTTP round-trip к Python.
//
// Это позволяет нейросети работать без влияния на пропускную способность:
// классификация делается 1 раз на поток, а не 8000 раз в секунду.
func (client *PythonMLClient) ProcessTraffic(packetData []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
	if len(packetData) == 0 {
		return packetData, fmt.Errorf("empty packet data")
	}
	if context == nil {
		return packetData, fmt.Errorf("nil traffic context")
	}
	if context.IsTLS {
		context.Protocol = context.TLSMode
	}
	// Пакеты < 64 байт не несут достаточно информации для классификации
	if len(packetData) < 64 {
		return packetData, nil
	}

	key := flowKey(packetData, context.Protocol, context.Direction)

	// ── Счётчик пакетов для данного потока ───────────────────────────────────
	var pktCount uint64
	if v, loaded := client.flowCounters.LoadOrStore(key, new(uint64)); loaded {
		pktCount = atomic.AddUint64(v.(*uint64), 1)
	} else {
		pktCount = 1
	}

	// ── Проверяем кэш потока ─────────────────────────────────────────────────
	needClassify := false
	if cached, ok := client.flowCache.Load(key); ok {
		profile := cached.(flowProfile)
		if time.Now().Before(profile.expires) && pktCount%flowSampleEvery != 0 {
			// Кэш свежий и не пора переклассифицировать —
			// применяем профиль локально без вызова Python
			if profile.dpiType > 0 {
				pred := types.PredictionResult{
					DPIType:    profile.dpiType,
					Confidence: profile.confidence,
				}
				return client.applyObfuscation(packetData, pred)
			}
			return packetData, nil
		}
		needClassify = true
	} else {
		needClassify = true
	}

	if !needClassify {
		return packetData, nil
	}

	// ── ML классификация (только для первого пакета / каждые N) ──────────────
	resultChan := client.resultChanPool.Get().(chan *types.MLPredictionResponse)
	errorChan := client.errorChanPool.Get().(chan error)

	go func() {
		resp, e := client.PredictTraffic(packetData, context.Protocol, context.Direction)
		select {
		case resultChan <- resp:
		default:
		}
		select {
		case errorChan <- e:
		default:
		}
	}()

	var response *types.MLPredictionResponse
	select {
	case response = <-resultChan:
		<-errorChan
		client.resultChanPool.Put(resultChan)
		client.errorChanPool.Put(errorChan)
	case <-time.After(5 * time.Millisecond):
		// Python не ответил за 5 мс — не блокируем пакет, просто пропускаем
		client.resultChanPool.Put(resultChan)
		client.errorChanPool.Put(errorChan)
		return packetData, nil
	}

	// ── Кэшируем профиль потока ───────────────────────────────────────────────
	profile := flowProfile{expires: time.Now().Add(flowCacheTTL)}
	if response != nil && len(response.Predictions) > 0 {
		pred := response.Predictions[0]
		profile.dpiType = pred.DPIType
		profile.confidence = pred.Confidence
	}
	client.flowCache.Store(key, profile)

	// ── Применяем обфускацию если DPI обнаружен ───────────────────────────────
	if profile.dpiType > 0 {
		pred := types.PredictionResult{
			DPIType:    profile.dpiType,
			Confidence: profile.confidence,
		}
		obfuscated, obfErr := client.applyObfuscation(packetData, pred)
		if obfErr != nil {
			log.Warn("Obfuscation failed: %v, using original data", obfErr)
			return packetData, nil
		}
		return obfuscated, nil
	}

	return packetData, nil
}

func (client *PythonMLClient) applyObfuscation(packetData []byte, pred types.PredictionResult) ([]byte, error) {
	var obfuscated []byte
	var err error

	switch pred.DPIType {
	case 1:
		obfuscated, err = client.applyVKMimicry(packetData, pred.Confidence)
	case 2:
		obfuscated, err = client.applyYandexMimicry(packetData, pred.Confidence)
	case 3:
		obfuscated, err = client.applyMailruMimicry(packetData, pred.Confidence)
	case 4:
		obfuscated, err = client.applyOzonMimicry(packetData, pred.Confidence)
	default:
		obfuscated = client.applyGenericObfuscation(packetData, pred.Confidence)
		err = nil
	}

	if err != nil {
		return client.applyGenericObfuscation(packetData, pred.Confidence), nil
	}

	return obfuscated, nil
}

func (client *PythonMLClient) applyVKMimicry(data []byte, confidence float64) ([]byte, error) {
	targetSize := 200 + int(confidence*800)
	if len(data) > 0 {
		targetSize = int(float64(len(data)) * (1.0 + confidence*0.5))
	}

	request := "POST /method/messages.get HTTP/1.1\r\n"
	request += "Host: api.vk.com\r\n"
	request += "User-Agent: VKAndroidApp/7.15-1234 (Android 11; SDK 30; arm64-v8a; samsung SM-G991B; ru)\r\n"
	request += "Content-Type: application/x-www-form-urlencoded\r\n"
	request += fmt.Sprintf("Content-Length: %d\r\n", len(data))
	request += "X-VK-Android-App: 7.15-1234\r\n"
	request += "X-VK-Language: ru\r\n"
	request += "\r\n"

	result := make([]byte, 0, targetSize)
	result = append(result, []byte(request)...)
	result = append(result, data...)

	if len(result) < targetSize {
		padding := client.generateVKPadding(targetSize - len(result))
		result = append(result, padding...)
	}

	return result[:targetSize], nil
}

func (client *PythonMLClient) applyYandexMimicry(data []byte, confidence float64) ([]byte, error) {
	targetSize := 300 + int(confidence*700)

	maxLen := len(data)
	if maxLen > 50 {
		maxLen = 50
	}
	request := fmt.Sprintf("GET /search/?text=%s HTTP/1.1\r\n", client.encodeDataForURL(data[:maxLen]))
	request += "Host: yandex.ru\r\n"
	request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
	request += "Accept: text/html,application/xhtml+xml\r\n"
	request += "\r\n"

	result := make([]byte, 0, targetSize)
	result = append(result, []byte(request)...)
	result = append(result, data...)

	if len(result) < targetSize {
		padding := client.generateYandexPadding(targetSize - len(result))
		result = append(result, padding...)
	}

	return result[:targetSize], nil
}

func (client *PythonMLClient) applyMailruMimicry(data []byte, confidence float64) ([]byte, error) {
	targetSize := 400 + int(confidence*600)

	request := "POST /api/v1/messages HTTP/1.1\r\n"
	request += "Host: e.mail.ru\r\n"
	request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
	request += "Content-Type: application/json\r\n"
	request += fmt.Sprintf("Content-Length: %d\r\n", len(data))
	request += "\r\n"

	result := make([]byte, 0, targetSize)
	result = append(result, []byte(request)...)
	result = append(result, data...)

	if len(result) < targetSize {
		padding := client.generateMailruPadding(targetSize - len(result))
		result = append(result, padding...)
	}

	return result[:targetSize], nil
}

func (client *PythonMLClient) applyOzonMimicry(data []byte, confidence float64) ([]byte, error) {
	targetSize := 600 + int(confidence*800)

	request := "GET /api/composer-api.bx/page/json/v2?url=/ HTTP/1.1\r\n"
	request += "Host: www.ozon.ru\r\n"
	request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
	request += "Accept: application/json\r\n"
	request += "\r\n"

	result := make([]byte, 0, targetSize)
	result = append(result, []byte(request)...)
	result = append(result, data...)

	if len(result) < targetSize {
		padding := client.generateOzonPadding(targetSize - len(result))
		result = append(result, padding...)
	}

	return result[:targetSize], nil
}

func (client *PythonMLClient) applyGenericObfuscation(data []byte, confidence float64) []byte {
	paddingSize := int(confidence * 100)
	if paddingSize < 20 {
		paddingSize = 20
	}

	result := make([]byte, len(data)+paddingSize)
	copy(result, data)

	for i := len(data); i < len(result); i++ {
		seed := byte(i) ^ data[i%len(data)]
		result[i] = 32 + (seed % 95)
	}

	return result
}

func (client *PythonMLClient) generateVKPadding(size int) []byte {
	padding := make([]byte, size)
	for i := range padding {
		switch i % 3 {
		case 0:
			padding[i] = byte(32 + (i % 95))
		case 1:
			padding[i] = byte(97 + (i % 26))
		default:
			padding[i] = byte(48 + (i % 10))
		}
	}
	return padding
}

func (client *PythonMLClient) generateYandexPadding(size int) []byte {
	padding := make([]byte, size)
	for i := range padding {
		padding[i] = byte(32 + (i % 95))
	}
	return padding
}

func (client *PythonMLClient) generateMailruPadding(size int) []byte {
	padding := make([]byte, size)
	for i := range padding {
		padding[i] = byte(97 + (i % 26))
	}
	return padding
}

func (client *PythonMLClient) generateOzonPadding(size int) []byte {
	padding := make([]byte, size)
	for i := range padding {
		padding[i] = byte(48 + (i % 10))
	}
	return padding
}

func (client *PythonMLClient) encodeDataForURL(data []byte) string {
	return fmt.Sprintf("%x", data)
}

func (client *PythonMLClient) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	dataLen := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / dataLen
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (client *PythonMLClient) detectProtocolSignature(data []byte) string {
	if len(data) < 4 {
		return "unknown"
	}

	if len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03 {
		return protocolTLS
	}

	if len(data) >= 4 {
		header := string(data[:minInt(4, len(data))])
		if header == "GET " || header == "POST" || header == "PUT " || header == "HEAD" {
			return "HTTP"
		}
	}

	if len(data) >= 12 && data[2] == 0x01 && data[3] == 0x00 {
		return "DNS"
	}

	if len(data) >= 4 && data[0] == 'S' && data[1] == 'S' && data[2] == 'H' {
		return "SSH"
	}

	return "unknown"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (client *PythonMLClient) enhancedFallbackPrediction(packetData []byte, protocol string, direction string) *types.MLPredictionResponse {
	isTLS := protocol == "tls" || protocol == "dtls" || strings.Contains(strings.ToLower(protocol), "tls")
	features := client.prepareFeatures(packetData, isTLS)

	internalAnomalyScore := 0.0
	if len(features) > 2 {
		internalAnomalyScore = features[2]
	}

	entropy := client.calculateEntropy(packetData)
	signature := client.detectProtocolSignature(packetData)

	var predictions []types.PredictionResult

	confidenceMultiplier := 1.0 - (internalAnomalyScore * 0.5)
	if confidenceMultiplier < 0.1 {
		confidenceMultiplier = 0.1
	}

	packetSize := len(packetData)
	if packetSize < 64 {
		predictions = append(predictions, types.PredictionResult{
			ClassID:    1,
			Confidence: 0.85 * confidenceMultiplier,
			Protocol:   protocol,
			Direction:  direction,
		})
	} else if packetSize < 256 {
		predictions = append(predictions, types.PredictionResult{
			ClassID:    2,
			Confidence: 0.8 * confidenceMultiplier,
			Protocol:   protocol,
			Direction:  direction,
		})
	} else if packetSize < 1024 {
		predictions = append(predictions, types.PredictionResult{
			ClassID:    3,
			Confidence: 0.75 * confidenceMultiplier,
			Protocol:   protocol,
			Direction:  direction,
		})
	} else if packetSize < 4096 {
		predictions = append(predictions, types.PredictionResult{
			ClassID:    4,
			Confidence: 0.7 * confidenceMultiplier,
			Protocol:   protocol,
			Direction:  direction,
		})
	} else {
		predictions = append(predictions, types.PredictionResult{
			ClassID:    5,
			Confidence: 0.65 * confidenceMultiplier,
			Protocol:   protocol,
			Direction:  direction,
		})
	}

	switch protocol {
	case "HTTP":
		if client.isHTTPRequest(packetData) {
			predictions = append(predictions, types.PredictionResult{
				ClassID:    10,
				Confidence: 0.95 * confidenceMultiplier,
				Protocol:   protocol,
				Direction:  direction,
			})
		} else if client.isHTTPResponse(packetData) {
			predictions = append(predictions, types.PredictionResult{
				ClassID:    11,
				Confidence: 0.95 * confidenceMultiplier,
				Protocol:   protocol,
				Direction:  direction,
			})
		} else {
			predictions = append(predictions, types.PredictionResult{
				ClassID:    12,
				Confidence: 0.9 * confidenceMultiplier,
				Protocol:   protocol,
				Direction:  direction,
			})
		}
	case "TLS":
		if client.isTLSHandshake(packetData) || signature == "TLS" {
			predictions = append(predictions, types.PredictionResult{
				ClassID:    20,
				Confidence: 0.95 * confidenceMultiplier,
				Protocol:   protocol,
				Direction:  direction,
			})
		} else {
			predictions = append(predictions, types.PredictionResult{
				ClassID:    21,
				Confidence: 0.9 * confidenceMultiplier,
				Protocol:   protocol,
				Direction:  direction,
			})
		}
	case "WebSocket":
		predictions = append(predictions, types.PredictionResult{
			ClassID:    30,
			Confidence: 0.9 * confidenceMultiplier,
			Protocol:   protocol,
			Direction:  direction,
		})
	default:
		predictions = append(predictions, types.PredictionResult{
			ClassID:    0,
			Confidence: 0.5 * confidenceMultiplier,
			Protocol:   protocol,
			Direction:  direction,
		})
	}

	if entropy > 7.5 {
		for i := range predictions {
			predictions[i].Confidence = math.Min(0.99, predictions[i].Confidence+0.05)
		}
	}

	return &types.MLPredictionResponse{
		Predictions: predictions,
		ModelUsed:   "enhanced_fallback_heuristic",
		Confidence:  0.8,
		Timestamp:   time.Now(),
	}
}

func (client *PythonMLClient) isHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	httpMethods := []string{"GET ", "POST", "PUT ", "HEAD", "DELETE", "OPTIONS", "PATCH"}
	dataStr := string(data[:minInt(20, len(data))])

	for _, method := range httpMethods {
		if strings.HasPrefix(dataStr, method) {
			return true
		}
	}

	return false
}

func (client *PythonMLClient) isHTTPResponse(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	dataStr := string(data[:minInt(20, len(data))])
	return strings.HasPrefix(dataStr, "HTTP/")
}

func (client *PythonMLClient) isTLSHandshake(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	return data[0] == 0x16
}
