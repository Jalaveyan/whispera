package ml

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/obfuscation/core/types"
)

var nativeEngine *NativeMLEngine

var overrideMLServerURL string
var overrideMLToken string
var overrideMu sync.RWMutex

func SetMLServerURL(url, token string) {
	overrideMu.Lock()
	overrideMLServerURL = url
	overrideMLToken = token
	overrideMu.Unlock()
	if url != "" {
		os.Setenv("WHISPERA_ML_SERVER", url)
	}
}

func GetMLServerURL() string {
	overrideMu.RLock()
	defer overrideMu.RUnlock()
	if overrideMLServerURL != "" {
		return overrideMLServerURL
	}
	return os.Getenv("WHISPERA_ML_SERVER")
}

func init() {
	modelDir := os.Getenv("WHISPERA_ML_MODEL_DIR")
	if modelDir == "" {
		modelDir = "./ml_models"
	}
	nativeEngine = NewNativeMLEngine(modelDir)

	evasion.NewPythonMLClientLocal = func() evasion.PythonMLClient {
		mode := strings.ToLower(os.Getenv("WHISPERA_ML_MODE"))
		if mode == "python" {
			realClient := NewPythonMLClientLocal()
			return &PythonMLClientEvasionAdapter{client: realClient}
		}
		return &NativeMLClientEvasionAdapter{engine: nativeEngine}
	}
}

type PythonMLClientEvasionAdapter struct {
	client *PythonMLClient
}

func (a *PythonMLClientEvasionAdapter) ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
	protocol := "tcp"
	direction := "outbound"
	if context != nil {
		if context.Protocol != "" {
			protocol = context.Protocol
		}
		if context.Direction != "" {
			direction = context.Direction
		}
	}

	response, err := a.client.PredictTraffic(data, protocol, direction)
	if err != nil {
		return data, nil
	}

	if len(response.Predictions) > 0 {
		pred := response.Predictions[0]
		if pred.DPIType > 0 && pred.Confidence > 0.7 {
			if pred.Confidence > 0.8 {
			}
		}
	}

	return data, nil
}

func (a *PythonMLClientEvasionAdapter) HealthCheck() error {
	return a.client.HealthCheck()
}

func (a *PythonMLClientEvasionAdapter) LoadModels() error {
	return a.client.LoadModels()
}

type NativeMLClientEvasionAdapter struct {
	engine    *NativeMLEngine
	flowCache sync.Map
	sampleCount uint64
}

type nativeFlowProfile struct {
	dpiType    int
	confidence float64
	expires    time.Time
}

func (a *NativeMLClientEvasionAdapter) ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	protocol := "tcp"
	direction := "outbound"
	if context != nil {
		if context.Protocol != "" {
			protocol = context.Protocol
		}
		if context.Direction != "" {
			direction = context.Direction
		}
	}

	key := protocol + ":" + direction

	if cached, ok := a.flowCache.Load(key); ok {
		fp := cached.(*nativeFlowProfile)
		if time.Now().Before(fp.expires) {
			if fp.dpiType > 0 {
				obf, err := applyNativeObfuscation(data, fp.dpiType, fp.confidence)
				if err != nil {
					return data, nil
				}
				if fp.confidence > adversarialConfTarget {
					obf = GetAdversarialEngine().PerturbPacket(obf, adversarialBudgetDefault)
				}
				return obf, nil
			}
			return data, nil
		}
		a.flowCache.Delete(key)
	}

	atomic.AddUint64(&a.sampleCount, 1)

	if !a.engine.QualitySamplesReady() {
		a.engine.AddSample(data, 0, 0)
		return data, nil
	}

	resp := a.engine.Predict(data, protocol, direction)
	if resp == nil || len(resp.Predictions) == 0 {
		return data, nil
	}

	pred := resp.Predictions[0]
	a.engine.AddSample(data, pred.ClassID, pred.DPIType)

	fp := &nativeFlowProfile{
		dpiType:    pred.DPIType,
		confidence: pred.Confidence,
		expires:    time.Now().Add(30 * time.Second),
	}
	a.flowCache.Store(key, fp)

	if pred.DPIType > 0 && pred.Confidence > 0.5 {
		if sni := extractTLSSNI(data); sni != "" {
			a.engine.StoreSNI(sni)
		}
		obf, err := applyNativeObfuscation(data, pred.DPIType, pred.Confidence)
		if err != nil {
			return data, nil
		}
		if pred.Confidence > adversarialConfTarget {
			obf = GetAdversarialEngine().PerturbPacket(obf, adversarialBudgetDefault)
		}
		return obf, nil
	}

	return data, nil
}

func applyNativeObfuscation(data []byte, dpiType int, confidence float64) ([]byte, error) {
	switch dpiType {
	case 1:
		return applyVKMimicry(data, confidence)
	case 2:
		return applyYandexMimicry(data, confidence)
	case 3:
		return applyMailruMimicry(data, confidence)
	case 4:
		return applyOzonMimicry(data, confidence)
	case 5:
		return applyOKMimicry(data, confidence)
	default:
		return applyGenericObfuscation(data, confidence), nil
	}
}

func applyVKMimicry(data []byte, confidence float64) ([]byte, error) {
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
		result = append(result, generatePadding(targetSize-len(result), 0)...)
	}
	if len(result) > targetSize {
		result = result[:targetSize]
	}

	return result, nil
}

func applyYandexMimicry(data []byte, confidence float64) ([]byte, error) {
	targetSize := 300 + int(confidence*700)

	maxLen := len(data)
	if maxLen > 50 {
		maxLen = 50
	}
	request := fmt.Sprintf("GET /search/?text=%s HTTP/1.1\r\n", hex.EncodeToString(data[:maxLen]))
	request += "Host: yandex.ru\r\n"
	request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
	request += "Accept: text/html,application/xhtml+xml\r\n"
	request += "\r\n"

	result := make([]byte, 0, targetSize)
	result = append(result, []byte(request)...)
	result = append(result, data...)

	if len(result) < targetSize {
		result = append(result, generatePadding(targetSize-len(result), 1)...)
	}
	if len(result) > targetSize {
		result = result[:targetSize]
	}

	return result, nil
}

func applyMailruMimicry(data []byte, confidence float64) ([]byte, error) {
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
		result = append(result, generatePadding(targetSize-len(result), 2)...)
	}
	if len(result) > targetSize {
		result = result[:targetSize]
	}

	return result, nil
}

func applyOzonMimicry(data []byte, confidence float64) ([]byte, error) {
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
		result = append(result, generatePadding(targetSize-len(result), 3)...)
	}
	if len(result) > targetSize {
		result = result[:targetSize]
	}

	return result, nil
}

func applyOKMimicry(data []byte, confidence float64) ([]byte, error) {
	targetSize := 300 + int(confidence*600)

	request := "POST /api/feed/get HTTP/1.1\r\n"
	request += "Host: api.ok.ru\r\n"
	request += "User-Agent: OKApp/23.11.1 (Android 13; sdk=33; arm64-v8a)\r\n"
	request += "Content-Type: application/x-www-form-urlencoded\r\n"
	request += fmt.Sprintf("Content-Length: %d\r\n", len(data))
	request += "X-OK-APP-KEY: CGMMEJLGDIHBABABA\r\n"
	request += "\r\n"

	result := make([]byte, 0, targetSize)
	result = append(result, []byte(request)...)
	result = append(result, data...)

	if len(result) < targetSize {
		result = append(result, generatePadding(targetSize-len(result), 4)...)
	}
	if len(result) > targetSize {
		result = result[:targetSize]
	}

	return result, nil
}

func applyGenericObfuscation(data []byte, confidence float64) []byte {
	paddingSize := int(confidence * 120)
	if paddingSize < 20 {
		paddingSize = 20
	}
	result := make([]byte, len(data)+paddingSize)
	copy(result, data)

	var rndBuf [64]byte
	rand.Read(rndBuf[:])
	for i := len(data); i < len(result); i++ {
		seed := rndBuf[i%64] ^ data[i%len(data)]
		result[i] = 32 + (seed % 95)
	}

	return result
}

func generatePadding(size int, variant int) []byte {
	padding := make([]byte, size)
	var rndBuf [32]byte
	rand.Read(rndBuf[:])
	for i := range padding {
		base := rndBuf[i%32]
		switch variant {
		case 0:
			switch i % 3 {
			case 0:
				padding[i] = 32 + (base % 95)
			case 1:
				padding[i] = 97 + (base % 26)
			default:
				padding[i] = 48 + (base % 10)
			}
		case 1:
			padding[i] = 32 + (base % 95)
		case 2:
			padding[i] = 97 + (base % 26)
		case 3:
			padding[i] = 48 + (base % 10)
		default:
			padding[i] = 65 + (base % 26)
		}
	}
	return padding
}

func (a *NativeMLClientEvasionAdapter) HealthCheck() error {
	return nil
}

func (a *NativeMLClientEvasionAdapter) LoadModels() error {
	return nil
}

func GetNativeEngine() *NativeMLEngine {
	return nativeEngine
}
