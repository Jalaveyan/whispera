package neural

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"whispera/neural/types"
)

type DataCollector struct {
	samples      []TrafficSample
	mu           sync.RWMutex
	maxSamples   int
	saveDir      string
	lastSave     time.Time
	saveInterval time.Duration

	totalCollected     uint64
	totalPredictions   uint64
	correctPredictions uint64
	falsePositives     uint64
	falseNegatives     uint64

	totalLatencyNs  uint64
	predictionCount uint64

	featureStats *FeatureStatistics

	onNewSample func(sample TrafficSample)

	mlServerURL   string
	mlToken       string
	lastUpload    time.Time
	uploadedCount uint64

	connectionActive uint32
	qualitySamples   uint64
	writeIdx         int
}

type TrafficSample struct {
	Timestamp time.Time `json:"timestamp"`
	Features  []float64 `json:"features"`
	Protocol  string    `json:"protocol"`
	Direction string    `json:"direction"`
	Size      int       `json:"size"`
	Entropy   float64   `json:"entropy"`

	TrafficClass int     `json:"traffic_class"`
	DPIDetected  bool    `json:"dpi_detected"`
	DPIType      int     `json:"dpi_type"`
	IsAnomaly    bool    `json:"is_anomaly"`
	AnomalyScore float64 `json:"anomaly_score"`

	PredictedClass int     `json:"predicted_class"`
	Confidence     float64 `json:"confidence"`
	WasCorrect     bool    `json:"was_correct"`
}

type FeatureStatistics struct {
	Mean     []float64 `json:"mean"`
	Variance []float64 `json:"variance"`
	Min      []float64 `json:"min"`
	Max      []float64 `json:"max"`
	Count    int64     `json:"count"`
	mu       sync.RWMutex
}

func NewDataCollector(maxSamples int, saveDir string) *DataCollector {
	dc := &DataCollector{
		samples:      make([]TrafficSample, 0, maxSamples),
		maxSamples:   maxSamples,
		saveDir:      saveDir,
		lastSave:     time.Now(),
		saveInterval: 5 * time.Minute,
		featureStats: NewFeatureStatistics(100),
	}

	dc.loadLatestFromDisk()

	go dc.backgroundSaveLoop()

	return dc
}

func (dc *DataCollector) loadLatestFromDisk() {
	if dc.saveDir == "" {
		return
	}
	entries, err := os.ReadDir(dc.saveDir)
	if err != nil {
		return
	}

	var latestFile string
	for _, e := range entries {
		if !e.IsDir() && len(e.Name()) > 11 &&
			e.Name()[:11] == "ml_samples_" &&
			filepath.Ext(e.Name()) == ".json" {
			latestFile = e.Name()
		}
	}
	if latestFile == "" {
		return
	}

	data, err := os.ReadFile(filepath.Join(dc.saveDir, latestFile))
	if err != nil {
		return
	}

	var loaded []TrafficSample
	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}

	if len(loaded) > dc.maxSamples {
		loaded = loaded[len(loaded)-dc.maxSamples:]
	}

	dc.mu.Lock()
	dc.samples = append(dc.samples, loaded...)
	dc.mu.Unlock()
}

func NewFeatureStatistics(numFeatures int) *FeatureStatistics {
	return &FeatureStatistics{
		Mean:     make([]float64, numFeatures),
		Variance: make([]float64, numFeatures),
		Min:      make([]float64, numFeatures),
		Max:      make([]float64, numFeatures),
		Count:    0,
	}
}

func (dc *DataCollector) SetConnectionActive(active bool) {
	if active {
		atomic.StoreUint32(&dc.connectionActive, 1)
	} else {
		atomic.StoreUint32(&dc.connectionActive, 0)
		go func() { _ = dc.SaveToDisk() }()
	}
}

func (dc *DataCollector) IsConnectionActive() bool {
	return atomic.LoadUint32(&dc.connectionActive) == 1
}

func isGarbageSample(sample TrafficSample) bool {
	if len(sample.Features) == 0 || sample.Size < 8 {
		return true
	}
	if sample.Entropy < 0.5 || sample.Entropy > 7.9 {
		return true
	}

	nonZero := 0
	sum := 0.0
	for _, f := range sample.Features {
		if f != 0 {
			nonZero++
			sum += f
		}
	}
	n := float64(len(sample.Features))
	if float64(nonZero) < n*0.25 {
		return true
	}

	mean := sum / n
	variance := 0.0
	for _, f := range sample.Features {
		d := f - mean
		variance += d * d
	}
	variance /= n
	if variance < 1e-9 {
		return true
	}

	coverage := float64(nonZero) / n
	stddev := sqrtDC(variance)
	if coverage*min64(1.0, stddev/10.0) < 0.01 {
		return true
	}
	return false
}

func sqrtDC(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 10; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func (dc *DataCollector) CollectSample(sample TrafficSample) {
	if !dc.IsConnectionActive() {
		return
	}
	if isGarbageSample(sample) {
		return
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()

	if len(dc.samples) < dc.maxSamples {
		dc.samples = append(dc.samples, sample)
		dc.writeIdx = len(dc.samples) % dc.maxSamples
	} else {
		minConf := dc.samples[dc.writeIdx].Confidence
		evict := dc.writeIdx
		for i := 0; i < dc.maxSamples; i++ {
			if dc.samples[i].Confidence < minConf {
				minConf = dc.samples[i].Confidence
				evict = i
			}
		}
		if sample.Confidence <= minConf {
			return
		}
		dc.samples[evict] = sample
		dc.writeIdx = (evict + 1) % dc.maxSamples
	}

	atomic.AddUint64(&dc.totalCollected, 1)

	if sample.Confidence > 0.7 {
		atomic.AddUint64(&dc.qualitySamples, 1)
	}

	if len(sample.Features) > 0 {
		dc.featureStats.Update(sample.Features)
	}

	if dc.onNewSample != nil {
		cb := dc.onNewSample
		go cb(sample)
	}
}

func (dc *DataCollector) RecordPrediction(predicted, actual int, confidence float64, latencyNs int64) {
	atomic.AddUint64(&dc.totalPredictions, 1)
	atomic.AddUint64(&dc.totalLatencyNs, uint64(latencyNs))
	atomic.AddUint64(&dc.predictionCount, 1)

	if predicted == actual {
		atomic.AddUint64(&dc.correctPredictions, 1)
	} else if predicted > 0 && actual == 0 {
		atomic.AddUint64(&dc.falsePositives, 1)
	} else if predicted == 0 && actual > 0 {
		atomic.AddUint64(&dc.falseNegatives, 1)
	}
}

func (dc *DataCollector) GetMetrics() RuntimeMetrics {
	total := atomic.LoadUint64(&dc.totalPredictions)
	correct := atomic.LoadUint64(&dc.correctPredictions)
	latencySum := atomic.LoadUint64(&dc.totalLatencyNs)
	count := atomic.LoadUint64(&dc.predictionCount)

	var accuracy float64
	if total > 0 {
		accuracy = float64(correct) / float64(total)
	}

	var avgLatency time.Duration
	if count > 0 {
		avgLatency = time.Duration(latencySum / count)
	}

	dc.mu.RLock()
	sampleCount := len(dc.samples)
	lastSave := dc.lastSave
	dc.mu.RUnlock()

	return RuntimeMetrics{
		TotalCollected:     atomic.LoadUint64(&dc.totalCollected),
		TotalPredictions:   total,
		CorrectPredictions: correct,
		FalsePositives:     atomic.LoadUint64(&dc.falsePositives),
		FalseNegatives:     atomic.LoadUint64(&dc.falseNegatives),
		Accuracy:           accuracy,
		AvgLatency:         avgLatency,
		SampleCount:        sampleCount,
		LastSave:           lastSave,
	}
}

type RuntimeMetrics struct {
	TotalCollected     uint64        `json:"total_collected"`
	TotalPredictions   uint64        `json:"total_predictions"`
	CorrectPredictions uint64        `json:"correct_predictions"`
	FalsePositives     uint64        `json:"false_positives"`
	FalseNegatives     uint64        `json:"false_negatives"`
	Accuracy           float64       `json:"accuracy"`
	AvgLatency         time.Duration `json:"avg_latency"`
	SampleCount        int           `json:"sample_count"`
	LastSave           time.Time     `json:"last_save"`
}

func (dc *DataCollector) GetSamples() []TrafficSample {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	result := make([]TrafficSample, len(dc.samples))
	copy(result, dc.samples)
	return result
}

func (dc *DataCollector) GetTrainingData() types.MLTrainingData {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	data := types.MLTrainingData{
		Features: make([][]float64, len(dc.samples)),
		Labels:   make([]int, len(dc.samples)),
		Metadata: make([]map[string]interface{}, len(dc.samples)),
	}

	for i, sample := range dc.samples {
		data.Features[i] = sample.Features
		data.Labels[i] = sample.TrafficClass
		data.Metadata[i] = map[string]interface{}{
			"protocol":    sample.Protocol,
			"direction":   sample.Direction,
			"size":        sample.Size,
			"entropy":     sample.Entropy,
			"dpi_type":    sample.DPIType,
			"was_correct": sample.WasCorrect,
		}
	}

	return data
}

func (dc *DataCollector) SaveToDisk() error {
	dc.mu.RLock()
	samples := make([]TrafficSample, len(dc.samples))
	copy(samples, dc.samples)
	dc.mu.RUnlock()

	if len(samples) == 0 {
		return nil
	}

	if err := os.MkdirAll(dc.saveDir, 0755); err != nil {
		return err
	}

	filename := filepath.Join(dc.saveDir,
		"ml_samples_"+time.Now().Format("20060102_150405")+".json")

	data, err := json.MarshalIndent(samples, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return err
	}

	dc.mu.Lock()
	dc.lastSave = time.Now()
	dc.mu.Unlock()

	return nil
}

func (dc *DataCollector) backgroundSaveLoop() {
	ticker := time.NewTicker(dc.saveInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := dc.SaveToDisk(); err != nil {
		}
	}
}

func (dc *DataCollector) SetMLServer(url, token string) {
	dc.mu.Lock()
	dc.mlServerURL = url
	dc.mlToken = token
	dc.mu.Unlock()
	if url != "" {
		uploadHTTPClient = buildUploadHTTPClient(url)
		go dc.backgroundUploadLoop()
		go dc.backgroundDownloadLoop()
	}
}

func buildUploadHTTPClient(mlServerURL string) *http.Client {
	isLocal := strings.Contains(mlServerURL, "127.0.0.1") ||
		strings.Contains(mlServerURL, "localhost") ||
		strings.Contains(mlServerURL, "::1")
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: isLocal,
			},
		},
	}
}

var uploadHTTPClient = buildUploadHTTPClient("")

func (dc *DataCollector) UploadToMLServer() error {
	dc.mu.RLock()
	mlServerURL := dc.mlServerURL
	mlToken := dc.mlToken
	if mlServerURL == "" || len(dc.samples) == 0 {
		dc.mu.RUnlock()
		return nil
	}
	batch := make([]TrafficSample, len(dc.samples))
	copy(batch, dc.samples)
	dc.mu.RUnlock()

	// Include NN weights so the aggregation server can run FedAvg across clients.
	var weights *ModelState
	if nativeEngine != nil {
		weights = nativeEngine.ExportModelState()
	}

	payload, err := json.Marshal(map[string]interface{}{
		"samples":     batch,
		"uploaded_at": time.Now().UTC(),
		"count":       len(batch),
		"weights":     weights,
	})
	if err != nil {
		return err
	}

	baseURL := mlServerURL
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"federated/upload", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if mlToken != "" {
		req.Header.Set("Authorization", "Bearer "+mlToken)
	}

	resp, err := uploadHTTPClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		atomic.AddUint64(&dc.uploadedCount, uint64(len(batch)))
		dc.lastUpload = time.Now()
	}
	return nil
}

// downloadAggregatedModel fetches the server-side FedAvg model and blends it
// into the local engine weights (alpha=0.7 trusts local data more).
func (dc *DataCollector) downloadAggregatedModel() error {
	dc.mu.RLock()
	mlServerURL := dc.mlServerURL
	mlToken := dc.mlToken
	dc.mu.RUnlock()
	if mlServerURL == "" {
		return nil
	}
	baseURL := mlServerURL
	if baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"federated/download", nil)
	if err != nil {
		return err
	}
	if mlToken != "" {
		req.Header.Set("Authorization", "Bearer "+mlToken)
	}
	resp, err := uploadHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil // server may not have aggregated model yet — not an error
	}
	var result struct {
		Weights *ModelState `json:"weights"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if result.Weights != nil && nativeEngine != nil {
		nativeEngine.ImportModelState(result.Weights, 0.7)
	}
	return nil
}

func (dc *DataCollector) backgroundUploadLoop() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if err := dc.UploadToMLServer(); err != nil {
		}
	}
}

func (dc *DataCollector) backgroundDownloadLoop() {
	// First download after 2 minutes (give server time to aggregate).
	time.Sleep(2 * time.Minute)
	if err := dc.downloadAggregatedModel(); err != nil {
	}
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if err := dc.downloadAggregatedModel(); err != nil {
		}
	}
}

func (dc *DataCollector) SetOnNewSample(callback func(sample TrafficSample)) {
	dc.mu.Lock()
	dc.onNewSample = callback
	dc.mu.Unlock()
}

func (fs *FeatureStatistics) Update(features []float64) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.Count++
	n := float64(fs.Count)

	for i := 0; i < len(features) && i < len(fs.Mean); i++ {
		delta := features[i] - fs.Mean[i]
		fs.Mean[i] += delta / n
		delta2 := features[i] - fs.Mean[i]
		fs.Variance[i] += delta * delta2

		if fs.Count == 1 || features[i] < fs.Min[i] {
			fs.Min[i] = features[i]
		}
		if fs.Count == 1 || features[i] > fs.Max[i] {
			fs.Max[i] = features[i]
		}
	}
}

func (fs *FeatureStatistics) NormalizeFeatures(features []float64) []float64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.Count < 100 {
		return features
	}

	normalized := make([]float64, len(features))
	for i := 0; i < len(features) && i < len(fs.Mean); i++ {
		variance := fs.Variance[i] / float64(fs.Count-1)
		if variance > 0 {
			stddev := sqrt(variance)
			if stddev > 0 {
				normalized[i] = (features[i] - fs.Mean[i]) / stddev
			}
		} else {
			normalized[i] = features[i]
		}
	}
	return normalized
}

func sqrt(x float64) float64 {
	if x < 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 10; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}

func (dc *DataCollector) GetFeatureStats() *FeatureStatistics {
	return dc.featureStats
}

func (dc *DataCollector) Clear() {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	dc.samples = dc.samples[:0]
	dc.writeIdx = 0
	atomic.StoreUint64(&dc.qualitySamples, 0)
	atomic.StoreUint64(&dc.totalCollected, 0)
}
