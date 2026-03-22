package ml

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/core/types"
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

	// ML server upload
	mlServerURL  string
	mlToken      string
	lastUpload   time.Time
	uploadedCount uint64
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

	go dc.backgroundSaveLoop()

	return dc
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

func (dc *DataCollector) CollectSample(sample TrafficSample) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if len(dc.samples) >= dc.maxSamples {
		dc.samples = dc.samples[1:]
	}
	dc.samples = append(dc.samples, sample)

	atomic.AddUint64(&dc.totalCollected, 1)

	if len(sample.Features) > 0 {
		dc.featureStats.Update(sample.Features)
	}

	if dc.onNewSample != nil {
		go dc.onNewSample(sample)
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
		LastSave:           dc.lastSave,
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

	log.Info("Saved %d samples to %s", len(samples), filename)
	return nil
}

func (dc *DataCollector) backgroundSaveLoop() {
	ticker := time.NewTicker(dc.saveInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := dc.SaveToDisk(); err != nil {
			log.Warn("Save error: %v", err)
		}
	}
}

func (dc *DataCollector) SetMLServer(url, token string) {
	dc.mlServerURL = url
	dc.mlToken = token
	if url != "" {
		go dc.backgroundUploadLoop()
	}
}

var uploadHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// UploadToMLServer sends collected samples to the ML server for centralized learning.
func (dc *DataCollector) UploadToMLServer() error {
	if dc.mlServerURL == "" {
		return nil
	}

	dc.mu.RLock()
	if len(dc.samples) == 0 {
		dc.mu.RUnlock()
		return nil
	}
	batch := make([]TrafficSample, len(dc.samples))
	copy(batch, dc.samples)
	dc.mu.RUnlock()

	payload, err := json.Marshal(map[string]interface{}{
		"samples":    batch,
		"uploaded_at": time.Now().UTC(),
		"count":      len(batch),
	})
	if err != nil {
		return err
	}

	url := dc.mlServerURL
	if url[len(url)-1] != '/' {
		url += "/"
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url+"federated/upload", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if dc.mlToken != "" {
		req.Header.Set("Authorization", "Bearer "+dc.mlToken)
	}

	resp, err := uploadHTTPClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		atomic.AddUint64(&dc.uploadedCount, uint64(len(batch)))
		dc.lastUpload = time.Now()
		log.Info("Uploaded %d samples to ML server (%d total)", len(batch), atomic.LoadUint64(&dc.uploadedCount))
	}
	return nil
}

func (dc *DataCollector) backgroundUploadLoop() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if err := dc.UploadToMLServer(); err != nil {
			log.Warn("ML upload error: %v", err)
		}
	}
}

func (dc *DataCollector) SetOnNewSample(callback func(sample TrafficSample)) {
	dc.onNewSample = callback
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
	dc.samples = make([]TrafficSample, 0, dc.maxSamples)
}
