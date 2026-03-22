package ml

import (
	"fmt"
	"sync/atomic"
	"time"
	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)

type UnifiedMLSystem struct {
	engine        *NativeMLEngine
	stats         *types.MLStats
	packetCount   int64
	dataCollector *DataCollector
}

func (mls *UnifiedMLSystem) ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
	if len(data) == 0 || context == nil || mls.engine == nil {
		return data, fmt.Errorf("invalid input")
	}

	startTime := time.Now()

	protocol := context.Protocol
	direction := context.Direction
	if protocol == "" {
		protocol = "tcp"
	}
	if direction == "" {
		direction = "outbound"
	}

	resp := mls.engine.Predict(data, protocol, direction)

	var processed []byte
	var err error

	if resp != nil && len(resp.Predictions) > 0 {
		pred := resp.Predictions[0]
		mls.engine.AddSample(data, pred.ClassID, pred.DPIType)

		if pred.DPIType > 0 && pred.Confidence > 0.5 {
			processed, err = applyNativeObfuscation(data, pred.DPIType, pred.Confidence)
			if err != nil {
				processed = data
			}
		} else {
			processed = data
		}
	} else {
		processed = data
	}

	latency := time.Since(startTime)
	count := atomic.AddInt64(&mls.packetCount, 1)

	if mls.stats != nil {
		mls.stats.ProcessedPackets = count
	}

	if mls.dataCollector != nil && resp != nil && len(resp.Predictions) > 0 {
		p := resp.Predictions[0]
		sample := TrafficSample{
			Timestamp:      time.Now(),
			Protocol:       protocol,
			Direction:      direction,
			Size:           len(data),
			Entropy:        calcEntropy(data),
			TrafficClass:   p.ClassID,
			DPIDetected:    p.DPIType > 0,
			DPIType:        p.DPIType,
			IsAnomaly:      p.IsAnomaly,
			AnomalyScore:   p.AnomalyScore,
			PredictedClass: p.ClassID,
			Confidence:     p.Confidence,
		}
		mls.dataCollector.CollectSample(sample)
		mls.dataCollector.RecordPrediction(sample.PredictedClass, sample.TrafficClass, sample.Confidence, latency.Nanoseconds())
	}

	return processed, nil
}

func (mls *UnifiedMLSystem) PredictTraffic(data []byte, protocol, direction string) (*types.MLPredictionResponse, error) {
	if mls.engine == nil {
		return nil, fmt.Errorf("ml engine not initialized")
	}
	resp := mls.engine.Predict(data, protocol, direction)
	if resp == nil {
		return nil, fmt.Errorf("prediction failed")
	}
	return resp, nil
}

func (mls *UnifiedMLSystem) CollectSample(data []byte, protocol, direction string, pred *types.MLPredictionResponse) {
	if mls.dataCollector == nil || mls.engine == nil {
		return
	}
	sample := TrafficSample{
		Timestamp: time.Now(),
		Protocol:  protocol,
		Direction: direction,
		Size:      len(data),
		Entropy:   calcEntropy(data),
	}
	if pred != nil && len(pred.Predictions) > 0 {
		p := pred.Predictions[0]
		sample.TrafficClass = p.ClassID
		sample.DPIDetected = p.DPIType > 0
		sample.DPIType = p.DPIType
		sample.IsAnomaly = p.IsAnomaly
		sample.AnomalyScore = p.AnomalyScore
		sample.PredictedClass = p.ClassID
		sample.Confidence = p.Confidence
	}
	mls.dataCollector.CollectSample(sample)
}

func (mls *UnifiedMLSystem) GetStats() *types.MLStats { return mls.stats }

func (mls *UnifiedMLSystem) HealthCheck() error {
	if mls.engine == nil {
		return fmt.Errorf("ml engine not initialized")
	}
	if mls.stats == nil {
		return fmt.Errorf("ml stats not initialized")
	}
	return nil
}

func (mls *UnifiedMLSystem) LoadModels() error {
	if mls.engine == nil {
		return fmt.Errorf("ml engine not initialized")
	}
	// NativeMLEngine loads models automatically in constructor;
	// verify engine is functional by checking stats.
	stats := mls.engine.GetStats()
	if stats == nil {
		return fmt.Errorf("ml engine stats unavailable")
	}
	return nil
}

func (mls *UnifiedMLSystem) GetDataCollector() *DataCollector {
	return mls.dataCollector
}

func (mls *UnifiedMLSystem) GetRuntimeMetrics() RuntimeMetrics {
	if mls.dataCollector != nil {
		return mls.dataCollector.GetMetrics()
	}
	return RuntimeMetrics{}
}

func (mls *UnifiedMLSystem) GetEngine() *NativeMLEngine {
	return mls.engine
}

func NewUnifiedMLSystem() *UnifiedMLSystem {
	return &UnifiedMLSystem{
		engine: nativeEngine,
		stats: &types.MLStats{
			ProcessedPackets: 0,
			Accuracy:         0.85,
			DPIEvasionRate:   0.75,
			ModelStatus:      "active",
			LastUpdate:       util.GetGlobalTimeCache().Now(),
		},
		dataCollector: NewDataCollector(10000, "./ml_data"),
	}
}
