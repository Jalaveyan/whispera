package types

import (
	"time"
)

type PredictionResult struct {
	ClassID      int     `json:"class_id"`
	Confidence   float64 `json:"confidence"`
	Protocol     string  `json:"protocol"`
	Direction    string  `json:"direction"`
	DPIType      int     `json:"dpi_type"`
	DPIName      string  `json:"dpi_name"`
	IsAnomaly    bool    `json:"is_anomaly"`
	AnomalyScore float64 `json:"anomaly_score"`
}

type MLPredictionResponse struct {
	Prediction        string             `json:"prediction"`
	Confidence        float64            `json:"confidence"`
	Method            string             `json:"method"`
	Metadata          map[string]string  `json:"metadata"`
	RecommendedAction string             `json:"recommended_action"`
	ModelUsed         string             `json:"model_used"`
	Timestamp         time.Time          `json:"timestamp"`
	Predictions       []PredictionResult `json:"predictions"`
}

type MLTrainingData struct {
	Features [][]float64              `json:"features"`
	Labels   []int                    `json:"labels"`
	Metadata []map[string]interface{} `json:"metadata"`
}
