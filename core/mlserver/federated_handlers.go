package mlserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"whispera/neural"
)

func (s *MLServer) handleFedExport(w http.ResponseWriter, r *http.Request) {
	s.feedbackMu.Lock()
	stats := make(map[string]*TransportStats)
	for k, v := range s.transportStats {
		cp := *v
		stats[k] = &cp
	}
	s.feedbackMu.Unlock()

	engineStats := s.engine.GetStats()
	modelState := s.engine.ExportModelState()

	s.jsonReply(w, map[string]interface{}{
		"transports": stats,
		"model":      engineStats,
		"weights":    modelState,
		"ts":         time.Now().Unix(),
	})
}

func (s *MLServer) handleFedImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transports map[string]*TransportStats `json:"transports"`
		Weights    *neural.ModelState         `json:"weights"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 10*1024*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// FedAvg: blend remote NN weights into local model (alpha=0.5 = equal trust).
	if req.Weights != nil {
		s.engine.ImportModelState(req.Weights, 0.5)
	}

	s.feedbackMu.Lock()
	for name, remote := range req.Transports {
		if local, ok := s.transportStats[name]; ok {
			local.Success = (local.Success + remote.Success) / 2
			local.Fail = (local.Fail + remote.Fail) / 2
			local.Total = local.Success + local.Fail
		} else {
			cp := *remote
			s.transportStats[name] = &cp
		}
	}
	s.feedbackMu.Unlock()

	s.addLogf("federated import applied (weights: %v)", req.Weights != nil)
	s.jsonReply(w, map[string]string{"status": "applied"})
}

func (s *MLServer) handleFedStatus(w http.ResponseWriter, r *http.Request) {
	s.jsonReply(w, map[string]interface{}{
		"engine":     "native_mlp_go",
		"stats":      s.engine.GetStats(),
		"transports": len(s.transportStats),
	})
}

func (s *MLServer) handleFedLosses(w http.ResponseWriter, r *http.Request) {
	s.feedbackMu.Lock()
	losses := make(map[string]float64)
	for name, ts := range s.transportStats {
		if ts.Total > 0 {
			failRate := float64(ts.Fail) / float64(ts.Total)
			avgLat := 0.0
			if ts.Count > 0 {
				avgLat = ts.TotalLatency / float64(ts.Count)
			}
			losses[name] = failRate*0.7 + min64f(avgLat/5000, 1.0)*0.3
		}
	}
	s.feedbackMu.Unlock()
	s.jsonReply(w, map[string]interface{}{"local_losses": losses})
}

func (s *MLServer) handleFedUpload(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	fname := fmt.Sprintf("delta_%d.json", time.Now().UnixNano())
	os.WriteFile(filepath.Join(s.fedDir, fname), body, 0600)

	var upload struct {
		Samples []json.RawMessage  `json:"samples"`
		Count   int                `json:"count"`
		Weights *neural.ModelState `json:"weights"`
	}
	if json.Unmarshal(body, &upload) == nil {
		if len(upload.Samples) > 0 {
			s.appendToDataset(upload.Samples)
			s.addLogf("federated upload: %s — %d samples (total: %d)",
				fname, len(upload.Samples), s.datasetSampleCount())
		}
		if upload.Weights != nil {
			// Apply client weights into aggregated model and into local engine.
			s.aggregateModelDelta(upload.Weights)
			s.engine.ImportModelState(upload.Weights, 0.7) // trust local more
			s.addLogf("federated upload: NN weights aggregated from %s", fname)
		}
		if len(upload.Samples) == 0 && upload.Weights == nil {
			s.addLogf("federated delta uploaded: %s (%d bytes, no samples/weights)", fname, len(body))
		}
	}

	s.jsonReply(w, map[string]string{"status": "ok"})
}

// aggregateModelDelta blends a remote ModelState into the on-disk aggregated
// model file (federated/aggregated_model.json). The file acts as the running
// FedAvg result that clients can download.
func (s *MLServer) aggregateModelDelta(remote *neural.ModelState) {
	if remote == nil {
		return
	}
	aggPath := filepath.Join(s.fedDir, "aggregated_model.json")
	var agg neural.ModelState
	if data, err := os.ReadFile(aggPath); err == nil {
		if err := json.Unmarshal(data, &agg); err != nil {
			agg = neural.ModelState{}
		}
	}
	if len(agg.TrafficLayers) == 0 {
		agg = *remote
	} else {
		// Create a temporary engine snapshot to perform FedAvg, then persist.
		tmp := neural.NewNativeMLEngine("") // no modelDir — in-memory only
		tmp.ImportModelState(&agg, 0.6)
		tmp.ImportModelState(remote, 0.4)
		agg = *tmp.ExportModelState()
	}
	data, err := json.Marshal(agg)
	if err == nil {
		os.WriteFile(aggPath, data, 0600)
	}
}

func (s *MLServer) appendToDataset(samples []json.RawMessage) {
	dsPath := filepath.Join(s.fedDir, "aggregated_dataset.jsonl")
	f, err := os.OpenFile(dsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	for _, sample := range samples {
		f.Write(sample)
		f.Write([]byte("\n"))
	}
}

func (s *MLServer) datasetSampleCount() int {
	dsPath := filepath.Join(s.fedDir, "aggregated_dataset.jsonl")
	data, err := os.ReadFile(dsPath)
	if err != nil {
		return 0
	}
	count := 0
	for _, b := range data {
		if b == '\n' {
			count++
		}
	}
	return count
}

func (s *MLServer) handleFedDownload(w http.ResponseWriter, r *http.Request) {
	// Return the aggregated model so clients can apply FedAvg locally.
	var aggModel *neural.ModelState
	aggPath := filepath.Join(s.fedDir, "aggregated_model.json")
	if data, err := os.ReadFile(aggPath); err == nil {
		var m neural.ModelState
		if json.Unmarshal(data, &m) == nil {
			aggModel = &m
		}
	}
	// Fallback: if no aggregated model exists yet, export local engine state.
	if aggModel == nil {
		aggModel = s.engine.ExportModelState()
	}

	s.jsonReply(w, map[string]interface{}{
		"weights": aggModel,
		"ts":      time.Now().Unix(),
	})
}

func min64f(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
