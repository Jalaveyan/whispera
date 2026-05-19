package ml

import (
	"encoding/json"
	"os"
	"path/filepath"

	"whispera/internal/obfuscation/ml/gnet"
)

type miniPolicyState struct {
	Layers  []gnet.LayerDef `json:"layers"`
	Epsilon float64         `json:"epsilon"`
	Steps   int64           `json:"steps"`
}

func saveRLMiniPolicy(dir, filename string, layers []gnet.LayerDef, epsilon float64, steps int64) {
	if dir == "" {
		return
	}
	state := miniPolicyState{Layers: layers, Epsilon: epsilon, Steps: steps}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, filename), data, 0600) //nolint:errcheck
}

// loadRLMiniPolicy returns (layers, epsilon, steps, ok).
func loadRLMiniPolicy(dir, filename string) ([]gnet.LayerDef, float64, int64, bool) {
	if dir == "" {
		return nil, 0, 0, false
	}
	data, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		return nil, 0, 0, false
	}
	var state miniPolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, 0, 0, false
	}
	if len(state.Layers) == 0 {
		return nil, 0, 0, false
	}
	return state.Layers, state.Epsilon, state.Steps, true
}
