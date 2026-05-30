package ml

import (
	"encoding/json"
	"os"
	"path/filepath"

	"whispera/internal/obfuscation/ml/gnet"
)

const rlPolicyVersion = 2

type miniPolicyState struct {
	Version int             `json:"v"`
	Layers  []gnet.LayerDef `json:"layers"`
	Epsilon float64         `json:"epsilon"`
	Steps   int64           `json:"steps"`
}

func saveRLMiniPolicy(dir, filename string, layers []gnet.LayerDef, epsilon float64, steps int64) {
	if dir == "" {
		return
	}
	state := miniPolicyState{Version: rlPolicyVersion, Layers: layers, Epsilon: epsilon, Steps: steps}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, filename), data, 0600) //nolint:errcheck
}

func validLayers(layers []gnet.LayerDef, wantIn, wantOut int) bool {
	if len(layers) == 0 {
		return false
	}
	for _, l := range layers {
		if l.InSize <= 0 || l.OutSize <= 0 {
			return false
		}
		if len(l.W) != l.InSize*l.OutSize || len(l.B) != l.OutSize {
			return false
		}
	}
	return layers[0].InSize == wantIn && layers[len(layers)-1].OutSize == wantOut
}

func loadRLMiniPolicy(dir, filename string, wantIn, wantOut int) ([]gnet.LayerDef, float64, int64, bool) {
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
	if state.Version != rlPolicyVersion || !validLayers(state.Layers, wantIn, wantOut) {
		return nil, 0, 0, false
	}
	return state.Layers, state.Epsilon, state.Steps, true
}
