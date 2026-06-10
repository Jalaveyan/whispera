package ml

import (
	"encoding/json"
	"fmt"
	"math"
	mrand "math/rand"
	"os"
	"sort"
	"strings"
	"sync"

	"whispera/internal/obfuscation/ml/gnet"
)

type scoredDecoy struct {
	features []float64
	score    float64
}

type TrafficGAN struct {
	mu sync.RWMutex

	disc     *gnet.GorgoniaNet
	discAdam *AdamState

	gen     *gnet.GorgoniaNet
	genAdam *AdamState

	norm ganNorm

	TunnelConfidence float64
	DecoyConfidence  float64

	trainCount int64

	decoyReplay []scoredDecoy
	smoothed    GeneratorAction
	lastTunnelX []float64
}

type GeneratorAction struct {
	PaddingFrac float64
	SleepMs     float64
	SegShrink   float64
}

func NewTrafficGAN() *TrafficGAN {
	disc := gnet.New([]int{FlowFeatureSize, 64, 32, 1})
	gen := gnet.New([]int{FlowFeatureSize, 32, 3})
	return &TrafficGAN{
		disc:     disc,
		discAdam: NewAdamState(disc),
		gen:      gen,
		genAdam:  NewAdamState(gen),
		norm:     newGANNorm(FlowFeatureSize),
	}
}

const decoyReplayCap = 4096

type ganState struct {
	DiscLayers    []gnet.LayerDef `json:"disc_layers"`
	GenLayers     []gnet.LayerDef `json:"gen_layers"`
	DiscAdam      *AdamState      `json:"disc_adam"`
	GenAdam       *AdamState      `json:"gen_adam"`
	NormMean      []float64       `json:"norm_mean"`
	NormM2        []float64       `json:"norm_m2"`
	NormN         float64         `json:"norm_n"`
	TunnelConf    float64         `json:"tunnel_conf"`
	DecoyConf     float64         `json:"decoy_conf"`
	TrainCount    int64           `json:"train_count"`
	DecoyFeatures [][]float64     `json:"decoy_features,omitempty"`
	DecoyScores   []float64       `json:"decoy_scores,omitempty"`
	DecoyReplay   [][]float64     `json:"decoy_replay,omitempty"` // legacy
}

func (g *TrafficGAN) Save(path string) error {
	g.mu.RLock()
	feats := make([][]float64, len(g.decoyReplay))
	scores := make([]float64, len(g.decoyReplay))
	for i, d := range g.decoyReplay {
		feats[i] = d.features
		scores[i] = d.score
	}
	state := ganState{
		DiscLayers:    g.disc.Layers,
		GenLayers:     g.gen.Layers,
		DiscAdam:      g.discAdam,
		GenAdam:       g.genAdam,
		NormMean:      g.norm.mean,
		NormM2:        g.norm.m2,
		NormN:         g.norm.n,
		TunnelConf:    g.TunnelConfidence,
		DecoyConf:     g.DecoyConfidence,
		TrainCount:    g.trainCount,
		DecoyFeatures: feats,
		DecoyScores:   scores,
	}
	g.mu.RUnlock()
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (g *TrafficGAN) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var state ganState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(state.DiscLayers) > 0 {
		g.disc = &gnet.GorgoniaNet{Layers: state.DiscLayers}
		if state.DiscAdam != nil {
			g.discAdam = state.DiscAdam
		}
	}
	if len(state.GenLayers) > 0 {
		g.gen = &gnet.GorgoniaNet{Layers: state.GenLayers}
		if state.GenAdam != nil {
			g.genAdam = state.GenAdam
		}
	}
	if len(state.NormMean) > 0 {
		g.norm.mean = state.NormMean
		g.norm.m2 = state.NormM2
		g.norm.n = state.NormN
	}
	g.TunnelConfidence = state.TunnelConf
	g.DecoyConfidence = state.DecoyConf
	g.trainCount = state.TrainCount

	feats := state.DecoyFeatures
	if len(feats) == 0 {
		feats = state.DecoyReplay
	}
	if len(feats) > 0 {
		scrs := state.DecoyScores
		if len(scrs) != len(feats) {
			scrs = make([]float64, len(feats))
			for i := range scrs {
				scrs[i] = 0.5
			}
		}
		g.decoyReplay = make([]scoredDecoy, len(feats))
		for i := range feats {
			g.decoyReplay[i] = scoredDecoy{feats[i], scrs[i]}
		}
		sort.Slice(g.decoyReplay, func(a, b int) bool {
			return g.decoyReplay[a].score < g.decoyReplay[b].score
		})
	}
	return nil
}

func (g *TrafficGAN) trainDiscOnDecoy(x []float64) {
	dActs := g.disc.ForwardActivations(x)
	pred := sigmoid64(dActs[len(dActs)-1][0])
	g.DecoyConfidence = 0.95*g.DecoyConfidence + 0.05*pred
	dLoss := pred - 1.0
	g.disc.Layers[len(g.disc.Layers)-1] = applyOutputGrad(g.disc.Layers[len(g.disc.Layers)-1], dLoss)
	dqnBackpropAdam(g.disc, g.discAdam, dActs, []float64{dLoss}, 0.001)
}

func (g *TrafficGAN) addDecoy(features []float64, score float64) {
	d := scoredDecoy{append([]float64(nil), features...), score}
	if len(g.decoyReplay) < decoyReplayCap {
		g.decoyReplay = append(g.decoyReplay, d)
		return
	}
	// Вытесняем худший элемент (индекс 0 — минимальный score после sort)
	if score > g.decoyReplay[0].score {
		g.decoyReplay[0] = d
		for i := 0; i < len(g.decoyReplay)-1; i++ {
			if g.decoyReplay[i].score > g.decoyReplay[i+1].score {
				g.decoyReplay[i], g.decoyReplay[i+1] = g.decoyReplay[i+1], g.decoyReplay[i]
			} else {
				break
			}
		}
	}
}

func (g *TrafficGAN) Train(lf LabeledFlow) {
	g.mu.Lock()
	defer g.mu.Unlock()

	vec := lf.Features.Vec()
	g.norm.update(vec)
	x := g.norm.normalise(vec)

	target := 0.0
	if lf.Label == FlowDecoy {
		target = 1.0
	}

	dActs := g.disc.ForwardActivations(x)
	raw := dActs[len(dActs)-1][0]
	pred := sigmoid64(raw)
	dLoss := pred - target

	g.disc.Layers[len(g.disc.Layers)-1] = applyOutputGrad(g.disc.Layers[len(g.disc.Layers)-1], dLoss)
	dqnBackpropAdam(g.disc, g.discAdam, dActs, []float64{dLoss}, 0.001)

	if lf.Label == FlowDecoy {
		g.addDecoy(x, pred)
	}

	if lf.Label == FlowTunnel {
		g.lastTunnelX = append([]float64(nil), x...)
		g.TunnelConfidence = 0.95*g.TunnelConfidence + 0.05*pred
		if n := len(g.decoyReplay); n > 0 {
			// Выбираем из верхней половины (лучшие декои)
			topStart := n / 2
			idx := topStart + mrand.Intn(n-topStart)
			g.trainDiscOnDecoy(g.decoyReplay[idx].features)
		}
	}

	if lf.Label != FlowTunnel {
		g.trainCount++
		return
	}

	gActs := g.gen.ForwardActivations(x)
	action := g.genAction(gActs[len(gActs)-1])

	xAdv := g.applyAction(x, action)
	dAdvActs := g.disc.ForwardActivations(xAdv)
	predAdv := sigmoid64(dAdvActs[len(dAdvActs)-1][0])

	gLossGrad := -(1.0 - predAdv)
	dqnBackpropAdam(g.gen, g.genAdam, gActs, []float64{gLossGrad, gLossGrad, gLossGrad}, 0.0005)

	// Не шейпить мелкие пакеты — это порождало петлю дросселирования
	if lf.Features.SizeMean < 200 {
		action.SegShrink = 0
	}
	// EMA-сглаживание: исключает резкие скачки действий генератора
	const alpha = 0.15
	g.smoothed.PaddingFrac = alpha*action.PaddingFrac + (1-alpha)*g.smoothed.PaddingFrac
	g.smoothed.SleepMs = alpha*action.SleepMs + (1-alpha)*g.smoothed.SleepMs
	g.smoothed.SegShrink = alpha*action.SegShrink + (1-alpha)*g.smoothed.SegShrink

	g.trainCount++
}

const GANDecideThreshold int64 = 500

func (g *TrafficGAN) Decide(f FlowFeatures) GeneratorAction {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.trainCount < GANDecideThreshold {
		return GeneratorAction{}
	}
	return g.smoothed
}

func (g *TrafficGAN) genAction(out []float64) GeneratorAction {
	pad := math.Max(0, math.Min(0.5, sigmoid64(out[0])*0.5))
	slp := math.Max(0, math.Min(50, sigmoid64(out[1])*50))
	seg := math.Max(0, math.Min(0.7, sigmoid64(out[2])*0.7))
	return GeneratorAction{PaddingFrac: pad, SleepMs: slp, SegShrink: seg}
}

func GANLambda(threatLevel int) float64 {
	t := float64(threatLevel)
	if t < 0 {
		t = 0
	}
	if t > 10 {
		t = 10
	}
	return (t / 10.0) * (t / 10.0)
}

func (g *TrafficGAN) applyAction(x []float64, a GeneratorAction) []float64 {
	out := make([]float64, len(x))
	copy(out, x)

	padEffect := 1.0 + a.PaddingFrac
	out[3] *= padEffect
	out[4] *= padEffect * 0.5
	out[5] *= padEffect

	sleepSec := a.SleepMs / 1000.0
	out[0] += sleepSec
	out[1] += sleepSec * 0.3
	out[2] += sleepSec * 0.5

	segEffect := 1.0 - a.SegShrink
	out[3] *= segEffect
	out[4] *= segEffect
	out[5] *= segEffect

	return out
}

var featureNames = [FlowFeatureSize]string{
	"iat_mean", "iat_std", "iat_p90",
	"pkt_size_mean", "pkt_size_std", "pkt_size_p90",
	"up_ratio", "burst_size", "duration", "pkt_count",
}

func (g *TrafficGAN) diagnoseFeatures() string {
	if len(g.decoyReplay) < 10 || len(g.lastTunnelX) == 0 {
		return ""
	}
	mean := make([]float64, FlowFeatureSize)
	variance := make([]float64, FlowFeatureSize)
	n := float64(len(g.decoyReplay))
	for _, d := range g.decoyReplay {
		for i, v := range d.features {
			mean[i] += v
		}
	}
	for i := range mean {
		mean[i] /= n
	}
	for _, d := range g.decoyReplay {
		for i, v := range d.features {
			diff := v - mean[i]
			variance[i] += diff * diff
		}
	}
	for i := range variance {
		variance[i] /= n
	}
	type zs struct {
		name string
		z    float64
	}
	zscores := make([]zs, FlowFeatureSize)
	for i, v := range g.lastTunnelX {
		std := 1.0
		if variance[i] > 1e-12 {
			std = math.Sqrt(variance[i])
		}
		zscores[i] = zs{featureNames[i], math.Abs(v-mean[i]) / std}
	}
	sort.Slice(zscores, func(a, b int) bool { return zscores[a].z > zscores[b].z })
	parts := make([]string, 0, 3)
	for i := 0; i < 3 && i < len(zscores); i++ {
		parts = append(parts, fmt.Sprintf("%s(z=%.1f)", zscores[i].name, zscores[i].z))
	}
	return strings.Join(parts, ", ")
}

func (g *TrafficGAN) Diagnostics() (tunnelConf, decoyConf float64, trainCount int64, poolSize int, detect string) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	tunnelConf = g.TunnelConfidence
	decoyConf = g.DecoyConfidence
	trainCount = g.trainCount
	poolSize = len(g.decoyReplay)
	if tunnelConf > 0.5 && len(g.lastTunnelX) > 0 {
		detect = g.diagnoseFeatures()
	}
	return
}

// ── Feature normalizer ────────────────────────────────────────────────────────

type ganNorm struct {
	mean []float64
	m2   []float64
	n    float64
}

func newGANNorm(size int) ganNorm {
	return ganNorm{mean: make([]float64, size), m2: make([]float64, size)}
}

func (n *ganNorm) update(x []float64) {
	n.n++
	for i, v := range x {
		delta := v - n.mean[i]
		n.mean[i] += delta / n.n
		n.m2[i] += delta * (v - n.mean[i])
	}
}

func (n *ganNorm) normalise(x []float64) []float64 {
	out := make([]float64, len(x))
	for i, v := range x {
		std := 1.0
		if n.n > 1 {
			v2 := n.m2[i] / (n.n - 1)
			if v2 > 0 {
				std = math.Sqrt(v2)
			}
		}
		out[i] = (v - n.mean[i]) / std
	}
	return out
}

// ── helpers ───────────────────────────────────────────────────────────────────

func sigmoid64(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func applyOutputGrad(l gnet.LayerDef, _ float64) gnet.LayerDef { return l }
