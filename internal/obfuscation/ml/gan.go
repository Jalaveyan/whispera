package ml

import (
	"context"
	"math"
	"sync"
	"time"

	"whispera/internal/obfuscation/ml/gnet"
)

// TrafficGAN implements a minimax GAN for traffic obfuscation.
//
// Discriminator D: FlowFeatures → [0,1]
//   D(x)=1 means "looks like real browser traffic"
//   D(x)=0 means "looks like VPN tunnel"
//
// Generator G: current tunnel flow stats → GeneratorAction
//   G learns to produce actions that push D(transformed features) → 1
//
// Training loop:
//   1. Server receives LabeledFlow from PCAPCollector
//   2. D is trained with BCE loss
//   3. G is trained to maximize D(G(tunnel_features))
type TrafficGAN struct {
	mu sync.RWMutex

	disc     *gnet.GorgoniaNet // discriminator: 10 → 64 → 32 → 1
	discAdam *AdamState

	gen     *gnet.GorgoniaNet // generator:     10 → 32 → 2  (padding_frac, sleep_ms)
	genAdam *AdamState

	// running statistics for feature normalisation
	norm ganNorm

	// smoothed discriminator confidence on tunnel flows — exposed for monitoring
	TunnelConfidence float64 // 0=detected, 1=looks like browser

	trainCount int64
}

// GeneratorAction is the output of the generator applied to each write.
type GeneratorAction struct {
	PaddingFrac float64 // fraction of write size to pad (0–0.5)
	SleepMs     float64 // milliseconds to sleep before write (0–50)
}

func NewTrafficGAN() *TrafficGAN {
	disc := gnet.New([]int{FlowFeatureSize, 64, 32, 1})
	gen := gnet.New([]int{FlowFeatureSize, 32, 2})
	return &TrafficGAN{
		disc:     disc,
		discAdam: NewAdamState(disc),
		gen:      gen,
		genAdam:  NewAdamState(gen),
		norm:     newGANNorm(FlowFeatureSize),
	}
}

// Train ingests one labeled flow and runs one D step + one G step.
func (g *TrafficGAN) Train(lf LabeledFlow) {
	g.mu.Lock()
	defer g.mu.Unlock()

	vec := lf.Features.Vec()
	g.norm.update(vec)
	x := g.norm.normalise(vec)

	// ── Discriminator step (BCE loss) ────────────────────────────────────────
	// target: 1 for real browser (decoy), 0 for tunnel
	target := 0.0
	if lf.Label == FlowDecoy {
		target = 1.0
	}

	dActs := g.disc.ForwardActivations(x)
	raw := dActs[len(dActs)-1][0]
	pred := sigmoid64(raw)
	dLoss := pred - target // dBCE/d(raw)

	g.disc.Layers[len(g.disc.Layers)-1] = applyOutputGrad(g.disc.Layers[len(g.disc.Layers)-1], dLoss)
	dqnBackpropAdam(g.disc, g.discAdam, dActs, []float64{dLoss}, 0.001)

	// Update smoothed tunnel confidence.
	if lf.Label == FlowTunnel {
		g.TunnelConfidence = 0.95*g.TunnelConfidence + 0.05*pred
	}

	// ── Generator step (only for tunnel flows) ───────────────────────────────
	// Generator loss: maximize D(x) → minimize -log(D(x)) → gradient = -dD/dx
	if lf.Label != FlowTunnel {
		g.trainCount++
		return
	}

	gActs := g.gen.ForwardActivations(x)
	action := g.genAction(gActs[len(gActs)-1])

	// Simulate transformed features and compute D on them.
	xAdv := g.applyAction(x, action)
	dAdvActs := g.disc.ForwardActivations(xAdv)
	predAdv := sigmoid64(dAdvActs[len(dAdvActs)-1][0])

	// Generator loss: -log(D(xAdv)), gradient = -(1-predAdv)
	gLossGrad := -(1.0 - predAdv)
	dqnBackpropAdam(g.gen, g.genAdam, gActs, []float64{gLossGrad, gLossGrad}, 0.0005)

	g.trainCount++
}

const GANDecideThreshold int64 = 500

func (g *TrafficGAN) Decide(f FlowFeatures) GeneratorAction {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.trainCount < GANDecideThreshold {
		return GeneratorAction{}
	}

	x := g.norm.normalise(f.Vec())
	out := g.gen.Forward(x)
	return g.genAction(out)
}

func (g *TrafficGAN) genAction(out []float64) GeneratorAction {
	// out[0] → PaddingFrac ∈ [0, 0.5]
	// out[1] → SleepMs    ∈ [0, 50]
	pad := math.Max(0, math.Min(0.5, sigmoid64(out[0])*0.5))
	slp := math.Max(0, math.Min(50, sigmoid64(out[1])*50))
	return GeneratorAction{PaddingFrac: pad, SleepMs: slp}
}

// applyAction simulates how the generator action would transform flow features.
// This lets G learn through D without requiring a full trajectory.
func (g *TrafficGAN) applyAction(x []float64, a GeneratorAction) []float64 {
	out := make([]float64, len(x))
	copy(out, x)

	// Padding increases mean and variance of sizes (indices 3,4,5).
	padEffect := 1.0 + a.PaddingFrac
	out[3] *= padEffect
	out[4] *= padEffect * 0.5
	out[5] *= padEffect

	// Sleep increases IAT (indices 0,1,2).
	sleepSec := a.SleepMs / 1000.0
	out[0] += sleepSec
	out[1] += sleepSec * 0.3
	out[2] += sleepSec * 0.5

	return out
}

// ExportDiscWeights returns discriminator layer weights for sync to clients.
func (g *TrafficGAN) ExportDiscWeights() []gnet.LayerDef {
	g.mu.RLock()
	defer g.mu.RUnlock()
	layers := make([]gnet.LayerDef, len(g.disc.Layers))
	for i, l := range g.disc.Layers {
		layers[i] = gnet.LayerDef{
			InSize: l.InSize, OutSize: l.OutSize,
			W: gnet.CopyF64(l.W), B: gnet.CopyF64(l.B),
		}
	}
	return layers
}

// ImportDiscWeights applies federated-average update from a remote discriminator.
func (g *TrafficGAN) ImportDiscWeights(remote []gnet.LayerDef, alpha float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, rl := range remote {
		if i >= len(g.disc.Layers) {
			break
		}
		ll := &g.disc.Layers[i]
		if len(rl.W) != len(ll.W) {
			continue
		}
		for j := range ll.W {
			ll.W[j] = (1-alpha)*ll.W[j] + alpha*rl.W[j]
		}
		for j := range ll.B {
			ll.B[j] = (1-alpha)*ll.B[j] + alpha*rl.B[j]
		}
	}
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

// applyOutputGrad is a no-op helper to make the grad flow explicit.
// dqnBackpropAdam handles the actual weight update.
func applyOutputGrad(l gnet.LayerDef, _ float64) gnet.LayerDef { return l }

// GANRunner runs the training loop and browser simulator on background goroutines.
type GANRunner struct {
	gan       *TrafficGAN
	collector *PCAPCollector
	stopCh    chan struct{}
	simCancel context.CancelFunc
}

func NewGANRunner(iface string, port int) *GANRunner {
	return &GANRunner{
		gan:       NewTrafficGAN(),
		collector: NewPCAPCollector(iface, port),
		stopCh:    make(chan struct{}),
	}
}

func (r *GANRunner) GAN() *TrafficGAN { return r.gan }

func (r *GANRunner) Start() error {
	if err := r.collector.Start(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.simCancel = cancel
	go r.loop()
	go RunBrowserSim(ctx)
	return nil
}

func (r *GANRunner) Stop() {
	if r.simCancel != nil {
		r.simCancel()
	}
	close(r.stopCh)
	r.collector.Stop()
}

func (r *GANRunner) loop() {
	logTicker := time.NewTicker(60 * time.Second)
	defer logTicker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case lf := <-r.collector.Out():
			r.gan.Train(lf)
		case <-logTicker.C:
			log.Info("GAN: tunnel_conf=%.3f trained=%d",
				r.gan.TunnelConfidence, r.gan.trainCount)
		}
	}
}
