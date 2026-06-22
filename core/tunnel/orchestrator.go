package tunnel

import (
	"context"
	"math"
	"net"
	"time"
	"whispera/neural"

	"github.com/sourcegraph/conc/iter"
)

type mlOrchestrator struct {
	m *Manager

	kaAgent      keepaliveDecisionAgent
	boAgent      backoffDecisionAgent
	jitterAgent  jitterDecisionAgent
	serverAgent  serverDecisionAgent
	chunkAgent   chunkDecisionAgent
	tspuDetector tspuDetectorIface
}

func newMLOrchestrator(m *Manager, modelDir string, enabled bool) *mlOrchestrator {
	if !enabled {
		return &mlOrchestrator{m: m}
	}
	return &mlOrchestrator{
		m:            m,
		kaAgent:      neural.NewRLKeepaliveAgent(modelDir),
		boAgent:      neural.NewRLBackoffAgent(modelDir),
		jitterAgent:  neural.NewRLJitterAgent(modelDir),
		serverAgent:  neural.NewRLServerAgent(modelDir),
		chunkAgent:   neural.NewRLChunkAgent(modelDir),
		tspuDetector: neural.NewTSPUDetector(),
	}
}

func probeLatency(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

func (ml *mlOrchestrator) pickServer(ctx context.Context) string {
	candidates := ml.regionCandidates()
	if len(candidates) == 0 {
		return ""
	}

	probes := iter.Map(candidates, func(a *string) neural.ServerProbe {
		addr := *a
		lat, err := probeLatency(ctx, addr, 200*time.Millisecond)
		if err != nil {
			return neural.ServerProbe{Addr: addr, Latency: math.MaxInt64}
		}
		return neural.ServerProbe{Addr: addr, Latency: lat}
	})

	if ml.serverAgent != nil {
		if chosen := ml.serverAgent.Decide(probes); chosen != "" {
			return chosen
		}
	}

	best := probes[0]
	for _, p := range probes[1:] {
		if p.Latency < best.Latency {
			best = p
		}
	}
	if best.Latency == math.MaxInt64 {
		return ""
	}
	return best.Addr
}

func (ml *mlOrchestrator) regionCandidates() []string {
	m := ml.m
	region := m.config.PreferredRegion
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	if region != "" && region != "auto" {
		if servers, ok := m.config.Regions[region]; ok && len(servers) > 0 {
			for _, s := range servers {
				add(s)
			}
			return out
		}
	}

	for _, s := range m.config.ServerList {
		add(s)
	}
	for _, servers := range m.config.Regions {
		for _, s := range servers {
			add(s)
		}
	}
	return out
}

func (ml *mlOrchestrator) runWeightSnapshotLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	neural.SetGlobalSnapshot(ml.exportWeights())
	for range ticker.C {
		neural.SetGlobalSnapshot(ml.exportWeights())
	}
}

func (ml *mlOrchestrator) exportWeights() *neural.WeightSnapshot {
	snap := &neural.WeightSnapshot{}
	if ml.kaAgent != nil {
		snap.Keepalive = ml.kaAgent.ExportWeights()
	}
	if ml.jitterAgent != nil {
		snap.Jitter = ml.jitterAgent.ExportWeights()
	}
	if ml.chunkAgent != nil {
		snap.Chunk = ml.chunkAgent.ExportWeights()
	}
	if ml.boAgent != nil {
		snap.Backoff = ml.boAgent.ExportWeights()
	}
	if ml.serverAgent != nil {
		snap.Server = ml.serverAgent.ExportWeights()
	}

	return snap
}

func (ml *mlOrchestrator) importWeights(snap *neural.WeightSnapshot) {
	if snap == nil {
		return
	}
	if ml.kaAgent != nil && len(snap.Keepalive) > 0 {
		ml.kaAgent.ImportWeights(snap.Keepalive)
	}
	if ml.jitterAgent != nil && len(snap.Jitter) > 0 {
		ml.jitterAgent.ImportWeights(snap.Jitter)
	}
	if ml.chunkAgent != nil && len(snap.Chunk) > 0 {
		ml.chunkAgent.ImportWeights(snap.Chunk)
	}
	if ml.boAgent != nil && len(snap.Backoff) > 0 {
		ml.boAgent.ImportWeights(snap.Backoff)
	}
	if ml.serverAgent != nil && len(snap.Server) > 0 {
		ml.serverAgent.ImportWeights(snap.Server)
	}
}
