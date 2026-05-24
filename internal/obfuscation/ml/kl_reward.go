package ml

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Fallback reference distributions used until enough real decoy traffic is observed.
// Bins: [0-64], [65-256], [257-512], [513-1024], [1025-1280], [1281-1400], [1401+]
var defaultRefSizeDist = [7]float64{0.04, 0.02, 0.02, 0.04, 0.08, 0.35, 0.45}

// Bins (ms): [0-1], [1-5], [5-20], [20-100], [100+]
var defaultRefIATDist = [5]float64{0.55, 0.25, 0.10, 0.07, 0.03}

// minRefSamples is the number of real decoy packets needed before switching
// from the fallback hardcoded distribution to the learned one.
const minRefSamples = 500

const (
	klWindowSize    = 512  // packets in rolling window
	klMinSamples    = 32   // minimum before computing reward
	klMaxReward     = 0.30 // maximum KL bonus added to agent reward
	klDecayPerReset = 200  // reset histogram every N packets to stay fresh
)

// FlowObserver collects packet size and IAT statistics over a rolling window
// and computes a KL-divergence reward bonus measuring similarity to the
// reference HTTPS streaming distribution.
//
// The reference distribution is learned from real decoy (FlowDecoy) traffic
// observed by PCAPCollector. Until minRefSamples are seen, the hardcoded
// fallback distribution is used.
type FlowObserver struct {
	mu sync.Mutex

	// Observed tunnel traffic (used to compute KL reward).
	sizeCounts [7]int64
	iatCounts  [5]int64
	total      int64

	// Reference distribution learned from real FlowDecoy traffic.
	refSizeCounts [7]int64
	refIATCounts  [5]int64
	refTotal      int64

	lastPacketAt int64 // UnixNano, atomic
}

func (f *FlowObserver) sizeBucket(n int) int {
	switch {
	case n <= 64:
		return 0
	case n <= 256:
		return 1
	case n <= 512:
		return 2
	case n <= 1024:
		return 3
	case n <= 1280:
		return 4
	case n <= 1400:
		return 5
	default:
		return 6
	}
}

func (f *FlowObserver) iatBucket(ms float64) int {
	switch {
	case ms < 1:
		return 0
	case ms < 5:
		return 1
	case ms < 20:
		return 2
	case ms < 100:
		return 3
	default:
		return 4
	}
}

// RecordPacket records an outbound packet for KL reward computation.
// Call this on every packet/chunk sent through the tunnel.
func (f *FlowObserver) RecordPacket(sizeBytes int) {
	now := time.Now().UnixNano()
	prev := atomic.SwapInt64(&f.lastPacketAt, now)

	sb := f.sizeBucket(sizeBytes)
	ib := -1
	if prev > 0 {
		ib = f.iatBucket(float64(now-prev) / 1e6)
	}

	total := atomic.AddInt64(&f.total, 1)
	f.mu.Lock()
	f.sizeCounts[sb]++
	if ib >= 0 {
		f.iatCounts[ib]++
	}
	if total%klDecayPerReset == 0 {
		f.sizeCounts = [7]int64{}
		f.iatCounts = [5]int64{}
	}
	f.mu.Unlock()
}

// UpdateReference records a single packet from real decoy traffic (FlowDecoy label).
// Called by PCAPCollector on Linux when it observes a completed decoy flow.
// Once minRefSamples are accumulated, KLReward() uses this learned distribution
// instead of the hardcoded fallback.
func (f *FlowObserver) UpdateReference(sizeBytes int, iatMs float64) {
	f.mu.Lock()
	f.refSizeCounts[f.sizeBucket(sizeBytes)]++
	if iatMs >= 0 {
		f.refIATCounts[f.iatBucket(iatMs)]++
	}
	f.refTotal++
	// Keep rolling: drop oldest half when window is full to stay fresh.
	if f.refTotal > 0 && f.refTotal%4096 == 0 {
		for i := range f.refSizeCounts {
			f.refSizeCounts[i] /= 2
		}
		for i := range f.refIATCounts {
			f.refIATCounts[i] /= 2
		}
		f.refTotal /= 2
	}
	f.mu.Unlock()
}

// refDistributions returns the active reference distributions.
// Uses learned data if enough samples exist, falls back to hardcoded defaults.
func (f *FlowObserver) refDistributions() (sizeDist [7]float64, iatDist [5]float64) {
	if f.refTotal >= minRefSamples {
		for i, c := range f.refSizeCounts {
			sizeDist[i] = float64(c) / float64(f.refTotal)
		}
		var iatTot int64
		for _, c := range f.refIATCounts {
			iatTot += c
		}
		if iatTot > 0 {
			for i, c := range f.refIATCounts {
				iatDist[i] = float64(c) / float64(iatTot)
			}
		} else {
			iatDist = defaultRefIATDist
		}
		return sizeDist, iatDist
	}
	return defaultRefSizeDist, defaultRefIATDist
}

// KLReward returns a reward bonus in [0, +0.30] based on how closely
// the current tunnel traffic distribution matches the reference profile.
// Returns 0 when there are not enough tunnel samples yet.
func (f *FlowObserver) KLReward() float64 {
	f.mu.Lock()
	total := atomic.LoadInt64(&f.total) % klDecayPerReset
	if total == 0 {
		total = klDecayPerReset
	}
	sc := f.sizeCounts
	ic := f.iatCounts
	sizeDist, iatDist := f.refDistributions()
	f.mu.Unlock()

	if total < klMinSamples {
		return 0
	}

	var obsSizeDist [7]float64
	var obsIATDist [5]float64
	for i, c := range sc {
		obsSizeDist[i] = float64(c) / float64(total)
	}
	var iatTotal float64
	for _, c := range ic {
		iatTotal += float64(c)
	}
	if iatTotal > 0 {
		for i, c := range ic {
			obsIATDist[i] = float64(c) / iatTotal
		}
	}

	klSize := klDiv(obsSizeDist[:], sizeDist[:])
	klIAT := klDiv(obsIATDist[:], iatDist[:])

	// Weighted combination: packet size matters more for ML DPI classifiers.
	kl := 0.65*klSize + 0.35*klIAT

	return klMaxReward * math.Exp(-3.0*kl)
}

// klDiv computes KL(P || Q) with Laplace smoothing to avoid log(0).
func klDiv(p, q []float64) float64 {
	const eps = 1e-9
	var kl float64
	for i := range p {
		pi := p[i] + eps
		qi := q[i] + eps
		kl += pi * math.Log(pi/qi)
	}
	if math.IsNaN(kl) || math.IsInf(kl, 0) {
		return 2.0
	}
	if kl > 2.0 {
		kl = 2.0
	}
	return kl
}

// GlobalFlowObserver is the shared instance used by all 7 RL agents.
// The tunnel's Send() path calls RecordPacket(); agents read KLReward()
// inside RecordOutcome() to get a reward component.
var GlobalFlowObserver = &FlowObserver{}
