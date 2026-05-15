package chameleon

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"

	"golang.org/x/crypto/hkdf"
)

// trafficGRU is a tiny Gated Recurrent Unit that generates (size, delay) pairs
// for traffic shaping. Weights are derived from the session HKDF seed — each
// session gets a unique network, producing a unique-but-realistic traffic fingerprint
// without any pre-training or model files.
//
// Architecture: GRU with H=16 hidden, I=8 noise input → 2 outputs (size, delay).
// Parameter count: ~1250 float32 ≈ 5 KB per session (stack-allocated).
//
// Output mapping (sigmoid → realistic HTTP/2 ranges):
//   size  ∈ [64, 4096] bytes  — bimodal via output nonlinearity
//   delay ∈ [0, 80] ms        — exponentially distributed via -ln(1-y)
const (
	gruH = 16 // hidden size
	gruI = 8  // noise input size
	gruC = gruH + gruI
)

type trafficGRU struct {
	// Reset gate:  r = σ(Wr @ [h,x] + br)
	Wr [gruH][gruC]float32
	Br [gruH]float32
	// Update gate: z = σ(Wz @ [h,x] + bz)
	Wz [gruH][gruC]float32
	Bz [gruH]float32
	// New gate:    n = tanh(Wn @ [r⊙h, x] + bn)
	Wn [gruH][gruC]float32
	Bn [gruH]float32
	// Output proj: y = σ(Wo @ h + bo)  → [size_norm, delay_norm]
	Wo [2][gruH]float32
	Bo [2]float32

	h   [gruH]float32 // hidden state (evolves each call)
	rng lcg            // fast in-session noise source
}

// lcg is a 64-bit linear congruential PRNG — deterministic, no allocations.
type lcg struct{ state uint64 }

func (l *lcg) next() float32 {
	l.state = l.state*6364136223846793005 + 1442695040888963407
	// map to [-1, 1]
	return float32(int32(l.state>>33))/float32(1<<31) * 0.3
}

// newTrafficGRU builds a GRU whose weights are derived from behaviorKey + window + sessionID.
// Both client and server derive identical weights from the same inputs.
func newTrafficGRU(behaviorKey []byte, window int64, sessionID []byte) *trafficGRU {
	salt := make([]byte, 8+len(sessionID))
	binary.BigEndian.PutUint64(salt, uint64(window))
	copy(salt[8:], sessionID)

	r := hkdf.New(sha256.New, behaviorKey, salt, []byte("chameleon-gru-v1"))

	// Read enough bytes for all weights:
	// 3 × (H×C + H) + 2×H + 2 = 3×(16×24+16) + 32 + 2 = 3×400 + 34 = 1234 float32 = 4936 bytes
	raw := make([]byte, 1234*4)
	if _, err := io.ReadFull(r, raw); err != nil {
		panic("chameleon gru derive: " + err.Error())
	}

	g := &trafficGRU{}
	off := 0

	readF := func() float32 {
		v := binary.BigEndian.Uint32(raw[off:])
		off += 4
		// Xavier uniform: scale weights to [-0.5/√C, 0.5/√C] for stability
		return (float32(v)/float32(math.MaxUint32) - 0.5) * float32(1.0/math.Sqrt(float64(gruC)))
	}
	readB := func() float32 {
		v := binary.BigEndian.Uint32(raw[off:])
		off += 4
		return (float32(v)/float32(math.MaxUint32) - 0.5) * 0.1 // small biases
	}

	for i := 0; i < gruH; i++ {
		for j := 0; j < gruC; j++ {
			g.Wr[i][j] = readF()
		}
		g.Br[i] = readB()
	}
	for i := 0; i < gruH; i++ {
		for j := 0; j < gruC; j++ {
			g.Wz[i][j] = readF()
		}
		g.Bz[i] = readB()
	}
	for i := 0; i < gruH; i++ {
		for j := 0; j < gruC; j++ {
			g.Wn[i][j] = readF()
		}
		g.Bn[i] = readB()
	}
	for i := 0; i < 2; i++ {
		for j := 0; j < gruH; j++ {
			g.Wo[i][j] = readF()
		}
		g.Bo[i] = readB()
	}

	// Seed LCG from first 8 bytes of remaining HKDF output.
	var lcgSeed [8]byte
	io.ReadFull(r, lcgSeed[:])
	g.rng.state = binary.BigEndian.Uint64(lcgSeed[:])

	return g
}

// Next advances the GRU one step and returns (chunkSize, delayMs).
func (g *trafficGRU) Next() (chunkSize int, delayMs float64) {
	// Build input vector: I random noise values
	var x [gruC]float32
	for i := gruH; i < gruC; i++ {
		x[i] = g.rng.next()
	}
	// Prefix with current hidden state
	copy(x[:gruH], g.h[:])

	sigmoid := func(v float32) float32 {
		return 1.0 / (1.0 + float32(math.Exp(-float64(v))))
	}
	tanh32 := func(v float32) float32 {
		return float32(math.Tanh(float64(v)))
	}
	dot := func(row [gruC]float32, inp [gruC]float32, bias float32) float32 {
		s := bias
		for k := 0; k < gruC; k++ {
			s += row[k] * inp[k]
		}
		return s
	}

	// Reset gate
	var r [gruH]float32
	for i := 0; i < gruH; i++ {
		r[i] = sigmoid(dot(g.Wr[i], x, g.Br[i]))
	}

	// Update gate
	var z [gruH]float32
	for i := 0; i < gruH; i++ {
		z[i] = sigmoid(dot(g.Wz[i], x, g.Bz[i]))
	}

	// New gate (reset gate applied to hidden state portion of x)
	var xr [gruC]float32
	copy(xr[:gruH], g.h[:])
	for i := 0; i < gruH; i++ {
		xr[i] *= r[i]
	}
	copy(xr[gruH:], x[gruH:])
	var n [gruH]float32
	for i := 0; i < gruH; i++ {
		n[i] = tanh32(dot(g.Wn[i], xr, g.Bn[i]))
	}

	// Update hidden state: h = (1-z)⊙n + z⊙h
	for i := 0; i < gruH; i++ {
		g.h[i] = (1-z[i])*n[i] + z[i]*g.h[i]
	}

	// Output projection → 2 sigmoid values
	var out [2]float32
	for i := 0; i < 2; i++ {
		s := g.Bo[i]
		for j := 0; j < gruH; j++ {
			s += g.Wo[i][j] * g.h[j]
		}
		out[i] = sigmoid(s)
	}

	// Map sigmoid outputs to realistic HTTP/2 traffic ranges:
	//   out[0] → size: bimodal — small frames (headers ~64-256B) or data frames (512-4096B)
	//   out[1] → delay: exponential via -ln(1-y)*mean; clipped at 80ms
	sizeNorm := float64(out[0])
	delayNorm := float64(out[1])

	// Bimodal size: below 0.3 → small frame (64-512), above → data frame (256-4096)
	var size float64
	if sizeNorm < 0.3 {
		size = 64 + sizeNorm/0.3*448 // 64..512
	} else {
		size = 256 + (sizeNorm-0.3)/0.7*3840 // 256..4096
	}

	// Exponential delay with mean 8ms, clipped at 80ms
	delay := -math.Log(1-math.Min(delayNorm, 0.999)) * 8.0
	if delay > 80 {
		delay = 80
	}

	return int(size), delay
}
