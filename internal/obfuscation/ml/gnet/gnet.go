package gnet

import (
	"crypto/rand"
	"encoding/binary"
	"math"
)

type LayerDef struct {
	InSize  int       `json:"in"`
	OutSize int       `json:"out"`
	W       []float64 `json:"w"`
	B       []float64 `json:"b"`
}

type GorgoniaNet struct {
	Layers []LayerDef
}

func New(sizes []int) *GorgoniaNet {
	net := &GorgoniaNet{}
	for i := 0; i < len(sizes)-1; i++ {
		in, out := sizes[i], sizes[i+1]
		scale := math.Sqrt(2.0 / float64(in)) // He init
		w := make([]float64, in*out)
		for j := range w {
			w[j] = RandNorm() * scale
		}
		b := make([]float64, out)
		net.Layers = append(net.Layers, LayerDef{InSize: in, OutSize: out, W: w, B: b})
	}
	return net
}

// Forward runs a fast inference pass (ReLU hidden, linear output).
func (net *GorgoniaNet) Forward(input []float64) []float64 {
	cur := input
	for i, ld := range net.Layers {
		out := make([]float64, ld.OutSize)
		for j := 0; j < ld.OutSize; j++ {
			sum := ld.B[j]
			for k := 0; k < ld.InSize && k < len(cur); k++ {
				sum += cur[k] * ld.W[k*ld.OutSize+j]
			}
			if i < len(net.Layers)-1 && sum < 0 {
				sum = 0 // ReLU
			}
			out[j] = sum
		}
		cur = out
	}
	return cur
}

// ForwardActivations runs a forward pass and returns activations at every layer
// (index 0 = input, index L = output). Required for backpropagation.
func (net *GorgoniaNet) ForwardActivations(input []float64) [][]float64 {
	acts := make([][]float64, len(net.Layers)+1)
	acts[0] = input
	cur := input
	for i, ld := range net.Layers {
		out := make([]float64, ld.OutSize)
		for j := 0; j < ld.OutSize; j++ {
			sum := ld.B[j]
			for k := 0; k < ld.InSize && k < len(cur); k++ {
				sum += cur[k] * ld.W[k*ld.OutSize+j]
			}
			if i < len(net.Layers)-1 && sum < 0 {
				sum = 0 // ReLU
			}
			out[j] = sum
		}
		acts[i+1] = out
		cur = out
	}
	return acts
}

func (net *GorgoniaNet) LoadWeights(layers []LayerDef) {
	for i, l := range layers {
		if i >= len(net.Layers) {
			break
		}
		if len(l.W) == len(net.Layers[i].W) {
			copy(net.Layers[i].W, l.W)
		}
		if len(l.B) == len(net.Layers[i].B) {
			copy(net.Layers[i].B, l.B)
		}
	}
}

func Clone(src *GorgoniaNet) *GorgoniaNet {
	dst := &GorgoniaNet{}
	for _, l := range src.Layers {
		dst.Layers = append(dst.Layers, LayerDef{
			InSize: l.InSize, OutSize: l.OutSize,
			W: CopyF64(l.W), B: CopyF64(l.B),
		})
	}
	return dst
}

func RandNorm() float64 {
	var buf [8]byte
	rand.Read(buf[:])
	u1 := float64(binary.LittleEndian.Uint64(buf[:])) / float64(math.MaxUint64)
	if u1 < 1e-15 {
		u1 = 1e-15
	}
	rand.Read(buf[:])
	u2 := float64(binary.LittleEndian.Uint64(buf[:])) / float64(math.MaxUint64)
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}

func CopyF64(src []float64) []float64 {
	dst := make([]float64, len(src))
	copy(dst, src)
	return dst
}
