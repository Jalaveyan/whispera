package ml

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

const (
	FlowInputSize  = 8
	FlowHiddenSize = 32
	FlowOutputSize = 7
	FlowMaxAge     = 5 * time.Minute
	FlowMaxEntries = 10000
	FlowBPTTDepth  = 8
	FlowLearnRate  = 0.001
)

type FlowState struct {
	Hidden     []float64
	Cell       []float64
	PacketNum  int
	LastSeen   time.Time
	History    []flowStep
	HistIdx    int
	HistFull   bool
	ClassVotes [FlowOutputSize]int
}

type flowStep struct {
	Input      []float64
	HidPrev    []float64
	CellPrev   []float64
	ForgetGate []float64
	InputGate  []float64
	OutputGate []float64
	CandCell   []float64
	CellNew    []float64
	HidNew     []float64
}

type FlowAnalyzer struct {
	mu    sync.RWMutex
	flows map[string]*FlowState

	WxF, WhF, BF []float64
	WxI, WhI, BI []float64
	WxO, WhO, BO []float64
	WxC, WhC, BC []float64

	Wo []float64
	Bo []float64
}

func NewFlowAnalyzer() *FlowAnalyzer {
	fa := &FlowAnalyzer{
		flows: make(map[string]*FlowState),
		WxF:   xavierInit(FlowInputSize, FlowHiddenSize),
		WhF:   xavierInit(FlowHiddenSize, FlowHiddenSize),
		BF:    biasInit(FlowHiddenSize, 1.0),
		WxI:   xavierInit(FlowInputSize, FlowHiddenSize),
		WhI:   xavierInit(FlowHiddenSize, FlowHiddenSize),
		BI:    make([]float64, FlowHiddenSize),
		WxO:   xavierInit(FlowInputSize, FlowHiddenSize),
		WhO:   xavierInit(FlowHiddenSize, FlowHiddenSize),
		BO:    make([]float64, FlowHiddenSize),
		WxC:   xavierInit(FlowInputSize, FlowHiddenSize),
		WhC:   xavierInit(FlowHiddenSize, FlowHiddenSize),
		BC:    make([]float64, FlowHiddenSize),
		Wo:    xavierInit(FlowHiddenSize, FlowOutputSize),
		Bo:    make([]float64, FlowOutputSize),
	}
	go fa.cleanupLoop()
	return fa
}

func biasInit(size int, val float64) []float64 {
	b := make([]float64, size)
	for i := range b {
		b[i] = val
	}
	return b
}

func ExtractFlowFeatures(data []byte, direction string, interArrivalMs float64) []float64 {
	f := make([]float64, FlowInputSize)
	n := float64(len(data))

	f[0] = math.Min(n/1500.0, 1.0)
	f[1] = math.Log2(n+1) / 11.0
	if direction == "outbound" {
		f[2] = 1.0
	}
	f[3] = math.Min(interArrivalMs/1000.0, 1.0)
	f[4] = math.Min(interArrivalMs/100.0, 1.0)

	if len(data) > 0 {
		f[5] = float64(data[0]) / 255.0
	}
	switch {
	case n < 100:
		f[6] = 0.0
	case n < 500:
		f[6] = 0.5
	default:
		f[6] = 1.0
	}
	if n > 0 {
		var freq [256]int
		for _, b := range data {
			freq[b]++
		}
		ent := 0.0
		for _, c := range freq {
			if c > 0 {
				p := float64(c) / n
				ent -= p * math.Log2(p)
			}
		}
		f[7] = ent / 8.0
	}
	return f
}

func (fa *FlowAnalyzer) Update(flowKey string, packetFeatures []float64) []float64 {
	fa.mu.Lock()
	state, exists := fa.flows[flowKey]
	if !exists {
		state = &FlowState{
			Hidden:  make([]float64, FlowHiddenSize),
			Cell:    make([]float64, FlowHiddenSize),
			History: make([]flowStep, FlowBPTTDepth),
		}
		fa.flows[flowKey] = state
	}
	state.PacketNum++
	state.LastSeen = time.Now()

	hPrev := make([]float64, FlowHiddenSize)
	cPrev := make([]float64, FlowHiddenSize)
	copy(hPrev, state.Hidden)
	copy(cPrev, state.Cell)
	fa.mu.Unlock()

	step := fa.lstmForward(packetFeatures, hPrev, cPrev)

	output := make([]float64, FlowOutputSize)
	for j := 0; j < FlowOutputSize; j++ {
		sum := fa.Bo[j]
		for i := 0; i < FlowHiddenSize; i++ {
			sum += fa.Wo[i*FlowOutputSize+j] * step.HidNew[i]
		}
		output[j] = sum
	}

	fa.mu.Lock()
	copy(state.Hidden, step.HidNew)
	copy(state.Cell, step.CellNew)
	state.History[state.HistIdx] = step
	state.HistIdx = (state.HistIdx + 1) % FlowBPTTDepth
	if state.HistIdx == 0 {
		state.HistFull = true
	}
	fa.mu.Unlock()

	return output
}

func (fa *FlowAnalyzer) lstmForward(x, hPrev, cPrev []float64) flowStep {
	H := FlowHiddenSize
	step := flowStep{
		Input:      copyF64(x),
		HidPrev:    copyF64(hPrev),
		CellPrev:   copyF64(cPrev),
		ForgetGate: make([]float64, H),
		InputGate:  make([]float64, H),
		OutputGate: make([]float64, H),
		CandCell:   make([]float64, H),
		CellNew:    make([]float64, H),
		HidNew:     make([]float64, H),
	}

	for j := 0; j < H; j++ {
		var fSum, iSum, oSum, cSum float64
		fSum = fa.BF[j]
		iSum = fa.BI[j]
		oSum = fa.BO[j]
		cSum = fa.BC[j]
		for k := 0; k < len(x) && k < FlowInputSize; k++ {
			fSum += fa.WxF[k*H+j] * x[k]
			iSum += fa.WxI[k*H+j] * x[k]
			oSum += fa.WxO[k*H+j] * x[k]
			cSum += fa.WxC[k*H+j] * x[k]
		}
		for k := 0; k < H; k++ {
			fSum += fa.WhF[k*H+j] * hPrev[k]
			iSum += fa.WhI[k*H+j] * hPrev[k]
			oSum += fa.WhO[k*H+j] * hPrev[k]
			cSum += fa.WhC[k*H+j] * hPrev[k]
		}
		step.ForgetGate[j] = sigmoid(fSum)
		step.InputGate[j] = sigmoid(iSum)
		step.OutputGate[j] = sigmoid(oSum)
		step.CandCell[j] = math.Tanh(cSum)

		step.CellNew[j] = step.ForgetGate[j]*cPrev[j] + step.InputGate[j]*step.CandCell[j]
		step.HidNew[j] = step.OutputGate[j] * math.Tanh(step.CellNew[j])
	}
	return step
}

func (fa *FlowAnalyzer) LearnOnline(flowKey string, trueClass int) {
	if trueClass < 0 || trueClass >= FlowOutputSize {
		return
	}

	fa.mu.RLock()
	state, exists := fa.flows[flowKey]
	if !exists {
		fa.mu.RUnlock()
		return
	}
	histLen := state.HistIdx
	if state.HistFull {
		histLen = FlowBPTTDepth
	}
	if histLen == 0 {
		fa.mu.RUnlock()
		return
	}

	steps := make([]flowStep, histLen)
	if state.HistFull {
		for i := 0; i < FlowBPTTDepth; i++ {
			idx := (state.HistIdx + i) % FlowBPTTDepth
			steps[i] = state.History[idx]
		}
	} else {
		copy(steps, state.History[:histLen])
	}
	fa.mu.RUnlock()

	H := FlowHiddenSize
	lr := FlowLearnRate

	lastH := steps[histLen-1].HidNew
	output := make([]float64, FlowOutputSize)
	for j := 0; j < FlowOutputSize; j++ {
		sum := fa.Bo[j]
		for i := 0; i < H; i++ {
			sum += fa.Wo[i*FlowOutputSize+j] * lastH[i]
		}
		output[j] = sum
	}

	probs := softmaxF64(output)
	dOutput := make([]float64, FlowOutputSize)
	for j := 0; j < FlowOutputSize; j++ {
		dOutput[j] = probs[j]
	}
	dOutput[trueClass] -= 1.0

	fa.mu.Lock()
	defer fa.mu.Unlock()

	for i := 0; i < H; i++ {
		for j := 0; j < FlowOutputSize; j++ {
			fa.Wo[i*FlowOutputSize+j] -= lr * dOutput[j] * lastH[i]
		}
	}
	for j := 0; j < FlowOutputSize; j++ {
		fa.Bo[j] -= lr * dOutput[j]
	}

	dh := make([]float64, H)
	for i := 0; i < H; i++ {
		for j := 0; j < FlowOutputSize; j++ {
			dh[i] += fa.Wo[i*FlowOutputSize+j] * dOutput[j]
		}
	}
	dc := make([]float64, H)

	for t := histLen - 1; t >= 0; t-- {
		s := &steps[t]

		tanhC := make([]float64, H)
		for j := 0; j < H; j++ {
			tanhC[j] = math.Tanh(s.CellNew[j])
			dc[j] += dh[j] * s.OutputGate[j] * (1 - tanhC[j]*tanhC[j])
		}

		dForget := make([]float64, H)
		dInput := make([]float64, H)
		dOutGate := make([]float64, H)
		dCand := make([]float64, H)

		for j := 0; j < H; j++ {
			dOutGate[j] = dh[j] * tanhC[j] * s.OutputGate[j] * (1 - s.OutputGate[j])
			dForget[j] = dc[j] * s.CellPrev[j] * s.ForgetGate[j] * (1 - s.ForgetGate[j])
			dInput[j] = dc[j] * s.CandCell[j] * s.InputGate[j] * (1 - s.InputGate[j])
			dCand[j] = dc[j] * s.InputGate[j] * (1 - s.CandCell[j]*s.CandCell[j])
		}

		fa.updateGateWeights(fa.WxF, fa.WhF, fa.BF, dForget, s.Input, s.HidPrev, lr)
		fa.updateGateWeights(fa.WxI, fa.WhI, fa.BI, dInput, s.Input, s.HidPrev, lr)
		fa.updateGateWeights(fa.WxO, fa.WhO, fa.BO, dOutGate, s.Input, s.HidPrev, lr)
		fa.updateGateWeights(fa.WxC, fa.WhC, fa.BC, dCand, s.Input, s.HidPrev, lr)

		newDh := make([]float64, H)
		for k := 0; k < H; k++ {
			for j := 0; j < H; j++ {
				newDh[k] += fa.WhF[k*H+j] * dForget[j]
				newDh[k] += fa.WhI[k*H+j] * dInput[j]
				newDh[k] += fa.WhO[k*H+j] * dOutGate[j]
				newDh[k] += fa.WhC[k*H+j] * dCand[j]
			}
		}
		dh = newDh

		newDc := make([]float64, H)
		for j := 0; j < H; j++ {
			newDc[j] = dc[j] * s.ForgetGate[j]
		}
		dc = newDc
	}
}

func (fa *FlowAnalyzer) updateGateWeights(Wx, Wh, B, dGate, x, hPrev []float64, lr float64) {
	H := FlowHiddenSize
	for j := 0; j < H; j++ {
		for k := 0; k < FlowInputSize && k < len(x); k++ {
			Wx[k*H+j] -= lr * dGate[j] * x[k]
		}
		for k := 0; k < H; k++ {
			Wh[k*H+j] -= lr * dGate[j] * hPrev[k]
		}
		B[j] -= lr * dGate[j]
	}
}

func (fa *FlowAnalyzer) GetFlowConfidence(flowKey string) (classID int, confidence float64) {
	fa.mu.RLock()
	state, exists := fa.flows[flowKey]
	fa.mu.RUnlock()
	if !exists || state.PacketNum < 3 {
		return -1, 0
	}

	fa.mu.RLock()
	hidden := make([]float64, FlowHiddenSize)
	copy(hidden, state.Hidden)
	fa.mu.RUnlock()

	output := make([]float64, FlowOutputSize)
	for j := 0; j < FlowOutputSize; j++ {
		sum := fa.Bo[j]
		for i := 0; i < FlowHiddenSize; i++ {
			sum += fa.Wo[i*FlowOutputSize+j] * hidden[i]
		}
		output[j] = sum
	}

	probs := softmaxF64(output)
	best := 0
	for i := 1; i < len(probs); i++ {
		if probs[i] > probs[best] {
			best = i
		}
	}
	return best, probs[best]
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func copyF64(s []float64) []float64 {
	out := make([]float64, len(s))
	copy(out, s)
	return out
}

func (fa *FlowAnalyzer) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		fa.mu.Lock()
		cutoff := time.Now().Add(-FlowMaxAge)
		for k, v := range fa.flows {
			if v.LastSeen.Before(cutoff) {
				delete(fa.flows, k)
			}
		}
		for len(fa.flows) > FlowMaxEntries {
			var oldestKey string
			var oldestTime time.Time
			first := true
			for k, v := range fa.flows {
				if first || v.LastSeen.Before(oldestTime) {
					oldestKey = k
					oldestTime = v.LastSeen
					first = false
				}
			}
			if oldestKey != "" {
				delete(fa.flows, oldestKey)
			}
		}
		fa.mu.Unlock()
	}
}

func xavierInit(in, out int) []float64 {
	scale := math.Sqrt(2.0 / float64(in+out))
	w := make([]float64, in*out)
	for i := range w {
		w[i] = randNormLocal() * scale
	}
	return w
}

func randNormLocal() float64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	u1 := float64(binary.LittleEndian.Uint32(buf[:4]))/float64(1<<32) + 1e-10
	u2 := float64(binary.LittleEndian.Uint32(buf[4:]))/float64(1<<32) + 1e-10
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}
