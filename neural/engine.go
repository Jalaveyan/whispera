package neural

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/cmplx"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"whispera/neural/gnet"
	"whispera/neural/types"

	"gorgonia.org/gorgonia"
	"gorgonia.org/tensor"
)

const (
	InputSize          = 52
	HiddenSize1        = 256
	HiddenSize2        = 128
	HiddenSize3        = 64
	HiddenSize4        = 32
	TrafficClasses     = 7
	DPIClasses         = 9
	TransportFeatures  = 42
	TransportChoices   = 28
	DefaultLR          = 0.0005
	DefaultL2          = 0.00005
	BatchSize          = 32
	ReplayBufferSize   = 10000
	PseudoLabelMinConf = 0.90
	SelfLearnInterval  = 300 * time.Second
	RetrainThreshold   = 200
	ValidationSplit    = 0.2
	MinAccForDeploy    = 0.60
	AccDegradationWarn = 0.10
)

type GorgoniaNet = gnet.GorgoniaNet
type LayerDef = gnet.LayerDef

type FeatureNormalizer struct {
	Mean    []float64 `json:"mean"`
	Std     []float64 `json:"std"`
	Samples int64     `json:"samples"`
}

type ProtocolPattern struct {
	Name       string
	Magic      []byte
	Offset     int
	ClassID    int
	Confidence float64
}

type TrainingSample struct {
	Features  []float64
	ClassID   int
	DPIType   int
	IsLabeled bool
	Quality   float64
}

func sampleQuality(features []float64) float64 {
	if len(features) == 0 {
		return 0
	}
	nonZero := 0
	sum, sumSq := 0.0, 0.0
	for _, v := range features {
		if v != 0 {
			nonZero++
		}
		sum += v
		sumSq += v * v
	}
	n := float64(len(features))
	if nonZero < 3 {
		return 0
	}
	mean := sum / n
	variance := sumSq/n - mean*mean
	if variance < 1e-12 {
		return 0
	}
	coverage := float64(nonZero) / n
	return coverage * math.Min(1.0, math.Sqrt(variance)/10.0)
}

type ReplayBuffer struct {
	samples  []TrainingSample
	maxSize  int
	writeIdx int
	full     bool
}

type TransportStats struct {
	Success    int64
	Fail       int64
	TotalMS    int64
	LastUpdate time.Time
}

type blockStats struct {
	success  int64
	fail     int64
	lastSeen time.Time
}

type ModelState struct {
	TrafficLayers   []LayerDef         `json:"traffic"`
	DPILayers       []LayerDef         `json:"dpi"`
	AnomalyLayers   []LayerDef         `json:"anomaly"`
	TransportLayers []LayerDef         `json:"transport"`
	Normalizer      *FeatureNormalizer `json:"norm"`
	Accuracy        float64            `json:"accuracy"`
	Trained         int64              `json:"trained"`
}

type NativeMLEngine struct {
	mu sync.RWMutex

	trafficNet   *GorgoniaNet
	dpiNet       *GorgoniaNet
	anomalyNet   *GorgoniaNet
	transportNet *GorgoniaNet

	featureNorm      *FeatureNormalizer
	protocolPatterns map[string]*ProtocolPattern

	modelDir string

	replayBuf *ReplayBuffer

	transportStats sync.Map

	sampleCount       int64
	predictionCount   int64
	pseudoLabelCount  int64
	retrainCount      int64
	accuracy          float64
	valAccuracy       float64
	prevAccuracy      float64
	lastTrained       time.Time
	samplesAfterTrain int64

	trainingActive  int32
	trainEpoch      int32
	trainTotalEpoch int32
	trainLoss       float64
	stopTraining    chan struct{}
	stopSelfLearn   chan struct{}
	selfLearnWG     sync.WaitGroup

	labeledBuf *ReplayBuffer

	blockHistory sync.Map

	flowAnalyzer *FlowAnalyzer
	rlAgent      *RLTransportAgent
	tspuDetector *TSPUDetector

	onDPIProfile     atomic.Value
	lastProfileDPI   int32
	profileHitStreak int32

	onTSPUDetected atomic.Value
	lastTSPUType   int32
	tspuHitStreak  int32

	activeConn int32
}

func NewNativeMLEngine(modelDir string) *NativeMLEngine {
	e := &NativeMLEngine{
		modelDir:      modelDir,
		accuracy:      0.5,
		stopTraining:  make(chan struct{}),
		stopSelfLearn: make(chan struct{}),
		replayBuf:     newReplayBuffer(ReplayBufferSize),
		labeledBuf:    newReplayBuffer(ReplayBufferSize / 2),
	}
	e.initProtocolPatterns()
	e.featureNorm = &FeatureNormalizer{
		Mean: make([]float64, InputSize),
		Std:  ones(InputSize),
	}
	e.trafficNet = gnet.New([]int{InputSize, HiddenSize1, HiddenSize2, HiddenSize3, HiddenSize4, TrafficClasses})
	e.dpiNet = gnet.New([]int{InputSize, HiddenSize2, HiddenSize3, HiddenSize4, DPIClasses})
	e.anomalyNet = gnet.New([]int{InputSize, HiddenSize2, HiddenSize3, HiddenSize4, 1})
	e.transportNet = gnet.New([]int{TransportFeatures, HiddenSize2, HiddenSize3, HiddenSize4, TransportChoices})
	e.flowAnalyzer = NewFlowAnalyzer()
	e.rlAgent = NewRLTransportAgent(modelDir, nil)
	e.tspuDetector = NewTSPUDetector()
	e.loadModel()
	if e.ShouldPretrain() {
		go e.PretrainFromPatterns()
	}
	go e.selfLearnLoop()
	return e
}

func newReplayBuffer(maxSize int) *ReplayBuffer {
	return &ReplayBuffer{
		samples: make([]TrainingSample, maxSize),
		maxSize: maxSize,
	}
}

func (rb *ReplayBuffer) add(s TrainingSample) {
	rb.samples[rb.writeIdx] = s
	rb.writeIdx++
	if rb.writeIdx >= rb.maxSize {
		rb.writeIdx = 0
		rb.full = true
	}
}

func (rb *ReplayBuffer) getAll() []TrainingSample {
	if rb.full {
		out := make([]TrainingSample, rb.maxSize)
		copy(out, rb.samples)
		return out
	}
	out := make([]TrainingSample, rb.writeIdx)
	copy(out, rb.samples[:rb.writeIdx])
	return out
}

func (rb *ReplayBuffer) getQualityFiltered(minQuality float64) []TrainingSample {
	src := rb.samples
	if !rb.full {
		src = rb.samples[:rb.writeIdx]
	}
	out := make([]TrainingSample, 0, len(src))
	for _, s := range src {
		if s.Quality >= minQuality {
			out = append(out, s)
		}
	}
	return out
}

func (rb *ReplayBuffer) size() int {
	if rb.full {
		return rb.maxSize
	}
	return rb.writeIdx
}

type gorgoniaTrainer struct {
	net      *GorgoniaNet
	isBinary bool
	outSize  int
	solver   gorgonia.Solver
}

func newTrainer(net *GorgoniaNet, outputSize int, isBinary bool) *gorgoniaTrainer {
	return &gorgoniaTrainer{
		net:      net,
		isBinary: isBinary,
		outSize:  outputSize,
		solver:   gorgonia.NewAdamSolver(gorgonia.WithLearnRate(DefaultLR), gorgonia.WithL2Reg(DefaultL2), gorgonia.WithBatchSize(float64(BatchSize))),
	}
}

func (t *gorgoniaTrainer) step(xData, yData []float64) (float64, error) {
	inSize := t.net.Layers[0].InSize
	g := gorgonia.NewGraph()

	x := gorgonia.NewMatrix(g, gorgonia.Float64, gorgonia.WithShape(BatchSize, inSize), gorgonia.WithName("x"))
	y := gorgonia.NewMatrix(g, gorgonia.Float64, gorgonia.WithShape(BatchSize, t.outSize), gorgonia.WithName("y"))

	var weights []*gorgonia.Node
	var biases []*gorgonia.Node

	result := x
	for i, ld := range t.net.Layers {
		wVal := tensor.New(tensor.WithShape(ld.InSize, ld.OutSize), tensor.WithBacking(gnet.CopyF64(ld.W)))
		bVal := tensor.New(tensor.WithShape(1, ld.OutSize), tensor.WithBacking(gnet.CopyF64(ld.B)))
		wNode := gorgonia.NewMatrix(g, gorgonia.Float64, gorgonia.WithShape(ld.InSize, ld.OutSize), gorgonia.WithValue(wVal), gorgonia.WithName(fmt.Sprintf("w%d", i)))
		bNode := gorgonia.NewMatrix(g, gorgonia.Float64, gorgonia.WithShape(1, ld.OutSize), gorgonia.WithValue(bVal), gorgonia.WithName(fmt.Sprintf("b%d", i)))

		weights = append(weights, wNode)
		biases = append(biases, bNode)

		linear := gorgonia.Must(gorgonia.Mul(result, wNode))
		linear = gorgonia.Must(gorgonia.BroadcastAdd(linear, bNode, nil, []byte{0}))

		if i < len(t.net.Layers)-1 {
			result = gorgonia.Must(gorgonia.Rectify(linear))
		} else {
			if t.isBinary {
				result = gorgonia.Must(gorgonia.Sigmoid(linear))
			} else {
				result = gorgonia.Must(gorgonia.SoftMax(linear))
			}
		}
	}

	eps := gorgonia.NewConstant(1e-7)
	logPred := gorgonia.Must(gorgonia.Log(gorgonia.Must(gorgonia.Add(result, eps))))
	ce := gorgonia.Must(gorgonia.HadamardProd(y, logPred))
	loss := gorgonia.Must(gorgonia.Neg(gorgonia.Must(gorgonia.Mean(ce))))

	var grads gorgonia.Nodes
	grads = append(grads, weights...)
	grads = append(grads, biases...)
	_, _ = gorgonia.Grad(loss, grads...)

	xT := tensor.New(tensor.WithShape(BatchSize, inSize), tensor.WithBacking(gnet.CopyF64(xData)))
	yT := tensor.New(tensor.WithShape(BatchSize, t.outSize), tensor.WithBacking(gnet.CopyF64(yData)))
	_ = gorgonia.Let(x, xT)
	_ = gorgonia.Let(y, yT)

	vm := gorgonia.NewTapeMachine(g, gorgonia.BindDualValues(weights...), gorgonia.BindDualValues(biases...))
	defer vm.Close()

	if err := vm.RunAll(); err != nil {
		return 0, err
	}

	lossVal := loss.Value().Data().(float64)

	var vg []gorgonia.ValueGrad
	for _, w := range weights {
		vg = append(vg, w)
	}
	for _, b := range biases {
		vg = append(vg, b)
	}
	if err := t.solver.Step(vg); err != nil {
		return lossVal, err
	}

	for i := range t.net.Layers {
		copy(t.net.Layers[i].W, weights[i].Value().Data().([]float64))
		copy(t.net.Layers[i].B, biases[i].Value().Data().([]float64))
	}

	return lossVal, nil
}

func (e *NativeMLEngine) selfLearnLoop() {
	ticker := time.NewTicker(SelfLearnInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopSelfLearn:
			return
		case <-ticker.C:
			after := atomic.LoadInt64(&e.samplesAfterTrain)
			if after >= RetrainThreshold && !e.IsTraining() {
				e.selfLearnWG.Add(1)
				go func() {
					defer e.selfLearnWG.Done()
					e.Train(30)
					atomic.StoreInt64(&e.samplesAfterTrain, 0)
					atomic.AddInt64(&e.retrainCount, 1)
					e.saveModel()
				}()
			}
		}
	}
}

func (e *NativeMLEngine) initProtocolPatterns() {
	e.protocolPatterns = map[string]*ProtocolPattern{
		"tls_hs":    {Name: "TLS", Magic: []byte{0x16, 0x03}, Offset: 0, ClassID: 0, Confidence: 0.95},
		"tls_data":  {Name: "TLS", Magic: []byte{0x17, 0x03, 0x03}, Offset: 0, ClassID: 0, Confidence: 0.92},
		"http_get":  {Name: "HTTP", Magic: []byte("GET "), Offset: 0, ClassID: 1, Confidence: 0.95},
		"http_post": {Name: "HTTP", Magic: []byte("POST"), Offset: 0, ClassID: 1, Confidence: 0.95},
		"http_resp": {Name: "HTTP", Magic: []byte("HTTP"), Offset: 0, ClassID: 1, Confidence: 0.92},
		"dns":       {Name: "DNS", Magic: nil, Offset: 0, ClassID: 2, Confidence: 0.90},
		"quic":      {Name: "QUIC", Magic: []byte{0xc0}, Offset: 0, ClassID: 3, Confidence: 0.80},
		"wg":        {Name: "WG", Magic: []byte{0x01, 0x00, 0x00, 0x00}, Offset: 0, ClassID: 4, Confidence: 0.85},
		"ssh":       {Name: "SSH", Magic: []byte("SSH-"), Offset: 0, ClassID: 5, Confidence: 0.95},
		"openvpn":   {Name: "OpenVPN", Magic: []byte{0x00, 0x0e}, Offset: 0, ClassID: 6, Confidence: 0.80},
	}
}

func (e *NativeMLEngine) ExtractFeatures(data []byte) []float64 {
	f := make([]float64, InputSize)
	n := float64(len(data))
	if n == 0 {
		return f
	}

	f[0] = n
	f[1] = math.Log2(n + 1)
	f[2] = math.Log10(n + 1)

	var freq [256]int
	zeros := 0
	for _, b := range data {
		freq[b]++
		if b == 0 {
			zeros++
		}
	}
	f[3] = float64(zeros) / n

	entropy := 0.0
	distinct := 0
	sumSq := 0.0
	for _, c := range freq {
		if c > 0 {
			distinct++
			p := float64(c) / n
			entropy -= p * math.Log2(p)
			sumSq += p * p
		}
	}
	f[4] = entropy
	f[5] = float64(distinct) / 256.0
	f[6] = sumSq

	if len(data) >= 4 {
		f[7] = float64(data[0])
		f[8] = float64(data[1])
		f[9] = float64(data[2])
		f[10] = float64(data[3])
	}

	for _, p := range e.protocolPatterns {
		if p.Magic != nil && len(data) > p.Offset+len(p.Magic) {
			if bytes.Equal(data[p.Offset:p.Offset+len(p.Magic)], p.Magic) {
				f[11] = float64(p.ClassID + 1)
				f[12] = p.Confidence
				break
			}
		}
	}

	if isDNSPacket(data) {
		f[11] = 3
		f[12] = 0.90
	}

	if len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03 {
		f[13] = float64(data[2])
	}

	head := data
	if len(head) > 64 {
		head = head[:64]
	}
	f[14] = calcEntropy(head)

	if len(data) > 64 {
		f[15] = calcEntropy(data[len(data)-64:])
	}

	printable := 0
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			printable++
		}
	}
	f[16] = float64(printable) / n

	if len(data) >= 4 {
		bigram := 0
		for i := 0; i < len(data)-1; i++ {
			if data[i] == data[i+1] {
				bigram++
			}
		}
		f[17] = float64(bigram) / (n - 1)
	}

	if len(data) > 2 {
		diffSum := 0.0
		for i := 1; i < len(data) && i < 256; i++ {
			diff := float64(data[i]) - float64(data[i-1])
			diffSum += diff * diff
		}
		cnt := math.Min(float64(len(data)-1), 255)
		f[18] = math.Sqrt(diffSum / cnt)
	}

	if len(data) >= 2 {
		f[19] = float64(binary.BigEndian.Uint16(data[:2]))
	}

	var sorted [256]int
	copy(sorted[:], freq[:])
	sortIntDesc(sorted[:])
	f[20] = float64(sorted[0]) / n
	if distinct > 1 {
		f[21] = float64(sorted[1]) / n
	}

	sum := 0.0
	for _, b := range data {
		sum += float64(b)
	}
	mean := sum / n
	f[22] = mean

	variance := 0.0
	for _, b := range data {
		d := float64(b) - mean
		variance += d * d
	}
	variance /= n
	f[23] = math.Sqrt(variance)
	f[24] = variance

	skewness := 0.0
	kurtosis := 0.0
	sd := math.Sqrt(variance)
	if sd > 1e-8 {
		for _, b := range data {
			z := (float64(b) - mean) / sd
			z3 := z * z * z
			skewness += z3
			kurtosis += z3 * z
		}
		skewness /= n
		kurtosis = kurtosis/n - 3.0
	}
	f[25] = skewness
	f[26] = kurtosis

	vals := make([]float64, len(data))
	for i, b := range data {
		vals[i] = float64(b)
	}
	q := quartiles(vals)
	f[27] = q[0]
	f[28] = q[1]
	f[29] = q[2]
	f[30] = q[2] - q[0]

	fftMag := fftMagnitude(data, 8)
	copy(f[31:31+8], fftMag)

	var hist [8]float64
	for _, b := range data {
		bin := int(b) / 32
		if bin > 7 {
			bin = 7
		}
		hist[bin]++
	}
	for i := range hist {
		f[39+i] = hist[i] / n
	}

	longestRun := 0
	currentRun := 1
	for i := 1; i < len(data); i++ {
		if data[i] == data[i-1] {
			currentRun++
		} else {
			if currentRun > longestRun {
				longestRun = currentRun
			}
			currentRun = 1
		}
	}
	if currentRun > longestRun {
		longestRun = currentRun
	}
	f[47] = float64(longestRun) / n

	ascending := 0
	for i := 1; i < len(data); i++ {
		if data[i] >= data[i-1] {
			ascending++
		}
	}
	if len(data) > 1 {
		f[48] = float64(ascending) / float64(len(data)-1)
	}

	if len(data) >= 4 {
		trigrams := make(map[uint32]int)
		for i := 0; i < len(data)-2; i++ {
			key := uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			trigrams[key]++
		}
		f[49] = float64(len(trigrams)) / float64(len(data)-2)
	}

	chiSq := 0.0
	expected := n / 256.0
	for _, c := range freq {
		d := float64(c) - expected
		chiSq += d * d / expected
	}
	f[50] = chiSq / 256.0

	serialCorr := 0.0
	if len(data) > 1 && sd > 1e-8 {
		for i := 0; i < len(data)-1; i++ {
			serialCorr += (float64(data[i]) - mean) * (float64(data[i+1]) - mean)
		}
		serialCorr /= float64(len(data)-1) * variance
	}
	f[51] = serialCorr

	return f
}

func calcEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	e := 0.0
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

func fftMagnitude(data []byte, bins int) []float64 {
	n := 64
	if len(data) < n {
		n = len(data)
	}
	if n == 0 {
		return make([]float64, bins)
	}
	c := make([]complex128, n)
	for i := 0; i < n; i++ {
		c[i] = complex(float64(data[i]), 0)
	}
	fft(c)
	mag := make([]float64, bins)
	binSize := n / bins
	if binSize < 1 {
		binSize = 1
	}
	for i := 0; i < bins && i*binSize < n/2; i++ {
		sum := 0.0
		for j := 0; j < binSize && i*binSize+j < n/2; j++ {
			sum += cmplx.Abs(c[i*binSize+j])
		}
		mag[i] = sum / float64(binSize)
	}
	return mag
}

func fft(a []complex128) {
	n := len(a)
	if n <= 1 {
		return
	}
	if n&(n-1) != 0 {
		return
	}
	for i, j := 1, 0; i < n; i++ {
		bit := n >> 1
		for ; j&bit != 0; bit >>= 1 {
			j ^= bit
		}
		j ^= bit
		if i < j {
			a[i], a[j] = a[j], a[i]
		}
	}
	for length := 2; length <= n; length <<= 1 {
		w := cmplx.Exp(complex(0, -2*math.Pi/float64(length)))
		for i := 0; i < n; i += length {
			wn := complex(1, 0)
			for j := 0; j < length/2; j++ {
				u := a[i+j]
				v := a[i+j+length/2] * wn
				a[i+j] = u + v
				a[i+j+length/2] = u - v
				wn *= w
			}
		}
	}
}

func quartiles(vals []float64) [3]float64 {
	n := len(vals)
	if n == 0 {
		return [3]float64{}
	}
	sorted := make([]float64, n)
	copy(sorted, vals)
	sortFloat64(sorted)
	return [3]float64{
		sorted[n/4],
		sorted[n/2],
		sorted[3*n/4],
	}
}

func sortFloat64(a []float64) {
	for i := 1; i < len(a); i++ {
		key := a[i]
		j := i - 1
		for j >= 0 && a[j] > key {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = key
	}
}

func sortIntDesc(a []int) {
	for i := 1; i < len(a); i++ {
		key := a[i]
		j := i - 1
		for j >= 0 && a[j] < key {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = key
	}
}

func (e *NativeMLEngine) normalize(features []float64) []float64 {
	e.mu.RLock()
	norm := e.featureNorm
	e.mu.RUnlock()

	out := make([]float64, len(features))
	for i := range features {
		if i < len(norm.Mean) && i < len(norm.Std) && norm.Std[i] > 1e-8 {
			out[i] = (features[i] - norm.Mean[i]) / norm.Std[i]
		} else {
			out[i] = features[i]
		}
	}
	return out
}

func (e *NativeMLEngine) Predict(data []byte, protocol, direction string) *types.MLPredictionResponse {
	atomic.AddInt64(&e.predictionCount, 1)

	var patternHint int = -1
	for _, p := range e.protocolPatterns {
		if p.Magic != nil && len(data) > p.Offset+len(p.Magic) {
			if bytes.Equal(data[p.Offset:p.Offset+len(p.Magic)], p.Magic) {
				patternHint = p.ClassID
				break
			}
		}
	}
	if patternHint < 0 && isDNSPacket(data) {
		patternHint = 2
	}

	features := e.ExtractFeatures(data)
	normF := e.normalize(features)

	e.mu.RLock()
	rawTraffic := e.trafficNet.Forward(normF)
	rawDPI := e.dpiNet.Forward(normF)
	rawAnomaly := e.anomalyNet.Forward(normF)
	e.mu.RUnlock()

	probs := softmaxF64(rawTraffic)
	classID := argmax(probs)
	confidence := probs[classID]

	if patternHint >= 0 {
		e.addGroundTruth(features, patternHint, 0)
	}

	if confidence >= PseudoLabelMinConf {
		if patternHint < 0 || classID == patternHint {
			e.addPseudoLabel(features, classID, 0)
		}
	}

	dpiProbs := softmaxF64(rawDPI)
	dpiType := argmax(dpiProbs)
	dpiConf := dpiProbs[dpiType]
	dpiName := ""
	if dpiConf > 0.6 && dpiType > 0 {
		dpiName = DPITypeName(dpiType)
	} else {
		dpiType = 0
	}

	if e.tspuDetector != nil {
		tspuType, tspuConf := e.tspuDetector.DetectTSPU()
		if tspuType != DPITypeNone && tspuConf > dpiConf {
			dpiType = tspuType
			dpiName = DPITypeName(tspuType)
		}
		e.maybeFireTSPUDetected(tspuType, tspuConf)
	}

	anomalyScore := sigmoidF64(rawAnomaly[0])
	isAnomaly := anomalyScore > 0.7

	e.maybeFireProfileChange(dpiType, dpiConf)

	return &types.MLPredictionResponse{
		Predictions: []types.PredictionResult{
			{
				ClassID:      classID,
				Confidence:   confidence,
				Protocol:     protocol,
				Direction:    direction,
				DPIType:      dpiType,
				DPIName:      dpiName,
				IsAnomaly:    isAnomaly,
				AnomalyScore: anomalyScore,
			},
		},
		ModelUsed:  "gorgonia_mlp_go",
		Confidence: confidence,
		Timestamp:  time.Now(),
	}
}

func (e *NativeMLEngine) PredictWithFlow(data []byte, protocol, direction, flowKey string, interArrivalMs float64) *types.MLPredictionResponse {
	resp := e.Predict(data, protocol, direction)

	if flowKey != "" && e.flowAnalyzer != nil {
		flowFeatures := ExtractFlowFeatures(data, direction, interArrivalMs)
		e.flowAnalyzer.Update(flowKey, flowFeatures)

		patternClass := e.matchPattern(data)
		if patternClass >= 0 {
			go e.flowAnalyzer.LearnOnline(flowKey, patternClass)
		}

		flowClass, flowConf := e.flowAnalyzer.GetFlowConfidence(flowKey)
		if flowClass >= 0 && flowConf > 0.6 && len(resp.Predictions) > 0 {
			pktConf := resp.Predictions[0].Confidence
			if flowClass != resp.Predictions[0].ClassID && flowConf > pktConf {
				resp.Predictions[0].ClassID = flowClass
				resp.Predictions[0].Confidence = 0.4*pktConf + 0.6*flowConf
			} else if flowClass == resp.Predictions[0].ClassID {
				resp.Predictions[0].Confidence = math.Min(1.0, pktConf+0.1*flowConf)
			}
			resp.ModelUsed = "gorgonia_mlp+lstm_go"
		}
	}
	return resp
}

func (e *NativeMLEngine) matchPattern(data []byte) int {
	for _, p := range e.protocolPatterns {
		if p.Magic != nil && len(data) > p.Offset+len(p.Magic) {
			if bytes.Equal(data[p.Offset:p.Offset+len(p.Magic)], p.Magic) {
				return p.ClassID
			}
		}
	}
	if isDNSPacket(data) {
		return 2
	}
	return -1
}

func (e *NativeMLEngine) RLAgent() *RLTransportAgent {
	return e.rlAgent
}

func (e *NativeMLEngine) GetFlowAnalyzer() *FlowAnalyzer {
	return e.flowAnalyzer
}

func (e *NativeMLEngine) GetTSPUDetector() *TSPUDetector {
	return e.tspuDetector
}

func (e *NativeMLEngine) addPseudoLabel(features []float64, classID, dpiType int) {
	q := sampleQuality(features)
	if q <= 0 {
		return
	}
	sample := TrainingSample{Features: features, ClassID: classID, DPIType: dpiType, IsLabeled: false, Quality: q}
	e.mu.Lock()
	e.replayBuf.add(sample)
	e.mu.Unlock()
	atomic.AddInt64(&e.pseudoLabelCount, 1)
	atomic.AddInt64(&e.samplesAfterTrain, 1)
}

func (e *NativeMLEngine) addGroundTruth(features []float64, classID, dpiType int) {
	q := sampleQuality(features)
	if q <= 0 {
		return
	}
	sample := TrainingSample{Features: features, ClassID: classID, DPIType: dpiType, IsLabeled: true, Quality: q}
	e.mu.Lock()
	e.labeledBuf.add(sample)
	e.replayBuf.add(sample)
	e.mu.Unlock()
	atomic.AddInt64(&e.samplesAfterTrain, 1)
}

func (e *NativeMLEngine) RecordBlockEvent(transport string, success bool) {
	hour := time.Now().Truncate(time.Hour).Unix()
	key := fmt.Sprintf("%s:%d", transport, hour)
	val, _ := e.blockHistory.LoadOrStore(key, &blockStats{})
	bs := val.(*blockStats)
	if success {
		atomic.AddInt64(&bs.success, 1)
	} else {
		atomic.AddInt64(&bs.fail, 1)
	}
	bs.lastSeen = time.Now()
}

func (e *NativeMLEngine) PredictBlockRisk(transport string) float64 {
	now := time.Now()
	var totalSuccess, totalFail int64
	for h := 0; h < 24; h++ {
		bucket := now.Add(-time.Duration(h) * time.Hour).Truncate(time.Hour).Unix()
		key := fmt.Sprintf("%s:%d", transport, bucket)
		if val, ok := e.blockHistory.Load(key); ok {
			bs := val.(*blockStats)
			weight := int64(24 - h)
			totalSuccess += atomic.LoadInt64(&bs.success) * weight
			totalFail += atomic.LoadInt64(&bs.fail) * weight
		}
	}
	total := totalSuccess + totalFail
	if total == 0 {
		return 0
	}
	return float64(totalFail) / float64(total)
}

func (e *NativeMLEngine) DetectDPI(data []byte, protocol, direction string) *types.MLPredictionResponse {
	features := e.ExtractFeatures(data)
	normF := e.normalize(features)

	e.mu.RLock()
	raw := e.dpiNet.Forward(normF)
	e.mu.RUnlock()

	probs := softmaxF64(raw)
	dpiType := argmax(probs)
	confidence := probs[dpiType]

	return &types.MLPredictionResponse{
		Predictions: []types.PredictionResult{{
			ClassID: dpiType, Confidence: confidence, Protocol: protocol,
			Direction: direction, DPIType: dpiType, DPIName: DPITypeName(dpiType),
		}},
		ModelUsed: "gorgonia_mlp_go_dpi", Confidence: confidence, Timestamp: time.Now(),
	}
}

func (e *NativeMLEngine) DetectAnomaly(data []byte, protocol, direction string) *types.MLPredictionResponse {
	features := e.ExtractFeatures(data)
	normF := e.normalize(features)

	e.mu.RLock()
	raw := e.anomalyNet.Forward(normF)
	e.mu.RUnlock()

	anomalyScore := sigmoidF64(raw[0])
	isAnomaly := anomalyScore > 0.7

	return &types.MLPredictionResponse{
		Predictions: []types.PredictionResult{{
			Confidence: 1.0 - anomalyScore, Protocol: protocol, Direction: direction,
			IsAnomaly: isAnomaly, AnomalyScore: anomalyScore,
		}},
		ModelUsed: "gorgonia_mlp_go_anomaly", Confidence: 1.0 - anomalyScore, Timestamp: time.Now(),
	}
}

func (e *NativeMLEngine) RecommendTransport(rttData []float64, successRates map[string]float64, latencies map[string]float64) string {
	transportNames := []string{
		"tcp", "websocket", "xhttp", "quic", "h2c",
		"obfs4", "meek", "snowflake", "shadowtls", "tuic",
		"httpupgrade", "splithttp", "shadowsocks", "torsocks", "domainfront",
		"vkvideo", "yatelemost", "okwebrtc", "yacloud", "yadisk",
		"vkwebrtc", "vkbot", "tgbot", "cdnworker", "mtproto",
		"mirage", "shadowsocks+meek", "shadowsocks+obfs4",
	}
	features := make([]float64, TransportFeatures)

	idx := 0
	for i := 0; i < 4 && i < len(rttData); i++ {
		features[idx] = rttData[i]
		idx++
	}
	for idx < 4 {
		features[idx] = 999
		idx++
	}

	reachable := 0
	for _, r := range rttData {
		if r < 900 {
			reachable++
		}
	}
	features[4] = float64(reachable) / float64(len(rttData)+1)

	for i, name := range transportNames {
		if i+5 >= TransportFeatures {
			break
		}
		features[5+i] = successRates[name]
	}
	for i, name := range transportNames {
		if 17+i >= TransportFeatures {
			break
		}
		features[17+i] = latencies[name] / 1000.0
	}

	e.mu.RLock()
	raw := e.transportNet.Forward(features)
	e.mu.RUnlock()

	probs := softmaxF64(raw)
	best := argmax(probs)
	if best < len(transportNames) {
		return transportNames[best]
	}
	return "tls"
}

func (e *NativeMLEngine) RecordFeedback(transport string, success bool, latencyMS int64) {
	val, _ := e.transportStats.LoadOrStore(transport, &TransportStats{})
	st := val.(*TransportStats)
	if success {
		atomic.AddInt64(&st.Success, 1)
	} else {
		atomic.AddInt64(&st.Fail, 1)
	}
	atomic.AddInt64(&st.TotalMS, latencyMS)
	st.LastUpdate = time.Now()
}

func (e *NativeMLEngine) GetTransportStats() map[string]interface{} {
	result := make(map[string]interface{})
	e.transportStats.Range(func(key, value interface{}) bool {
		name := key.(string)
		st := value.(*TransportStats)
		s := atomic.LoadInt64(&st.Success)
		f := atomic.LoadInt64(&st.Fail)
		total := s + f
		rate := 0.0
		avgMS := 0.0
		if total > 0 {
			rate = float64(s) / float64(total)
			avgMS = float64(atomic.LoadInt64(&st.TotalMS)) / float64(total)
		}
		result[name] = map[string]interface{}{
			"success": s, "fail": f, "rate": rate, "avg_latency_ms": avgMS,
		}
		return true
	})
	return result
}

func (e *NativeMLEngine) SetConnectionActive(active bool) {
	if active {
		atomic.StoreInt32(&e.activeConn, 1)
	} else {
		atomic.StoreInt32(&e.activeConn, 0)
	}
}

func (e *NativeMLEngine) Train(epochs int) (int, float64) {
	if !atomic.CompareAndSwapInt32(&e.trainingActive, 0, 1) {
		return 0, 0
	}
	defer atomic.StoreInt32(&e.trainingActive, 0)

	e.stopTraining = make(chan struct{})

	e.mu.Lock()
	filtered := e.replayBuf.getQualityFiltered(0.05)
	var samples []TrainingSample
	if len(filtered) >= BatchSize*4 {
		samples = filtered
	} else {
		samples = e.replayBuf.getAll()
	}
	e.mu.Unlock()

	if len(samples) < BatchSize {
		return 0, 0
	}

	if epochs <= 0 {
		epochs = 50
	}

	atomic.StoreInt32(&e.trainTotalEpoch, int32(epochs))

	trafficNet := gnet.Clone(e.trafficNet)
	dpiNet := gnet.Clone(e.dpiNet)
	anomalyNet := gnet.Clone(e.anomalyNet)

	trafficTrainer := newTrainer(trafficNet, TrafficClasses, false)
	dpiTrainer := newTrainer(dpiNet, DPIClasses, false)
	anomalyTrainer := newTrainer(anomalyNet, 1, true)

	var totalLoss float64

	xData := make([]float64, BatchSize*InputSize)
	yTraffic := make([]float64, BatchSize*TrafficClasses)
	yDPI := make([]float64, BatchSize*DPIClasses)
	yAnomaly := make([]float64, BatchSize)

	for epoch := 0; epoch < epochs; epoch++ {
		select {
		case <-e.stopTraining:
			goto done
		default:
		}

		atomic.StoreInt32(&e.trainEpoch, int32(epoch+1))
		shuffleSamples(samples)

		epochLoss := 0.0
		batchCount := 0

		for bStart := 0; bStart+BatchSize <= len(samples); bStart += BatchSize {
			batch := samples[bStart : bStart+BatchSize]

			for i := range xData {
				xData[i] = 0
			}
			for i := range yTraffic {
				yTraffic[i] = 0
			}
			for i := range yDPI {
				yDPI[i] = 0
			}
			for i := range yAnomaly {
				yAnomaly[i] = 0
			}

			for i, s := range batch {
				normF := e.normalizeSnapshot(s.Features)
				copy(xData[i*InputSize:], normF)

				if s.ClassID >= 0 && s.ClassID < TrafficClasses {
					yTraffic[i*TrafficClasses+s.ClassID] = 1.0
				}
				if s.DPIType >= 0 && s.DPIType < DPIClasses {
					yDPI[i*DPIClasses+s.DPIType] = 1.0
				}
				if len(s.Features) > 3 && (s.Features[3] > 0.5 || s.Features[4] < 2.0) {
					yAnomaly[i] = 1.0
				}
			}

			l1, err1 := trafficTrainer.step(xData, yTraffic)
			if err1 == nil {
				epochLoss += l1
			}
			_, _ = dpiTrainer.step(xData, yDPI)
			_, _ = anomalyTrainer.step(xData, yAnomaly)
			batchCount++
			runtime.Gosched()
		}

		if batchCount > 0 {
			totalLoss = epochLoss / float64(batchCount)
		}
		e.mu.Lock()
		e.trainLoss = totalLoss
		e.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}

done:
	correct := 0
	for _, s := range samples {
		normF := e.normalizeSnapshot(s.Features)
		raw := trafficNet.Forward(normF)
		probs := softmaxF64(raw)
		if argmax(probs) == s.ClassID {
			correct++
		}
	}
	trainAcc := float64(correct) / float64(len(samples))

	e.mu.Lock()
	valSamples := e.labeledBuf.getAll()
	e.mu.Unlock()

	var valAcc float64
	if len(valSamples) >= 10 {
		valCorrect := 0
		for _, s := range valSamples {
			normF := e.normalizeSnapshot(s.Features)
			raw := trafficNet.Forward(normF)
			probs := softmaxF64(raw)
			if argmax(probs) == s.ClassID {
				valCorrect++
			}
		}
		valAcc = float64(valCorrect) / float64(len(valSamples))
	} else {
		valAcc = trainAcc
	}

	prevAcc := e.accuracy
	if prevAcc > MinAccForDeploy && valAcc < prevAcc-AccDegradationWarn {
		return len(samples), valAcc
	}

	e.mu.Lock()
	e.trafficNet = trafficNet
	e.dpiNet = dpiNet
	e.anomalyNet = anomalyNet
	e.accuracy = trainAcc
	e.valAccuracy = valAcc
	e.prevAccuracy = prevAcc
	e.lastTrained = time.Now()
	e.trainLoss = totalLoss
	e.mu.Unlock()

	e.saveModel()
	return len(samples), valAcc
}

func (e *NativeMLEngine) StopTraining() {
	select {
	case <-e.stopTraining:
	default:
		close(e.stopTraining)
	}
}

func (e *NativeMLEngine) IsTraining() bool {
	return atomic.LoadInt32(&e.trainingActive) == 1
}

func (e *NativeMLEngine) TrainingStatus() (bool, int, int, float64) {
	e.mu.RLock()
	loss := e.trainLoss
	e.mu.RUnlock()
	return e.IsTraining(),
		int(atomic.LoadInt32(&e.trainEpoch)),
		int(atomic.LoadInt32(&e.trainTotalEpoch)),
		loss
}

func (e *NativeMLEngine) normalizeSnapshot(features []float64) []float64 {
	e.mu.RLock()
	norm := e.featureNorm
	e.mu.RUnlock()

	out := make([]float64, len(features))
	for i := range features {
		if i < len(norm.Mean) && i < len(norm.Std) && norm.Std[i] > 1e-8 {
			out[i] = (features[i] - norm.Mean[i]) / norm.Std[i]
		} else {
			out[i] = features[i]
		}
	}
	return out
}

func (e *NativeMLEngine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]interface{}{
		"predictions":      atomic.LoadInt64(&e.predictionCount),
		"samples":          atomic.LoadInt64(&e.sampleCount),
		"pseudo_labels":    atomic.LoadInt64(&e.pseudoLabelCount),
		"retrains":         atomic.LoadInt64(&e.retrainCount),
		"accuracy":         e.accuracy,
		"last_trained":     e.lastTrained.Unix(),
		"model":            "gorgonia_mlp_go",
		"replay_buffer":    e.replayBuf.size(),
		"train_samples":    e.replayBuf.size(),
		"traffic_layers":   netLayerSizes(e.trafficNet),
		"dpi_layers":       netLayerSizes(e.dpiNet),
		"anomaly_layers":   netLayerSizes(e.anomalyNet),
		"transport_layers": netLayerSizes(e.transportNet),
		"parameters":       netParams(e.trafficNet) + netParams(e.dpiNet) + netParams(e.anomalyNet) + netParams(e.transportNet),
	}
}

func dpiTypeToProfile(dpiType int) string {
	switch dpiType {
	case 1:
		return "vk"
	case 2:
		return "max"
	case 3:
		return "facebook"
	case 4:
		return "instagram"
	case 5:
		return "vk"
	case 6:
		return "telegram"
	default:
		return ""
	}
}

func (e *NativeMLEngine) SetOnDPIProfile(fn func(profile string)) {
	e.onDPIProfile.Store(fn)
}

const (
	TSPUReactConfidence  = 0.6
	TSPUReactStreak      = 3
	TSPUReactRequiredMin = DPITypeTSPURST
)

func (e *NativeMLEngine) SetOnTSPUDetected(fn func(dpiType int, confidence float64)) {
	e.onTSPUDetected.Store(fn)
}

func (e *NativeMLEngine) maybeFireTSPUDetected(dpiType int, conf float64) {
	if dpiType < TSPUReactRequiredMin || conf < TSPUReactConfidence {
		atomic.StoreInt32(&e.tspuHitStreak, 0)
		return
	}
	last := atomic.LoadInt32(&e.lastTSPUType)
	if int32(dpiType) == last {
		streak := atomic.AddInt32(&e.tspuHitStreak, 1)
		if streak < TSPUReactStreak {
			return
		}
		atomic.StoreInt32(&e.tspuHitStreak, 0)
	} else {
		atomic.StoreInt32(&e.lastTSPUType, int32(dpiType))
		atomic.StoreInt32(&e.tspuHitStreak, 1)
		return
	}
	if fn, ok := e.onTSPUDetected.Load().(func(int, float64)); ok && fn != nil {
		fn(dpiType, conf)
	}
}

func (e *NativeMLEngine) maybeFireProfileChange(dpiType int, conf float64) {
	if dpiType <= 0 || conf < 0.82 {
		atomic.StoreInt32(&e.profileHitStreak, 0)
		return
	}
	last := atomic.LoadInt32(&e.lastProfileDPI)
	if int32(dpiType) == last {
		streak := atomic.AddInt32(&e.profileHitStreak, 1)
		if streak < 5 {
			return
		}
		atomic.StoreInt32(&e.profileHitStreak, 0)
	} else {
		atomic.StoreInt32(&e.lastProfileDPI, int32(dpiType))
		atomic.StoreInt32(&e.profileHitStreak, 1)
		return
	}
	profile := dpiTypeToProfile(dpiType)
	if profile == "" {
		return
	}
	if fn, ok := e.onDPIProfile.Load().(func(string)); ok && fn != nil {
		fn(profile)
	}
}

// ExportModelState returns a serializable copy of current NN weights.
// Safe to call concurrently with inference.
func (e *NativeMLEngine) ExportModelState() *ModelState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return &ModelState{
		TrafficLayers:   copyLayerDefs(e.trafficNet.Layers),
		DPILayers:       copyLayerDefs(e.dpiNet.Layers),
		AnomalyLayers:   copyLayerDefs(e.anomalyNet.Layers),
		TransportLayers: copyLayerDefs(e.transportNet.Layers),
		Normalizer:      copyNorm(e.featureNorm),
		Accuracy:        e.accuracy,
		Trained:         e.lastTrained.Unix(),
	}
}

// ImportModelState applies FedAvg between local and remote NN weights.
// alpha=0.5 gives equal weight to both sides; increase toward 1.0 to trust
// local weights more (useful when local has seen much more data).
func (e *NativeMLEngine) ImportModelState(remote *ModelState, alpha float64) {
	if remote == nil || alpha <= 0 || alpha >= 1 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	fedAvgLayers(e.trafficNet.Layers, remote.TrafficLayers, alpha)
	fedAvgLayers(e.dpiNet.Layers, remote.DPILayers, alpha)
	fedAvgLayers(e.anomalyNet.Layers, remote.AnomalyLayers, alpha)
	fedAvgLayers(e.transportNet.Layers, remote.TransportLayers, alpha)
	if remote.Accuracy > 0 {
		e.accuracy = alpha*e.accuracy + (1-alpha)*remote.Accuracy
	}
}

// SelfTest runs a synthetic forward pass and reports NN health.
// Returns ok=false if output contains NaN/Inf.
// is_uniform=true means the model is likely still untrained (max-entropy output).
func (e *NativeMLEngine) SelfTest() map[string]interface{} {
	input := make([]float64, InputSize)
	for i := range input {
		input[i] = 0.5
	}

	e.mu.RLock()
	rawOut := e.trafficNet.Forward(input)
	trainedAt := e.lastTrained.Unix()
	acc := e.accuracy
	e.mu.RUnlock()

	hasNaN, hasInf := false, false
	for _, v := range rawOut {
		if math.IsNaN(v) {
			hasNaN = true
		}
		if math.IsInf(v, 0) {
			hasInf = true
		}
	}

	softOut := softmaxF64(rawOut)
	entropy := 0.0
	for _, p := range softOut {
		if p > 1e-12 {
			entropy -= p * math.Log(p)
		}
	}
	maxEntropy := math.Log(float64(TrafficClasses))

	return map[string]interface{}{
		"ok":          !hasNaN && !hasInf,
		"has_nan":     hasNaN,
		"has_inf":     hasInf,
		"traffic_raw": rawOut,
		"traffic_p":   softOut,
		"entropy":     entropy,
		"max_entropy": maxEntropy,
		"is_uniform":  entropy > 0.95*maxEntropy,
		"accuracy":    acc,
		"samples":     atomic.LoadInt64(&e.sampleCount),
		"trained_at":  trainedAt,
	}
}

func copyLayerDefs(layers []LayerDef) []LayerDef {
	out := make([]LayerDef, len(layers))
	for i, l := range layers {
		out[i] = LayerDef{
			InSize:  l.InSize,
			OutSize: l.OutSize,
			W:       append([]float64(nil), l.W...),
			B:       append([]float64(nil), l.B...),
		}
	}
	return out
}

func copyNorm(n *FeatureNormalizer) *FeatureNormalizer {
	if n == nil {
		return nil
	}
	return &FeatureNormalizer{
		Mean:    append([]float64(nil), n.Mean...),
		Std:     append([]float64(nil), n.Std...),
		Samples: n.Samples,
	}
}

func fedAvgLayers(local, remote []LayerDef, alpha float64) {
	beta := 1 - alpha
	for i := range local {
		if i >= len(remote) {
			break
		}
		r := remote[i]
		for j := range local[i].W {
			if j < len(r.W) {
				local[i].W[j] = alpha*local[i].W[j] + beta*r.W[j]
			}
		}
		for j := range local[i].B {
			if j < len(r.B) {
				local[i].B[j] = alpha*local[i].B[j] + beta*r.B[j]
			}
		}
	}
}

func (e *NativeMLEngine) Close() {
	select {
	case <-e.stopSelfLearn:
	default:
		close(e.stopSelfLearn)
	}
	e.StopTraining()
	e.selfLearnWG.Wait()
	e.saveModel()
}

func (e *NativeMLEngine) saveModel() {
	if e.modelDir == "" {
		return
	}
	os.MkdirAll(e.modelDir, 0700)

	e.mu.RLock()
	state := ModelState{
		TrafficLayers:   e.trafficNet.Layers,
		DPILayers:       e.dpiNet.Layers,
		AnomalyLayers:   e.anomalyNet.Layers,
		TransportLayers: e.transportNet.Layers,
		Normalizer:      e.featureNorm,
		Accuracy:        e.accuracy,
		Trained:         e.lastTrained.Unix(),
	}
	e.mu.RUnlock()

	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	path := filepath.Join(e.modelDir, "gorgonia_mlp.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func (e *NativeMLEngine) loadModel() {
	if e.modelDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(e.modelDir, "gorgonia_mlp.json"))
	if err != nil {
		return
	}
	var state ModelState
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	e.mu.Lock()
	if validLayers(state.TrafficLayers, InputSize, TrafficClasses) {
		e.trafficNet = layersToNet(state.TrafficLayers)
	}
	if validLayers(state.DPILayers, InputSize, DPIClasses) {
		e.dpiNet = layersToNet(state.DPILayers)
	}
	if validLayers(state.AnomalyLayers, InputSize, 1) {
		e.anomalyNet = layersToNet(state.AnomalyLayers)
	}
	if validLayers(state.TransportLayers, TransportFeatures, TransportChoices) {
		e.transportNet = layersToNet(state.TransportLayers)
	}
	if state.Normalizer != nil && len(state.Normalizer.Mean) > 0 {
		e.featureNorm = state.Normalizer
	}
	e.accuracy = state.Accuracy
	e.lastTrained = time.Unix(state.Trained, 0)
	e.mu.Unlock()
}

func isDNSPacket(data []byte) bool {
	if len(data) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	opcode := (flags >> 11) & 0xf
	qdcount := binary.BigEndian.Uint16(data[4:6])
	return opcode <= 2 && qdcount >= 1 && qdcount <= 10
}

func softmaxF64(x []float64) []float64 {
	if len(x) == 0 {
		return x
	}
	maxVal := x[0]
	for _, v := range x[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	out := make([]float64, len(x))
	sum := 0.0
	for i, v := range x {
		out[i] = math.Exp(v - maxVal)
		sum += out[i]
	}
	if sum > 0 {
		for i := range out {
			out[i] /= sum
		}
	}
	return out
}

func sigmoidF64(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func argmax(x []float64) int {
	best := 0
	for i := 1; i < len(x); i++ {
		if x[i] > x[best] {
			best = i
		}
	}
	return best
}

func ones(n int) []float64 {
	v := make([]float64, n)
	for i := range v {
		v[i] = 1.0
	}
	return v
}

func shuffleSamples(s []TrainingSample) {
	var buf [8]byte
	for i := len(s) - 1; i > 0; i-- {
		rand.Read(buf[:4])
		j := int(binary.LittleEndian.Uint32(buf[:4])) % (i + 1)
		s[i], s[j] = s[j], s[i]
	}
}

func layersToNet(layers []LayerDef) *GorgoniaNet {
	net := &GorgoniaNet{}
	for _, l := range layers {
		net.Layers = append(net.Layers, LayerDef{
			InSize: l.InSize, OutSize: l.OutSize,
			W: gnet.CopyF64(l.W), B: gnet.CopyF64(l.B),
		})
	}
	return net
}

func netLayerSizes(net *GorgoniaNet) []int {
	if len(net.Layers) == 0 {
		return nil
	}
	sizes := []int{net.Layers[0].InSize}
	for _, l := range net.Layers {
		sizes = append(sizes, l.OutSize)
	}
	return sizes
}

func netParams(net *GorgoniaNet) int {
	total := 0
	for _, l := range net.Layers {
		total += l.InSize*l.OutSize + l.OutSize
	}
	return total
}

func (e *NativeMLEngine) GetCurrentDPILevel() (dpiType int, confidence float64) {
	e.mu.RLock()
	samples := e.replayBuf.getAll()
	e.mu.RUnlock()
	if len(samples) == 0 {
		return 0, 0
	}
	if len(samples) > 50 {
		samples = samples[len(samples)-50:]
	}
	counts := make([]int, DPIClasses)
	totalConf := 0.0
	for _, s := range samples {
		if s.DPIType >= 0 && s.DPIType < DPIClasses {
			counts[s.DPIType]++
		}
		totalConf += s.Quality
	}
	maxCount, dominantType := 0, 0
	for t, c := range counts {
		if c > maxCount {
			maxCount = c
			dominantType = t
		}
	}
	return dominantType, totalConf / float64(len(samples))
}
