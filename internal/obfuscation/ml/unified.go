package ml

import (
	"sync"

	"whispera/internal/obfuscation/ml/gnet"
)

const (
	usRTTMs = iota
	usUpBps
	usDnBps
	usSuccessRate
	usFailRate
	usLoss
	usDPIDetected
	usBlockRisk
	usPoolSize
	usLatencyMs
	usThreatLevel
	usEpsilon
	UnifiedStateSize
)

type UnifiedState struct {
	RTTMs       float64
	UpBps       float64
	DnBps       float64
	SuccessRate float64
	FailRate    float64
	Loss        float64
	DPIDetected float64
	BlockRisk   float64
	PoolSize    float64
	LatencyMs   float64
	ThreatLevel float64
	Epsilon     float64
}

func (s UnifiedState) Vec() []float64 {
	v := make([]float64, UnifiedStateSize)
	v[usRTTMs] = s.RTTMs
	v[usUpBps] = s.UpBps
	v[usDnBps] = s.DnBps
	v[usSuccessRate] = s.SuccessRate
	v[usFailRate] = s.FailRate
	v[usLoss] = s.Loss
	v[usDPIDetected] = s.DPIDetected
	v[usBlockRisk] = s.BlockRisk
	v[usPoolSize] = s.PoolSize
	v[usLatencyMs] = s.LatencyMs
	v[usThreatLevel] = s.ThreatLevel
	v[usEpsilon] = s.Epsilon
	return v
}

type UnifiedNet struct {
	mu        sync.Mutex
	trunk     *gnet.GorgoniaNet
	trunkAdam *AdamState
	heads     map[string]*gnet.GorgoniaNet
	headAdam  map[string]*AdamState
}

func NewUnifiedNet(stateSize, hidden, emb int, heads map[string]int) *UnifiedNet {
	trunk := gnet.New([]int{stateSize, hidden, emb})
	u := &UnifiedNet{
		trunk:     trunk,
		trunkAdam: NewAdamState(trunk),
		heads:     make(map[string]*gnet.GorgoniaNet, len(heads)),
		headAdam:  make(map[string]*AdamState, len(heads)),
	}
	for name, nActions := range heads {
		h := gnet.New([]int{emb, nActions})
		u.heads[name] = h
		u.headAdam[name] = NewAdamState(h)
	}
	return u
}

func (u *UnifiedNet) QValues(state []float64, head string) []float64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	h := u.heads[head]
	if h == nil {
		return nil
	}
	emb := u.trunk.Forward(state)
	return h.Forward(emb)
}

func (u *UnifiedNet) Train(state []float64, head string, action int, target, lr float64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	h := u.heads[head]
	hAdam := u.headAdam[head]
	if h == nil {
		return
	}
	trunkActs := u.trunk.ForwardActivations(state)
	emb := trunkActs[len(trunkActs)-1]
	headActs := h.ForwardActivations(emb)
	q := headActs[len(headActs)-1]
	if action < 0 || action >= len(q) {
		return
	}
	dOut := make([]float64, len(q))
	dOut[action] = q[action] - target
	gradEmb := dqnBackpropAdam(h, hAdam, headActs, dOut, lr)
	dqnBackpropAdam(u.trunk, u.trunkAdam, trunkActs, gradEmb, lr)
}
