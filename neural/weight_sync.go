package neural

import (
	"sync/atomic"
	"whispera/neural/gnet"
)

type WeightSnapshot struct {
	Version   int64           `json:"v"`
	Transport []gnet.LayerDef `json:"transport,omitempty"`
	SNI       []gnet.LayerDef `json:"sni,omitempty"`
	Keepalive []gnet.LayerDef `json:"keepalive,omitempty"`
	Jitter    []gnet.LayerDef `json:"jitter,omitempty"`
	Chunk     []gnet.LayerDef `json:"chunk,omitempty"`
	Conn      []gnet.LayerDef `json:"conn,omitempty"`
	Backoff   []gnet.LayerDef `json:"backoff,omitempty"`
	Server    []gnet.LayerDef `json:"server,omitempty"`
	TLS       []gnet.LayerDef `json:"tls,omitempty"`
}

var (
	globalSnapshot atomic.Pointer[WeightSnapshot]
	globalVersion  atomic.Int64
)

func SetGlobalSnapshot(snap *WeightSnapshot) {
	snap.Version = globalVersion.Add(1)
	globalSnapshot.Store(snap)
}

func GetGlobalSnapshot() *WeightSnapshot {
	return globalSnapshot.Load()
}

func copyLayers(net *gnet.GorgoniaNet) []gnet.LayerDef {
	if net == nil {
		return nil
	}
	out := make([]gnet.LayerDef, len(net.Layers))
	for i, ld := range net.Layers {
		out[i] = gnet.LayerDef{
			InSize:  ld.InSize,
			OutSize: ld.OutSize,
			W:       gnet.CopyF64(ld.W),
			B:       gnet.CopyF64(ld.B),
		}
	}
	return out
}

func (a *RLTransportAgent) ExportWeights() []gnet.LayerDef {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return copyLayers(a.qNet)
}

func (a *RLTransportAgent) ImportWeights(layers []gnet.LayerDef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.qNet.LoadWeights(layers)
	a.target = gnet.Clone(a.qNet)
}

func (a *RLKeepaliveAgent) ExportWeights() []gnet.LayerDef {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return copyLayers(a.qNet)
}

func (a *RLKeepaliveAgent) ImportWeights(layers []gnet.LayerDef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.qNet.LoadWeights(layers)
	a.target = gnet.Clone(a.qNet)
}

func (a *RLJitterAgent) ExportWeights() []gnet.LayerDef {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return copyLayers(a.qNet)
}

func (a *RLJitterAgent) ImportWeights(layers []gnet.LayerDef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.qNet.LoadWeights(layers)
	a.target = gnet.Clone(a.qNet)
}

func (a *RLChunkAgent) ExportWeights() []gnet.LayerDef {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return copyLayers(a.qNet)
}

func (a *RLChunkAgent) ImportWeights(layers []gnet.LayerDef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.qNet.LoadWeights(layers)
	a.target = gnet.Clone(a.qNet)
}

func (a *RLConnAgent) ExportWeights() []gnet.LayerDef {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return copyLayers(a.qNet)
}

func (a *RLConnAgent) ImportWeights(layers []gnet.LayerDef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.qNet.LoadWeights(layers)
	a.target = gnet.Clone(a.qNet)
}

func (a *RLBackoffAgent) ExportWeights() []gnet.LayerDef {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return copyLayers(a.qNet)
}

func (a *RLBackoffAgent) ImportWeights(layers []gnet.LayerDef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.qNet.LoadWeights(layers)
	a.target = gnet.Clone(a.qNet)
}

func (a *RLServerAgent) ExportWeights() []gnet.LayerDef {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return copyLayers(a.qNet)
}

func (a *RLServerAgent) ImportWeights(layers []gnet.LayerDef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.qNet.LoadWeights(layers)
	a.target = gnet.Clone(a.qNet)
}
