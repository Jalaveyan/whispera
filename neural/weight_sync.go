package neural

import (
	"sync/atomic"
	"whispera/neural/gnet"
)

type WeightSnapshot struct {
	Version   int64           `json:"v"`
	SNI       []gnet.LayerDef `json:"sni,omitempty"`
	Keepalive []gnet.LayerDef `json:"keepalive,omitempty"`
	Jitter    []gnet.LayerDef `json:"jitter,omitempty"`
	Chunk     []gnet.LayerDef `json:"chunk,omitempty"`
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

func (a *RLKeepaliveAgent) ExportWeights() []gnet.LayerDef       { return a.core.ExportWeights() }
func (a *RLKeepaliveAgent) ImportWeights(layers []gnet.LayerDef) { a.core.ImportWeights(layers) }

func (a *RLJitterAgent) ExportWeights() []gnet.LayerDef       { return a.core.ExportWeights() }
func (a *RLJitterAgent) ImportWeights(layers []gnet.LayerDef) { a.core.ImportWeights(layers) }

func (a *RLChunkAgent) ExportWeights() []gnet.LayerDef       { return a.core.ExportWeights() }
func (a *RLChunkAgent) ImportWeights(layers []gnet.LayerDef) { a.core.ImportWeights(layers) }

func (a *RLBackoffAgent) ExportWeights() []gnet.LayerDef       { return a.core.ExportWeights() }
func (a *RLBackoffAgent) ImportWeights(layers []gnet.LayerDef) { a.core.ImportWeights(layers) }

func (a *RLServerAgent) ExportWeights() []gnet.LayerDef       { return a.core.ExportWeights() }
func (a *RLServerAgent) ImportWeights(layers []gnet.LayerDef) { a.core.ImportWeights(layers) }
