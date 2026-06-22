package tunnel

import (
	"context"
	"net"
	"time"
	"whispera/neural"
	"whispera/neural/gnet"
)

type killSwitchController interface {
	SetVPNServer(ip net.IP, port int)
	Enable() error
	Disable() error
}

type tcpBypassDialer interface {
	DialTCP(ctx context.Context, network, addr string) (net.Conn, error)
}

type weightExportable interface {
	ExportWeights() []gnet.LayerDef
	ImportWeights(layers []gnet.LayerDef)
}

type keepaliveDecisionAgent interface {
	weightExportable
	Decide(v neural.KeepaliveView) time.Duration
	RecordOutcome(quality float64)
}

type backoffDecisionAgent interface {
	weightExportable
	Decide(v neural.BackoffView) time.Duration
	RecordOutcome(success bool)
}

type jitterDecisionAgent interface {
	weightExportable
	Decide(v neural.JitterView) float64
	RecordOutcome(quality float64)
}

type serverDecisionAgent interface {
	weightExportable
	Decide(probes []neural.ServerProbe) string
	RecordOutcome(success bool, latencyMs float64)
}

type chunkDecisionAgent interface {
	weightExportable
	Decide(v neural.ChunkView) int
}

type tspuDetectorIface interface {
	RecordRST(sni string, timeToRST time.Duration)
	DetectTSPU() (dpiType int, confidence float64)
}
