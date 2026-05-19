//go:build !linux

package ml

// FlowLabel identifies whether a TCP flow is a VPN tunnel or a real browser.
type FlowLabel int

const (
	FlowUnknown FlowLabel = iota
	FlowTunnel
	FlowDecoy
)

// FlowFeatures is the feature vector fed to the GAN discriminator.
type FlowFeatures struct {
	IATMean, IATStd, IATP90    float64
	SizeMean, SizeStd, SizeP90 float64
	UpRatio, BurstSize         float64
	Duration, PacketCount      float64
}

func (f FlowFeatures) Vec() []float64 {
	return []float64{
		f.IATMean, f.IATStd, f.IATP90,
		f.SizeMean, f.SizeStd, f.SizeP90,
		f.UpRatio, f.BurstSize,
		f.Duration, f.PacketCount,
	}
}

const FlowFeatureSize = 10

// LabeledFlow is a completed flow with its feature vector and label.
type LabeledFlow struct {
	Features FlowFeatures
	Label    FlowLabel
}

// FlowRegistry is a no-op on non-Linux platforms.
var FlowRegistry = &flowRegistry{}

type flowRegistry struct{}

func (r *flowRegistry) Register(remoteAddr string, label FlowLabel) {}
func (r *flowRegistry) Get(key string) FlowLabel                    { return FlowUnknown }
func (r *flowRegistry) Delete(remoteAddr string)                    {}

// PCAPCollector is a no-op on non-Linux platforms.
type PCAPCollector struct{ out chan LabeledFlow }

func NewPCAPCollector(iface string, port int) *PCAPCollector {
	return &PCAPCollector{out: make(chan LabeledFlow)}
}
func (c *PCAPCollector) Start() error          { return nil }
func (c *PCAPCollector) Stop()                 {}
func (c *PCAPCollector) Out() <-chan LabeledFlow { return c.out }
