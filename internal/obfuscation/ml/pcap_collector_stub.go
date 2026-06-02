//go:build !linux

package ml

type PCAPCollector struct{ out chan LabeledFlow }

func NewPCAPCollector(iface string, port int) *PCAPCollector {
	return &PCAPCollector{out: make(chan LabeledFlow)}
}
func (c *PCAPCollector) Start() error            { return nil }
func (c *PCAPCollector) Stop()                   {}
func (c *PCAPCollector) Out() <-chan LabeledFlow { return c.out }
