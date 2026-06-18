//go:build !linux

package neural

import "context"

type GANRunner struct {
	gan       *TrafficGAN
	stopCh    chan struct{}
	simCancel context.CancelFunc
	savePath  string
}

func NewGANRunner(iface string, port int, savePath string) *GANRunner {
	return &GANRunner{
		gan:      NewTrafficGAN(),
		stopCh:   make(chan struct{}),
		savePath: savePath,
	}
}

func (r *GANRunner) GAN() *TrafficGAN        { return r.gan }
func (r *GANRunner) Out() <-chan LabeledFlow { return nil }
func (r *GANRunner) Start() error            { return nil }
func (r *GANRunner) Stop()                   {}
