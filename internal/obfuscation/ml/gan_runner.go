package ml

import (
	"context"
	"time"
)

type GANRunner struct {
	gan       *TrafficGAN
	collector *PCAPCollector
	stopCh    chan struct{}
	simCancel context.CancelFunc
	savePath  string
}

func NewGANRunner(iface string, port int, savePath string) *GANRunner {
	return &GANRunner{
		gan:       NewTrafficGAN(),
		collector: NewPCAPCollector(iface, port),
		stopCh:    make(chan struct{}),
		savePath:  savePath,
	}
}

func (r *GANRunner) GAN() *TrafficGAN { return r.gan }

func (r *GANRunner) Start() error {
	if r.savePath != "" {
		if err := r.gan.Load(r.savePath); err == nil {
		}
	}
	if err := r.collector.Start(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.simCancel = cancel
	go r.loop()
	go RunBrowserSim(ctx)
	return nil
}

func (r *GANRunner) Stop() {
	close(r.stopCh)
	if r.savePath != "" {
		if err := r.gan.Save(r.savePath); err != nil {
			log.Error("GAN: save state failed: %v", err)
		}
	}
	if r.simCancel != nil {
		r.simCancel()
	}
}

func (r *GANRunner) loop() {
	logTicker := time.NewTicker(60 * time.Second)
	defer logTicker.Stop()
	saveTicker := time.NewTicker(5 * time.Minute)
	defer saveTicker.Stop()
	var tun, dec, unk int
	for {
		select {
		case <-r.stopCh:
			return
		case lf := <-r.collector.Out():
			switch lf.Label {
			case FlowTunnel:
				tun++
			case FlowDecoy:
				dec++
			default:
				unk++
			}
			r.gan.Train(lf)
		case <-saveTicker.C:
			if r.savePath != "" {
				if err := r.gan.Save(r.savePath); err != nil {
					log.Error("GAN: save state failed: %v", err)
				}
			}
		}
	}
}
