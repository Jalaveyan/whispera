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
		gan:      NewTrafficGAN(),
		collector: NewPCAPCollector(iface, port),
		stopCh:   make(chan struct{}),
		savePath: savePath,
	}
}

func (r *GANRunner) GAN() *TrafficGAN { return r.gan }

func (r *GANRunner) Start() error {
	if r.savePath != "" {
		if err := r.gan.Load(r.savePath); err == nil {
			log.Info("GAN: loaded saved state from %s (trained=%d)", r.savePath, r.gan.trainCount)
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
		} else {
			log.Info("GAN: state saved to %s", r.savePath)
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
		case <-logTicker.C:
			tc, dc, trained, pool, detect := r.gan.Diagnostics()
			if detect != "" {
				log.Warn("GAN: tunnel_conf=%.3f decoy_conf=%.3f trained=%d flows[tun=%d dec=%d unk=%d] pool=%d | DETECTED: %s",
					tc, dc, trained, tun, dec, unk, pool, detect)
			} else {
				log.Info("GAN: tunnel_conf=%.3f decoy_conf=%.3f trained=%d flows[tun=%d dec=%d unk=%d] pool=%d",
					tc, dc, trained, tun, dec, unk, pool)
			}
		case <-saveTicker.C:
			if r.savePath != "" {
				r.gan.Save(r.savePath)
			}
		}
	}
}
