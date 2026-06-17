package evasion

import (
	"encoding/binary"
	"sync"
	"time"
)

type CorrelationDefense struct {
	mu             sync.Mutex
	enabled        bool
	constantRate   int
	paddingEnabled bool
	delayJitter    time.Duration
	mixEnabled     bool

	sendBucket  *leakyBucket
	recvBucket  *leakyBucket
	delayBuffer chan delayedPacket
	stopCh      chan struct{}
}

type delayedPacket struct {
	data    []byte
	sendAt  time.Time
	handler func([]byte) error
}

type leakyBucket struct {
	mu       sync.Mutex
	rate     float64
	tokens   float64
	maxBurst float64
	lastTick time.Time
}

func newLeakyBucket(rate float64, burst float64) *leakyBucket {
	return &leakyBucket{
		rate:     rate,
		tokens:   burst,
		maxBurst: burst,
		lastTick: time.Now(),
	}
}

func NewCorrelationDefense(config *CorrelationConfig) *CorrelationDefense {
	if config == nil {
		config = DefaultCorrelationConfig()
	}

	cd := &CorrelationDefense{
		enabled:        config.Enabled,
		constantRate:   config.ConstantRatePPS,
		paddingEnabled: config.PaddingEnabled,
		delayJitter:    config.DelayJitter,
		mixEnabled:     config.MixEnabled,
		sendBucket:     newLeakyBucket(float64(config.ConstantRatePPS), 50),
		recvBucket:     newLeakyBucket(float64(config.ConstantRatePPS), 50),
		delayBuffer:    make(chan delayedPacket, 1024),
		stopCh:         make(chan struct{}),
	}

	if config.Enabled {
		go cd.delayDispatcher()
	}

	return cd
}

type CorrelationConfig struct {
	Enabled         bool          `yaml:"enabled"`
	ConstantRatePPS int           `yaml:"constant_rate_pps"`
	PaddingEnabled  bool          `yaml:"padding_enabled"`
	DelayJitter     time.Duration `yaml:"delay_jitter"`
	MixEnabled      bool          `yaml:"mix_enabled"`
}

func DefaultCorrelationConfig() *CorrelationConfig {
	return &CorrelationConfig{
		Enabled:         true,
		ConstantRatePPS: 10000,
		PaddingEnabled:  true,
		DelayJitter:     5 * time.Millisecond,
		MixEnabled:      true,
	}
}

func (cd *CorrelationDefense) ProcessInbound(data []byte) []byte {
	if !cd.enabled {
		return data
	}
	return cd.unpadFromConstantSize(data)
}

func (cd *CorrelationDefense) unpadFromConstantSize(data []byte) []byte {
	if !cd.paddingEnabled || len(data) < 4 {
		return data
	}

	realLen := binary.BigEndian.Uint32(data[:4])
	if int(realLen) > len(data)-4 || realLen > 65535 {
		return data
	}

	return data[4 : 4+realLen]
}

func (cd *CorrelationDefense) delayDispatcher() {
	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()

	var pending []delayedPacket

	for {
		select {
		case <-cd.stopCh:
			for _, p := range pending {
				p.handler(p.data)
			}
			return
		case pkt := <-cd.delayBuffer:
			pending = append(pending, pkt)
		case <-ticker.C:
			now := time.Now()
			remaining := pending[:0]
			for _, p := range pending {
				if now.After(p.sendAt) {
					p.handler(p.data)
				} else {
					remaining = append(remaining, p)
				}
			}
			pending = remaining
		}
	}
}

func (cd *CorrelationDefense) Stop() {
	close(cd.stopCh)
}
