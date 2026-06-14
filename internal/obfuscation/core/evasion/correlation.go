package evasion

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
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
	sessionSeed    [16]byte

	sendBucket  *leakyBucket
	recvBucket  *leakyBucket
	delayBuffer chan delayedPacket
	stopCh      chan struct{}
}

func (cd *CorrelationDefense) sessionBucketSizes() []int {
	if cd.sessionSeed == [16]byte{} {
		crand.Read(cd.sessionSeed[:])
	}
	base := []int{128, 256, 512, 1024, 1500}
	sizes := make([]int, len(base))
	for i, b := range base {
		jitter := int(cd.sessionSeed[i%16]) % 64
		if i%2 == 0 {
			sizes[i] = b + jitter
		} else {
			sizes[i] = b - jitter/2 + jitter
		}
		if sizes[i] < 64 {
			sizes[i] = 64
		}
	}
	return sizes
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

func (lb *leakyBucket) take() time.Duration {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(lb.lastTick).Seconds()
	lb.lastTick = now
	lb.tokens += elapsed * lb.rate
	if lb.tokens > lb.maxBurst {
		lb.tokens = lb.maxBurst
	}

	if lb.tokens >= 1 {
		lb.tokens--
		return 0
	}

	wait := time.Duration((1 - lb.tokens) / lb.rate * float64(time.Second))
	lb.tokens = 0
	return wait
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

func (cd *CorrelationDefense) ProcessOutbound(data []byte, send func([]byte) error) error {
	if !cd.enabled {
		return send(data)
	}

	shaped := cd.padToConstantSize(data)

	if cd.delayJitter > 0 {
		jitter := cd.randomDelay()
		select {
		case cd.delayBuffer <- delayedPacket{
			data:    shaped,
			sendAt:  time.Now().Add(jitter),
			handler: send,
		}:
			return nil
		case <-cd.stopCh:
			return send(shaped)
		}
	}

	wait := cd.sendBucket.take()
	if wait > 0 {
		time.Sleep(wait)
	}

	return send(shaped)
}

func (cd *CorrelationDefense) ProcessInbound(data []byte) []byte {
	if !cd.enabled {
		return data
	}
	return cd.unpadFromConstantSize(data)
}

func (cd *CorrelationDefense) padToConstantSize(data []byte) []byte {
	if !cd.paddingEnabled {
		return data
	}

	sizes := cd.sessionBucketSizes()
	target := sizes[len(sizes)-1]
	for _, s := range sizes {
		if len(data)+4 <= s {
			target = s
			break
		}
	}

	result := make([]byte, target)
	binary.BigEndian.PutUint32(result[:4], uint32(len(data)))
	copy(result[4:], data)

	padStart := 4 + len(data)
	if padStart < target {
		noise := make([]byte, target-padStart)
		crand.Read(noise)
		copy(result[padStart:], noise)
	}

	return result
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

func (cd *CorrelationDefense) randomDelay() time.Duration {
	b := make([]byte, 8)
	crand.Read(b)
	val := binary.BigEndian.Uint64(b)
	frac := float64(val) / float64(^uint64(0))

	lambda := 1.0 / cd.delayJitter.Seconds()
	delay := -math.Log(1-frac) / lambda
	maxDelay := cd.delayJitter.Seconds() * 3
	if delay > maxDelay {
		delay = maxDelay
	}

	return time.Duration(delay * float64(time.Second))
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

func (cd *CorrelationDefense) GenerateCoverTraffic(send func([]byte) error) {
	if !cd.enabled {
		return
	}

	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(cd.constantRate/10+1))
		defer ticker.Stop()

		for {
			select {
			case <-cd.stopCh:
				return
			case <-ticker.C:
				cover := make([]byte, 128)
				cover[0] = 0xFF
				crand.Read(cover[1:])
				send(cover)
			}
		}
	}()
}

func (cd *CorrelationDefense) Stop() {
	close(cd.stopCh)
}
