package evasion

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultCorrelationConfig(t *testing.T) {
	cfg := DefaultCorrelationConfig()
	if !cfg.Enabled {
		t.Error("expected enabled by default")
	}
	if cfg.ConstantRatePPS != 10000 {
		t.Errorf("expected 10000 pps, got %d", cfg.ConstantRatePPS)
	}
	if cfg.DelayJitter != 5*time.Millisecond {
		t.Errorf("expected 5ms jitter, got %v", cfg.DelayJitter)
	}
}

func TestPaddingRoundTrip(t *testing.T) {
	cd := NewCorrelationDefense(&CorrelationConfig{
		Enabled:         true,
		PaddingEnabled:  true,
		DelayJitter:     0,
		ConstantRatePPS: 1000,
	})
	defer cd.Stop()

	original := []byte("hello world test data for padding")
	padded := cd.padToConstantSize(original)

	if len(padded) < len(original)+4 {
		t.Errorf("padded too small: %d", len(padded))
	}

	recovered := cd.unpadFromConstantSize(padded)
	if string(recovered) != string(original) {
		t.Errorf("round trip failed: got %q", string(recovered))
	}
}

func TestPaddingBucketSizes(t *testing.T) {
	cd := NewCorrelationDefense(&CorrelationConfig{
		Enabled:         true,
		PaddingEnabled:  true,
		DelayJitter:     0,
		ConstantRatePPS: 1000,
	})
	defer cd.Stop()

	sizes := cd.sessionBucketSizes()
	if len(sizes) != 5 {
		t.Fatalf("expected 5 bucket sizes, got %d", len(sizes))
	}
	for i, s := range sizes {
		if s < 64 {
			t.Errorf("bucket %d too small: %d", i, s)
		}
	}

	for _, dataLen := range []int{10, 100, 200, 400, 600, 1200} {
		data := make([]byte, dataLen)
		padded := cd.padToConstantSize(data)
		if len(padded) < dataLen+4 {
			t.Errorf("data %d bytes: padded %d too small", dataLen, len(padded))
		}
		recovered := cd.unpadFromConstantSize(padded)
		if len(recovered) != dataLen {
			t.Errorf("data %d bytes: round-trip got %d", dataLen, len(recovered))
		}
	}
}

func TestProcessOutboundWithoutJitter(t *testing.T) {
	cd := NewCorrelationDefense(&CorrelationConfig{
		Enabled:         true,
		PaddingEnabled:  true,
		DelayJitter:     0,
		ConstantRatePPS: 10000,
	})
	defer cd.Stop()

	var sent []byte
	err := cd.ProcessOutbound([]byte("test"), func(data []byte) error {
		sent = data
		return nil
	})
	if err != nil {
		t.Fatalf("ProcessOutbound error: %v", err)
	}
	if len(sent) == 0 {
		t.Error("no data sent")
	}
}

func TestProcessInbound(t *testing.T) {
	cd := NewCorrelationDefense(&CorrelationConfig{
		Enabled:         true,
		PaddingEnabled:  true,
		DelayJitter:     0,
		ConstantRatePPS: 1000,
	})
	defer cd.Stop()

	original := []byte("inbound test payload data")
	padded := cd.padToConstantSize(original)
	recovered := cd.ProcessInbound(padded)

	if string(recovered) != string(original) {
		t.Errorf("inbound processing failed: got %q", string(recovered))
	}
}

func TestDisabledPassthrough(t *testing.T) {
	cd := NewCorrelationDefense(&CorrelationConfig{
		Enabled: false,
	})
	defer cd.Stop()

	data := []byte("passthrough")

	var sent []byte
	cd.ProcessOutbound(data, func(d []byte) error {
		sent = d
		return nil
	})
	if string(sent) != "passthrough" {
		t.Errorf("disabled should passthrough, got %q", string(sent))
	}

	result := cd.ProcessInbound(data)
	if string(result) != "passthrough" {
		t.Errorf("disabled inbound should passthrough, got %q", string(result))
	}
}

func TestCoverTraffic(t *testing.T) {
	cd := NewCorrelationDefense(&CorrelationConfig{
		Enabled:         true,
		ConstantRatePPS: 100,
		PaddingEnabled:  true,
	})

	var count int64
	cd.GenerateCoverTraffic(func(data []byte) error {
		if len(data) != 128 {
			t.Errorf("cover packet should be 128 bytes, got %d", len(data))
		}
		if data[0] != 0xFF {
			t.Error("cover packet should start with 0xFF marker")
		}
		atomic.AddInt64(&count, 1)
		return nil
	})

	time.Sleep(200 * time.Millisecond)
	cd.Stop()

	c := atomic.LoadInt64(&count)
	if c == 0 {
		t.Error("expected some cover traffic packets")
	}
}

func TestJitterDelay(t *testing.T) {
	cd := NewCorrelationDefense(&CorrelationConfig{
		Enabled:         true,
		ConstantRatePPS: 1000,
		PaddingEnabled:  false,
		DelayJitter:     50 * time.Millisecond,
	})
	defer cd.Stop()

	delays := make([]time.Duration, 100)
	for i := range delays {
		delays[i] = cd.randomDelay()
	}

	var hasVariation bool
	for i := 1; i < len(delays); i++ {
		if delays[i] != delays[0] {
			hasVariation = true
			break
		}
	}
	if !hasVariation {
		t.Error("expected random variation in delays")
	}
}
