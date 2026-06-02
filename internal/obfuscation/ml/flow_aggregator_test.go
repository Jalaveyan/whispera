package ml

import "testing"

func drain(out chan LabeledFlow) (LabeledFlow, bool) {
	select {
	case lf := <-out:
		return lf, true
	default:
		return LabeledFlow{}, false
	}
}

func TestFlowAggregator_DecoyEmitOnSweep(t *testing.T) {
	out := make(chan LabeledFlow, 4)
	agg := newFlowAggregator(443, out)

	base := 1000.0
	for i := 0; i < 10; i++ {
		agg.observe(base+float64(i)*0.01, "1.2.3.4", "5.6.7.8", 12345, 80, 500+i*10)
	}
	agg.sweep(base + 100) // age > 30 → emit

	lf, ok := drain(out)
	if !ok {
		t.Fatal("expected a LabeledFlow after sweep")
	}
	if lf.Label != FlowDecoy {
		t.Fatalf("label=%v, want FlowDecoy", lf.Label)
	}
	if lf.Features.PacketCount != 10 {
		t.Fatalf("packetCount=%v, want 10", lf.Features.PacketCount)
	}
	if lf.Features.SizeMean <= 0 || lf.Features.Duration <= 0 {
		t.Fatalf("expected positive sizeMean/duration, got %+v", lf.Features)
	}
}

func TestFlowAggregator_EmitOn200(t *testing.T) {
	out := make(chan LabeledFlow, 4)
	agg := newFlowAggregator(443, out)

	for i := 0; i < 200; i++ {
		agg.observe(2000+float64(i)*0.001, "9.9.9.9", "8.8.8.8", 23456, 80, 600)
	}
	lf, ok := drain(out)
	if !ok {
		t.Fatal("expected emit on the 200th packet without sweep")
	}
	if lf.Features.PacketCount != 200 {
		t.Fatalf("packetCount=%v, want 200", lf.Features.PacketCount)
	}
}

func TestFlowAggregator_IgnoresOffPort(t *testing.T) {
	out := make(chan LabeledFlow, 4)
	agg := newFlowAggregator(443, out)

	for i := 0; i < 20; i++ {
		agg.observe(3000+float64(i), "1.1.1.1", "2.2.2.2", 22, 51000, 400)
	}
	agg.sweep(9999)
	if _, ok := drain(out); ok {
		t.Fatal("off-port flow must not be emitted")
	}
}

func TestFlowAggregator_RegistryTunnelLabel(t *testing.T) {
	FlowRegistry.Register("7.7.7.7:44444", FlowTunnel)
	defer FlowRegistry.Delete("7.7.7.7:44444")

	out := make(chan LabeledFlow, 4)
	agg := newFlowAggregator(443, out)

	base := 4000.0
	for i := 0; i < 8; i++ {
		agg.observe(base+float64(i)*0.02, "7.7.7.7", "0.0.0.0", 44444, 443, 1200)
	}
	agg.sweep(base + 100)

	lf, ok := drain(out)
	if !ok {
		t.Fatal("expected a LabeledFlow for registered tunnel flow")
	}
	if lf.Label != FlowTunnel {
		t.Fatalf("label=%v, want FlowTunnel (registry lookup failed)", lf.Label)
	}
}
