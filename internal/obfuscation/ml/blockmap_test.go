package ml

import "testing"

func TestApplyBlockmapPrior(t *testing.T) {
	a := NewRLTransportAgent("", nil)
	a.ApplyBlockmapPrior(BlockmapEntry{
		Transports: map[string]TransportRate{
			"shadowtls": {OK: 90, Fail: 10, Rate: 0.9},
			"tcp":       {OK: 10, Fail: 90, Rate: 0.1},
		},
	})

	si := a.transportIndex["shadowtls"]
	ti := a.transportIndex["tcp"]
	if a.thompson.alpha[si] <= a.thompson.beta[si] {
		t.Fatalf("shadowtls prior should favor success: alpha=%.2f beta=%.2f", a.thompson.alpha[si], a.thompson.beta[si])
	}
	if a.thompson.beta[ti] <= a.thompson.alpha[ti] {
		t.Fatalf("tcp prior should favor failure: alpha=%.2f beta=%.2f", a.thompson.alpha[ti], a.thompson.beta[ti])
	}
}

func TestDrainOutcomes(t *testing.T) {
	a := NewRLTransportAgent("", nil)
	idx := a.transportIndex["tcp"]

	a.pendingState = make([]float64, RLStateSize)
	a.pendingAction = idx
	a.RecordOutcome(true, 50)

	a.pendingState = make([]float64, RLStateSize)
	a.pendingAction = idx
	a.RecordOutcome(false, 50)

	snap := a.DrainOutcomes()
	r, ok := snap["tcp"]
	if !ok || r.OK != 1 || r.Fail != 1 {
		t.Fatalf("tcp outcomes wrong: %+v (ok=%v)", r, ok)
	}
	if again := a.DrainOutcomes(); len(again) != 0 {
		t.Fatalf("drain did not reset outcomes: %+v", again)
	}
}
