package ml

import "testing"

func TestUnifiedNetChainedBackprop(t *testing.T) {
	u := NewUnifiedNet(UnifiedStateSize, 32, 16, map[string]int{"chunk": 6, "transport": 4})
	st := UnifiedState{RTTMs: 0.3, UpBps: 0.5, DnBps: 0.8, SuccessRate: 0.9}.Vec()

	for i := 0; i < 4000; i++ {
		u.Train(st, "chunk", 2, 1.0, 0.01)
		u.Train(st, "chunk", 0, 0.0, 0.01)
		u.Train(st, "chunk", 4, 0.0, 0.01)
	}

	q := u.QValues(st, "chunk")
	if q[2] < 0.7 {
		t.Fatalf("chunk q[2] should converge toward 1.0, got %v", q)
	}
	if q[0] > 0.3 || q[4] > 0.3 {
		t.Fatalf("chunk q[0],q[4] should stay near 0, got %v", q)
	}

	if qt := u.QValues(st, "transport"); len(qt) != 4 {
		t.Fatalf("transport head should output 4 actions, got %d", len(qt))
	}
}
