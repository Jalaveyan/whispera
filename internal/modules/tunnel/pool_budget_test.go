package tunnel

import (
	"context"
	"testing"
)

func TestPoolConnCap(t *testing.T) {
	poolCap := browserConnBudget - chGameLaneReserve
	cases := []struct {
		mux  int
		want int
	}{
		{0, poolCap},
		{1, 1},
		{poolCap - 1, poolCap - 1},
		{poolCap, poolCap},
		{poolCap + 1, poolCap},
		{16, poolCap},
		{256, poolCap},
	}
	for _, c := range cases {
		m := &Manager{config: &Config{ChameleonOptions: ChameleonOptions{ChameleonMux: c.mux}}}
		if got := m.poolConnCap(); got != c.want {
			t.Errorf("poolConnCap(ChameleonMux=%d)=%d, want %d", c.mux, got, c.want)
		}
	}
}

func TestPoolPlusGameLaneWithinBudget(t *testing.T) {
	m := &Manager{config: &Config{}}
	if total := m.poolConnCap() + chGameLaneReserve; total > browserConnBudget {
		t.Fatalf("pool(%d) + game lane(%d) = %d exceeds browser budget %d",
			m.poolConnCap(), chGameLaneReserve, total, browserConnBudget)
	}
}

func TestOpenPoolConnRespectsBudget(t *testing.T) {
	m := &Manager{config: &Config{ChameleonOptions: ChameleonOptions{EnableChameleon: true}}}
	m.activePool = make([]*managedConn, m.poolConnCap())
	before := len(m.activePool)
	if err := m.openPoolConn(context.Background()); err != nil {
		t.Fatalf("openPoolConn returned error: %v", err)
	}
	if got := len(m.activePool); got != before {
		t.Fatalf("pool grew past budget: before=%d after=%d (cap=%d)", before, got, m.poolConnCap())
	}
}

func TestGameLaneActive(t *testing.T) {
	m := &Manager{config: &Config{}}
	if m.gameLaneActive() {
		t.Fatal("game lane should be inactive with refs=0")
	}
	m.gameLn.refs = 1
	if !m.gameLaneActive() {
		t.Fatal("game lane should be active with refs=1")
	}
}
