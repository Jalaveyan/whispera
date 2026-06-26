package tunnel

import (
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return m
}

func TestNewInitialState(t *testing.T) {
	m := newTestManager(t)

	if got := m.GetState(); got != StateDisconnected {
		t.Errorf("GetState() = %v, want %v", got, StateDisconnected)
	}
	if m.IsConnected() {
		t.Error("IsConnected() = true on fresh Manager")
	}
	if m.GetSessionID() != 0 {
		t.Errorf("GetSessionID() = %d, want 0", m.GetSessionID())
	}
}

func TestGetMuxConfigWithoutChunkAgent(t *testing.T) {
	m := &Manager{ml: &mlOrchestrator{}}

	cfg := m.getMuxConfig()
	if cfg.MaxFrameSize != 65535 {
		t.Errorf("MaxFrameSize = %d, want 65535 when chunkAgent is nil", cfg.MaxFrameSize)
	}
	if cfg.MaxConcurrentStreams != 256 {
		t.Errorf("MaxConcurrentStreams = %d, want 256", cfg.MaxConcurrentStreams)
	}
}

func TestDisconnectOnFreshManagerIsSafe(t *testing.T) {
	m := newTestManager(t)

	m.Disconnect()

	if got := m.GetState(); got != StateDisconnected {
		t.Errorf("GetState() after Disconnect() = %v, want %v", got, StateDisconnected)
	}
}

func TestQualityMetrics(t *testing.T) {
	m := newTestManager(t)

	rtt, missed := m.GetQualityMetrics()
	if rtt != 0 || missed != 0 {
		t.Errorf("GetQualityMetrics() = (%v, %d), want (0, 0) on fresh Manager", rtt, missed)
	}

	m.updateQualityRTT(50 * time.Millisecond)
	rtt, _ = m.GetQualityMetrics()
	if rtt != 50*time.Millisecond {
		t.Errorf("GetQualityMetrics() rtt = %v, want %v after first sample", rtt, 50*time.Millisecond)
	}
}

func TestStats(t *testing.T) {
	m := newTestManager(t)

	up, down := m.Stats()
	if up != 0 || down != 0 {
		t.Errorf("Stats() = (%d, %d), want (0, 0) on fresh Manager", up, down)
	}
}

func TestTransportGetSet(t *testing.T) {
	m := newTestManager(t)

	m.SetTransport("quic")
	if got := m.GetTransport(); got != "quic" {
		t.Errorf("GetTransport() = %q, want %q", got, "quic")
	}
}

func TestRateLimitGetSet(t *testing.T) {
	m := newTestManager(t)

	m.SetRateLimit(1024)
	if got := m.GetRateLimit(); got != 1024 {
		t.Errorf("GetRateLimit() = %d, want 1024", got)
	}
}

func TestTLSFragmentSizeGetSet(t *testing.T) {
	m := newTestManager(t)

	m.SetTLSFragmentSize(40)
	if got := m.GetTLSFragmentSize(); got != 40 {
		t.Errorf("GetTLSFragmentSize() = %d, want 40", got)
	}

	m.SetTLSFragmentSize(-5)
	if got := m.GetTLSFragmentSize(); got != 0 {
		t.Errorf("GetTLSFragmentSize() = %d, want 0 after negative input", got)
	}
}

func TestForceObfuscationGetSet(t *testing.T) {
	m := newTestManager(t)

	m.SetForceObfuscation(true)
	if !m.IsForceObfuscation() {
		t.Error("IsForceObfuscation() = false after SetForceObfuscation(true)")
	}

	m.SetForceObfuscation(false)
	if m.IsForceObfuscation() {
		t.Error("IsForceObfuscation() = true after SetForceObfuscation(false)")
	}
}

func TestSetBehavioralProfileWithoutObfuscator(t *testing.T) {
	m := newTestManager(t)
	m.obfuscator = nil

	if err := m.SetBehavioralProfile("steady"); err == nil {
		t.Error("SetBehavioralProfile() error = nil, want error when obfuscator is nil")
	}
	if err := m.SetBehavioralProfile(""); err == nil {
		t.Error("SetBehavioralProfile(\"\") error = nil, want error when obfuscator is nil")
	}
}

func TestAddRussianSNIDeduplicates(t *testing.T) {
	m := newTestManager(t)

	m.AddRussianSNI("vk.com")
	m.AddRussianSNI("ok.ru")
	m.AddRussianSNI("vk.com")

	got := m.GetRussianSNIs()
	if len(got) != 2 {
		t.Fatalf("GetRussianSNIs() = %v, want 2 unique entries", got)
	}
}

func TestAddRussianSNIIgnoresEmpty(t *testing.T) {
	m := newTestManager(t)

	m.AddRussianSNI("")

	if got := m.GetRussianSNIs(); len(got) != 0 {
		t.Errorf("GetRussianSNIs() = %v, want empty after adding \"\"", got)
	}
}

func TestHealthyPoolFiltersSlowConns(t *testing.T) {
	m := newTestManager(t)

	slow := &managedConn{}
	slow.rateMbpsX100.Store(100)
	fast := &managedConn{}
	fast.rateMbpsX100.Store(1000)

	got := m.healthyPool([]*managedConn{slow, fast})
	if len(got) != 1 || got[0] != fast {
		t.Errorf("healthyPool() = %v, want only the fast conn", got)
	}
}

func TestHealthyPoolPassesThroughSmallPools(t *testing.T) {
	m := newTestManager(t)

	only := &managedConn{}
	got := m.healthyPool([]*managedConn{only})
	if len(got) != 1 || got[0] != only {
		t.Errorf("healthyPool() = %v, want pool unchanged when len <= 1", got)
	}
}

func TestRTDialNilWithoutWhispera(t *testing.T) {
	m := newTestManager(t)

	if dial := m.rtDial(); dial != nil {
		t.Error("rtDial() != nil, want nil when EnableWhispera is false")
	}
	if m.rtLaneActive() {
		t.Error("rtLaneActive() = true on fresh Manager")
	}
}

func TestExportImportMLWeightsRoundTrip(t *testing.T) {
	m := newTestManager(t)

	snap := m.ExportMLWeights()
	if snap == nil {
		t.Fatal("ExportMLWeights() = nil")
	}
	m.ImportMLWeights(snap)
	m.ImportMLWeights(nil)
}

func TestHealthCheck(t *testing.T) {
	m := newTestManager(t)

	status := m.HealthCheck()
	if status.Details["state"] != StateDisconnected.String() {
		t.Errorf("HealthCheck() state = %v, want %v", status.Details["state"], StateDisconnected.String())
	}
	if status.Details["active_streams"] != 0 {
		t.Errorf("HealthCheck() active_streams = %v, want 0", status.Details["active_streams"])
	}
}
