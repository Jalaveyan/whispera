package proxyagent

import (
	"sync/atomic"
	"testing"
	"time"
)


func makeAgent(transports []string, server string) *ProxyAgent {
	candidates := make([]TransportCandidate, len(transports))
	for i, tr := range transports {
		candidates[i] = TransportCandidate{
			Name:    tr,
			Server:  server,
			Enabled: true,
			Priority: 1.0,
		}
	}
	cfg := DefaultAgentConfig()
	cfg.Candidates = candidates
	cfg.ExploreRate = 0
	cfg.LearnRate = 0.5
	cfg.FailThreshold = 1000
	return NewProxyAgent(cfg)
}

func succeed(pa *ProxyAgent, transport, server string) {
	pa.ReportResult(ProbeResult{
		Transport: transport,
		Server:    server,
		Success:   true,
		Latency:   10 * time.Millisecond,
	})
}

func fail(pa *ProxyAgent, transport, server string) {
	pa.ReportResult(ProbeResult{
		Transport: transport,
		Server:    server,
		Success:   false,
		Error:     "timeout",
		Latency:   3 * time.Second,
	})
}


func TestTransportSelectionPrefersBest(t *testing.T) {
	pa := makeAgent([]string{"tcp", "udp", "websocket"}, "127.0.0.1:8443")

	for i := 0; i < 10; i++ {
		succeed(pa, "tcp", "127.0.0.1:8443")
	}
	for i := 0; i < 10; i++ {
		fail(pa, "udp", "127.0.0.1:8443")
	}
	for i := 0; i < 5; i++ {
		succeed(pa, "websocket", "127.0.0.1:8443")
	}
	for i := 0; i < 5; i++ {
		fail(pa, "websocket", "127.0.0.1:8443")
	}

	chosen, _ := pa.SelectTransport()
	if chosen != "tcp" {
		t.Errorf("expected tcp (best Q), got %s", chosen)
	}
}

func TestTransportFallbackAfterFailures(t *testing.T) {
	pa := makeAgent([]string{"tcp", "udp"}, "127.0.0.1:8443")

	for i := 0; i < 5; i++ {
		succeed(pa, "tcp", "127.0.0.1:8443")
	}
	for i := 0; i < 8; i++ {
		succeed(pa, "udp", "127.0.0.1:8443")
	}
	for i := 0; i < 10; i++ {
		fail(pa, "tcp", "127.0.0.1:8443")
	}

	chosen, _ := pa.SelectTransport()
	if chosen != "udp" {
		t.Errorf("expected fallback to udp after tcp failures, got %s", chosen)
	}
}

func TestTransportAllCombinations(t *testing.T) {
	allTransports := []string{
		"tcp", "udp", "websocket", "xhttp", "quic",
		"h2c", "shadowsocks", "domainfront", "vkvideo",
	}

	pa := makeAgent(allTransports, "127.0.0.1:8443")

	pa.config.ExploreRate = 1.0
	seen := make(map[string]bool)

	for i := 0; i < 200; i++ {
		tr, _ := pa.SelectTransport()
		seen[tr] = true
	}

	for _, tr := range allTransports {
		if !seen[tr] {
			t.Errorf("transport %s was never selected during explore", tr)
		}
	}
}

func TestTransportQValueDecay(t *testing.T) {
	pa := makeAgent([]string{"tcp", "udp"}, "127.0.0.1:8443")
	pa.config.DecayRate = 0.5

	for i := 0; i < 10; i++ {
		succeed(pa, "tcp", "127.0.0.1:8443")
	}
	for i := 0; i < 10; i++ {
		succeed(pa, "udp", "127.0.0.1:8443")
	}

	// After many failures on tcp, its Q decays to near zero; udp should win.
	for i := 0; i < 20; i++ {
		fail(pa, "tcp", "127.0.0.1:8443")
	}

	tr, _ := pa.SelectTransport()
	if tr == "tcp" {
		t.Errorf("expected tcp Q to decay below udp after many failures, but tcp was still selected")
	}
}

func TestTransportDisableEnableCandidate(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Candidates = []TransportCandidate{
		{Name: "tcp", Server: "127.0.0.1:8443", Enabled: true, Priority: 1.0},
		{Name: "udp", Server: "127.0.0.1:8443", Enabled: false, Priority: 1.0},
	}
	cfg.ExploreRate = 0
	pa := NewProxyAgent(cfg)

	for i := 0; i < 10; i++ {
		succeed(pa, "udp", "127.0.0.1:8443")
	}

	for i := 0; i < 20; i++ {
		tr, _ := pa.SelectTransport()
		if tr == "udp" {
			t.Errorf("disabled transport udp was selected on attempt %d", i)
		}
	}
}

func TestTransportSwitchCallback(t *testing.T) {
	pa := makeAgent([]string{"tcp", "udp"}, "127.0.0.1:8443")
	pa.Stop()

	var switchCount int32
	pa.SetSwitchCallback(func(transport, server string) {
		atomic.AddInt32(&switchCount, 1)
	})

	for i := 0; i < 10; i++ {
		succeed(pa, "udp", "127.0.0.1:8443")
	}
	for i := 0; i < 10; i++ {
		fail(pa, "tcp", "127.0.0.1:8443")
	}

	pa.scheduledRotate()

	time.Sleep(20 * time.Millisecond)
	if atomic.LoadInt32(&switchCount) == 0 {
		t.Error("switch callback was never called after transport degradation")
	}
}

func TestTransportMLAwareness(t *testing.T) {
	pa := makeAgent([]string{"tcp", "udp", "websocket"}, "127.0.0.1:8443")

	succeed(pa, "tcp", "127.0.0.1:8443")
	fail(pa, "udp", "127.0.0.1:8443")

	stats := pa.Stats()

	required := []string{"state", "current_arm", "arms"}
	for _, key := range required {
		if _, ok := stats[key]; !ok {
			t.Errorf("Stats() missing field %q", key)
		}
	}

	arms, ok := stats["arms"].([]map[string]interface{})
	if !ok || len(arms) == 0 {
		t.Error("Stats()[arms] should be non-empty slice")
	}
}

func TestTransportParallelProbes(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Candidates = []TransportCandidate{
		{Name: "tcp", Server: "127.0.0.1:8443", Enabled: true, Priority: 1.0},
		{Name: "udp", Server: "127.0.0.1:8443", Enabled: true, Priority: 1.0},
		{Name: "websocket", Server: "127.0.0.1:8443", Enabled: true, Priority: 1.0},
	}
	cfg.ParallelProbes = 3
	cfg.ExploreRate = 0.3
	pa := NewProxyAgent(cfg)

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				tr := cfg.Candidates[j%3].Name
				if j%4 == 0 {
					fail(pa, tr, "127.0.0.1:8443")
				} else {
					succeed(pa, tr, "127.0.0.1:8443")
				}
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 8; i++ {
		<-done
	}

	for i := 0; i < 100; i++ {
		tr, srv := pa.SelectTransport()
		if tr == "" || srv == "" {
			t.Errorf("SelectTransport returned empty (iter %d)", i)
		}
	}
}
