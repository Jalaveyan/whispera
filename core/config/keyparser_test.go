package config

import "testing"

func TestGetPrimaryServerTCP(t *testing.T) {
	ck := &ConnectionKey{Transport: "tcp", ServerTCP: "tcp.example.com", Server: "fallback.example.com"}
	if got := ck.GetPrimaryServer(); got != "tcp.example.com" {
		t.Errorf("GetPrimaryServer() = %q, want %q", got, "tcp.example.com")
	}
}

func TestGetPrimaryServerTCPFallsBackToServer(t *testing.T) {
	ck := &ConnectionKey{Transport: "tcp", Server: "fallback.example.com"}
	if got := ck.GetPrimaryServer(); got != "fallback.example.com" {
		t.Errorf("GetPrimaryServer() = %q, want %q", got, "fallback.example.com")
	}
}

func TestGetPrimaryServerWS(t *testing.T) {
	ck := &ConnectionKey{Transport: "ws", ServerWS: "ws.example.com", ServerTCP: "tcp.example.com"}
	if got := ck.GetPrimaryServer(); got != "ws.example.com" {
		t.Errorf("GetPrimaryServer() = %q, want %q", got, "ws.example.com")
	}
}

func TestGetPrimaryServerUDP(t *testing.T) {
	ck := &ConnectionKey{Transport: "udp", Server: "udp.example.com", ServerTCP: "tcp.example.com"}
	if got := ck.GetPrimaryServer(); got != "udp.example.com" {
		t.Errorf("GetPrimaryServer() = %q, want %q", got, "udp.example.com")
	}
}

func TestGetPrimaryServerUnknownTransportFallsBack(t *testing.T) {
	ck := &ConnectionKey{Transport: "quic", Server: "quic.example.com", ServerTCP: "tcp.example.com"}
	if got := ck.GetPrimaryServer(); got != "quic.example.com" {
		t.Errorf("GetPrimaryServer() = %q, want %q", got, "quic.example.com")
	}

	ck2 := &ConnectionKey{Transport: "quic", ServerTCP: "tcp.example.com"}
	if got := ck2.GetPrimaryServer(); got != "tcp.example.com" {
		t.Errorf("GetPrimaryServer() = %q, want %q", got, "tcp.example.com")
	}
}

func TestToClientConfigUDPOnly(t *testing.T) {
	tcp := &ConnectionKey{Transport: "tcp"}
	if cfg := tcp.ToClientConfig(); cfg.UDPOnly {
		t.Error("ToClientConfig().UDPOnly = true for tcp transport, want false")
	}

	udp := &ConnectionKey{Transport: "udp"}
	if cfg := udp.ToClientConfig(); !cfg.UDPOnly {
		t.Error("ToClientConfig().UDPOnly = false for udp transport, want true")
	}

	unknown := &ConnectionKey{Transport: "quic"}
	if cfg := unknown.ToClientConfig(); cfg.UDPOnly {
		t.Error("ToClientConfig().UDPOnly = true for unknown transport, want false (default)")
	}
}

func TestMapXRayTransport(t *testing.T) {
	cases := map[string]string{
		"grpc": "grpc",
		"GRPC": "grpc",
		"quic": "quic",
		"tcp":  "tcp",
		"":     "tcp",
		"ws":   "tcp",
	}
	for in, want := range cases {
		if got := mapXRayTransport(in); got != want {
			t.Errorf("mapXRayTransport(%q) = %q, want %q", in, got, want)
		}
	}
}
