package main

import (
	"testing"
	"whispera/core/config"
)

func TestPickServerAddressTCP(t *testing.T) {
	cfg := &config.ClientConfig{ServerTCP: "tcp.example.com", Server: "fallback.example.com"}
	if got := pickServerAddress(cfg, "tcp"); got != "tcp.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "tcp.example.com")
	}
}

func TestPickServerAddressTLSUsesTCP(t *testing.T) {
	cfg := &config.ClientConfig{ServerTCP: "tcp.example.com"}
	if got := pickServerAddress(cfg, "tls"); got != "tcp.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "tcp.example.com")
	}
}

func TestPickServerAddressWSFallsBackToTCP(t *testing.T) {
	cfg := &config.ClientConfig{ServerTCP: "tcp.example.com"}
	if got := pickServerAddress(cfg, "ws"); got != "tcp.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "tcp.example.com")
	}
}

func TestPickServerAddressWSPrefersServerWS(t *testing.T) {
	cfg := &config.ClientConfig{ServerWS: "ws.example.com", ServerTCP: "tcp.example.com"}
	if got := pickServerAddress(cfg, "ws"); got != "ws.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "ws.example.com")
	}
}

func TestPickServerAddressUnknownTransportFallsBackToServer(t *testing.T) {
	cfg := &config.ClientConfig{Server: "fallback.example.com", ServerTCP: "tcp.example.com"}
	if got := pickServerAddress(cfg, "quic"); got != "fallback.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "fallback.example.com")
	}
}

func TestResolveMLTokenEmptyWithoutMLServerURL(t *testing.T) {
	cfg := &config.ClientConfig{MLToken: "should-be-ignored"}
	if got := resolveMLToken(cfg); got != "" {
		t.Errorf("resolveMLToken() = %q, want \"\" when MLServerURL is empty", got)
	}
}

func TestResolveMLTokenPrefersExplicitToken(t *testing.T) {
	cfg := &config.ClientConfig{MLServerURL: "https://ml.example.com", MLToken: "explicit-token"}
	if got := resolveMLToken(cfg); got != "explicit-token" {
		t.Errorf("resolveMLToken() = %q, want %q", got, "explicit-token")
	}
}

func TestLoadClientConfigUsesServerAddrFlag(t *testing.T) {
	origServer, origKey, origPath := *serverAddr, *connKey, *configPath
	defer func() {
		*serverAddr, *connKey, *configPath = origServer, origKey, origPath
	}()

	*connKey = ""
	*configPath = ""
	*serverAddr = "203.0.113.10:443"

	cfg := loadClientConfig()
	if cfg.Server != "203.0.113.10:443" {
		t.Errorf("loadClientConfig().Server = %q, want %q", cfg.Server, "203.0.113.10:443")
	}
}
