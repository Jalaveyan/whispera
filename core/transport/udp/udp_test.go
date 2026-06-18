package udp

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ListenAddr != ":8443" {
		t.Errorf("expected :8443, got %s", cfg.ListenAddr)
	}
	if cfg.MaxPacketSize != 65535 {
		t.Errorf("expected 65535, got %d", cfg.MaxPacketSize)
	}
	if cfg.WorkerCount != 16 {
		t.Errorf("expected 16 workers, got %d", cfg.WorkerCount)
	}
	if cfg.WriteTimeout != 10*time.Second {
		t.Errorf("expected 10s write timeout, got %v", cfg.WriteTimeout)
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := &Config{ListenAddr: ""}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty listen addr")
	}

	cfg.ListenAddr = ":9999"
	cfg.MaxPacketSize = -1
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if cfg.MaxPacketSize != 65535 {
		t.Errorf("expected MaxPacketSize corrected to 65535, got %d", cfg.MaxPacketSize)
	}
}

func TestNewTransport(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	if tr.Name() != ModuleName {
		t.Errorf("expected %s, got %s", ModuleName, tr.Name())
	}
}

func TestTransportType(t *testing.T) {
	tr, _ := New(DefaultConfig())
	if tr.Type() != "udp" {
		t.Errorf("expected udp, got %s", tr.Type())
	}
}

func TestFactory(t *testing.T) {
	m, err := Factory(nil)
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	if m.Name() != ModuleName {
		t.Errorf("expected %s, got %s", ModuleName, m.Name())
	}
}
