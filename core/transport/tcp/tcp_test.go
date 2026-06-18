package tcp

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ListenAddr != ":8443" {
		t.Errorf("expected :8443, got %s", cfg.ListenAddr)
	}
	if cfg.MaxConns != 10000 {
		t.Errorf("expected 10000 max conns, got %d", cfg.MaxConns)
	}
	if cfg.BufferSize != 32*1024*1024 {
		t.Errorf("expected 32MB buffer, got %d", cfg.BufferSize)
	}
	if cfg.ReadTimeout != 30*time.Second {
		t.Errorf("expected 30s read timeout, got %v", cfg.ReadTimeout)
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := &Config{ListenAddr: ""}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty listen addr")
	}

	cfg.ListenAddr = ":9999"
	cfg.MaxConns = -1
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if cfg.MaxConns != 10000 {
		t.Errorf("expected MaxConns to be corrected to 10000, got %d", cfg.MaxConns)
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
	if tr.Version() != ModuleVersion {
		t.Errorf("expected %s, got %s", ModuleVersion, tr.Version())
	}
}

func TestTransportStartStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	_ = tr.Init(context.Background(), nil)

	if err := tr.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	health := tr.HealthCheck()
	if !health.Healthy {
		t.Error("transport should be healthy after start")
	}

	if err := tr.Stop(); err != nil {
		t.Fatalf("failed to stop: %v", err)
	}
}

func TestTransportAcceptDial(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	_ = tr.Init(context.Background(), nil)
	if err := tr.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer tr.Stop()

	addr := tr.listener.Addr().String()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := tr.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	clientConn, err := tr.Dial(ctx, addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	select {
	case serverConn := <-accepted:
		defer serverConn.Close()
		msg := []byte("hello")
		clientConn.Write(msg)
		buf := make([]byte, 16)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		if string(buf[:n]) != "hello" {
			t.Errorf("expected 'hello', got %q", string(buf[:n]))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for accept")
	}
}

func TestTransportType(t *testing.T) {
	tr, _ := New(DefaultConfig())
	if tr.Type() != "tcp" {
		t.Errorf("expected tcp type, got %s", tr.Type())
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
