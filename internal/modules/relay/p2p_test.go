package relay

// Item 7: Whitelist bypass + client=client bidirectional P2P
//
// Тесты охватывают:
// - регистрацию двух peer-ов
// - установление P2P соединения через relay
// - двунаправленную передачу данных
// - отказ при неверном auth
// - cleanup при отключении peer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

const testSecret = "whispera-p2p-test-secret"

func startTestRelay(t *testing.T) (addr string, stop func()) {
	t.Helper()
	cfg := DefaultP2PRelayConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.Secret = []byte(testSecret)
	cfg.MaxPeers = 64
	cfg.PeerTimeout = 5 * time.Second

	relay := NewP2PRelay(cfg)
	if err := relay.Start(); err != nil {
		t.Fatalf("relay start: %v", err)
	}

	// Получаем реальный порт
	relay.mu.Lock()
	addr = relay.listener.Addr().String()
	relay.mu.Unlock()

	return addr, func() { relay.Stop() }
}

// TestP2PRegisterAndConnect: два peer регистрируются, устанавливают соединение.
func TestP2PRegisterAndConnect(t *testing.T) {
	addr, stop := startTestRelay(t)
	defer stop()

	secret := []byte(testSecret)

	clientA := NewP2PClient(addr, secret)
	clientB := NewP2PClient(addr, secret)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A регистрируется
	if err := clientA.Register(ctx); err != nil {
		t.Fatalf("clientA register: %v", err)
	}
	// B регистрируется
	if err := clientB.Register(ctx); err != nil {
		t.Fatalf("clientB register: %v", err)
	}

	// B ждёт партнёра в фоне
	connBCh := make(chan net.Conn, 1)
	errBCh := make(chan error, 1)
	go func() {
		conn, err := clientB.WaitForPartner(ctx)
		if err != nil {
			errBCh <- err
			return
		}
		connBCh <- conn
	}()

	// A подключается к B
	connA, err := clientA.ConnectTo(ctx, clientB.PeerID())
	if err != nil {
		t.Fatalf("clientA connect to B: %v", err)
	}
	defer connA.Close()

	select {
	case connB := <-connBCh:
		defer connB.Close()
		// Соединение установлено с обеих сторон
	case err := <-errBCh:
		t.Fatalf("clientB wait for partner: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for P2P connection")
	}
}

// TestP2PBidirectionalData: проверяем что данные проходят в обе стороны.
func TestP2PBidirectionalData(t *testing.T) {
	addr, stop := startTestRelay(t)
	defer stop()

	secret := []byte(testSecret)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	clientA := NewP2PClient(addr, secret)
	clientB := NewP2PClient(addr, secret)

	clientA.Register(ctx)
	clientB.Register(ctx)

	connBCh := make(chan net.Conn, 1)
	go func() {
		conn, err := clientB.WaitForPartner(ctx)
		if err == nil {
			connBCh <- conn
		}
	}()

	connA, err := clientA.ConnectTo(ctx, clientB.PeerID())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer connA.Close()

	connB := <-connBCh
	defer connB.Close()

	msgAtoB := []byte("hello from A to B")
	msgBtoA := []byte("hello from B to A")

	// A → B
	connA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := connA.Write(msgAtoB); err != nil {
		t.Fatalf("A write: %v", err)
	}

	buf := make([]byte, len(msgAtoB))
	connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(connB, buf); err != nil {
		t.Fatalf("B read: %v", err)
	}
	if !bytes.Equal(buf, msgAtoB) {
		t.Errorf("A→B data mismatch: got %q, want %q", buf, msgAtoB)
	}

	// B → A
	connB.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := connB.Write(msgBtoA); err != nil {
		t.Fatalf("B write: %v", err)
	}

	buf2 := make([]byte, len(msgBtoA))
	connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(connA, buf2); err != nil {
		t.Fatalf("A read: %v", err)
	}
	if !bytes.Equal(buf2, msgBtoA) {
		t.Errorf("B→A data mismatch: got %q, want %q", buf2, msgBtoA)
	}
}

// TestP2PBulkTransfer: передаём 1MB данных через relay.
func TestP2PBulkTransfer(t *testing.T) {
	addr, stop := startTestRelay(t)
	defer stop()

	secret := []byte(testSecret)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientA := NewP2PClient(addr, secret)
	clientB := NewP2PClient(addr, secret)
	clientA.Register(ctx)
	clientB.Register(ctx)

	connBCh := make(chan net.Conn, 1)
	go func() {
		conn, _ := clientB.WaitForPartner(ctx)
		connBCh <- conn
	}()

	connA, err := clientA.ConnectTo(ctx, clientB.PeerID())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer connA.Close()

	connB := <-connBCh
	defer connB.Close()

	const totalBytes = 1 << 20 // 1 MB
	payload := bytes.Repeat([]byte{0xAB}, 4096)

	// Отправляем из A в B
	go func() {
		sent := 0
		for sent < totalBytes {
			n := min(len(payload), totalBytes-sent)
			connA.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := connA.Write(payload[:n]); err != nil {
				return
			}
			sent += n
		}
	}()

	// Читаем в B
	received := 0
	buf := make([]byte, 4096)
	for received < totalBytes {
		connB.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := connB.Read(buf)
		if err != nil {
			t.Fatalf("B read at %d bytes: %v", received, err)
		}
		received += n
	}

	if received != totalBytes {
		t.Errorf("transferred %d bytes, expected %d", received, totalBytes)
	}
}

// TestP2PInvalidAuthRejected: клиент с неверным секретом отклоняется.
func TestP2PInvalidAuthRejected(t *testing.T) {
	addr, stop := startTestRelay(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	badClient := NewP2PClient(addr, []byte("wrong-secret"))
	err := badClient.Register(ctx)
	// Relay должен закрыть соединение или вернуть ошибку
	if err == nil {
		// Попробуем ConnectTo — тоже должен упасть
		good := NewP2PClient(addr, []byte(testSecret))
		good.Register(ctx)
		_, connErr := badClient.ConnectTo(ctx, good.PeerID())
		if connErr == nil {
			t.Error("bad-auth client should not be able to connect")
		}
	}
	// err != nil уже достаточно
}

// TestP2PMultiplePairs: N пар клиентов одновременно.
func TestP2PMultiplePairs(t *testing.T) {
	addr, stop := startTestRelay(t)
	defer stop()

	const pairs = 5
	secret := []byte(testSecret)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type result struct{ err error }
	results := make(chan result, pairs)

	for i := 0; i < pairs; i++ {
		go func(idx int) {
			cA := NewP2PClient(addr, secret)
			cB := NewP2PClient(addr, secret)

			if err := cA.Register(ctx); err != nil {
				results <- result{fmt.Errorf("pair %d A register: %w", idx, err)}
				return
			}
			if err := cB.Register(ctx); err != nil {
				results <- result{fmt.Errorf("pair %d B register: %w", idx, err)}
				return
			}

			connBCh := make(chan net.Conn, 1)
			go func() {
				conn, _ := cB.WaitForPartner(ctx)
				connBCh <- conn
			}()

			connA, err := cA.ConnectTo(ctx, cB.PeerID())
			if err != nil {
				results <- result{fmt.Errorf("pair %d connect: %w", idx, err)}
				return
			}
			connB := <-connBCh

			msg := []byte(fmt.Sprintf("pair-%d-data", idx))
			connA.Write(msg)
			buf := make([]byte, len(msg))
			connB.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.ReadFull(connB, buf)

			connA.Close()
			connB.Close()

			if !bytes.Equal(buf, msg) {
				results <- result{fmt.Errorf("pair %d data mismatch", idx)}
				return
			}
			results <- result{}
		}(i)
	}

	for i := 0; i < pairs; i++ {
		if r := <-results; r.err != nil {
			t.Error(r.err)
		}
	}
}

// TestP2PRelayStats: статистика relay обновляется.
func TestP2PRelayStats(t *testing.T) {
	cfg := DefaultP2PRelayConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.Secret = []byte(testSecret)
	relay := NewP2PRelay(cfg)
	if err := relay.Start(); err != nil {
		t.Fatalf("relay.Start: %v", err)
	}
	defer relay.Stop()

	relay.mu.Lock()
	addr := relay.listener.Addr().String()
	relay.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	secret := []byte(testSecret)
	cA := NewP2PClient(addr, secret)
	cB := NewP2PClient(addr, secret)
	cA.Register(ctx)
	cB.Register(ctx)

	stats := relay.Stats()
	registered, ok := stats["registered"].(int)
	if !ok || registered < 2 {
		t.Errorf("expected >= 2 registered peers in stats, got %v", stats["registered"])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
