package relay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func BenchmarkP2PRelay_Throughput(b *testing.B) {
	secret := []byte("bench-secret-key")
	relay := NewP2PRelay(&P2PRelayConfig{
		ListenAddr:   "127.0.0.1:0",
		Secret:       secret,
		MaxPeers:     256,
		PeerTimeout:  30 * time.Second,
		MaxBandwidth: 1 << 30,
	})

	if err := relay.Start(); err != nil {
		b.Fatal(err)
	}
	defer relay.Stop()

	relay.mu.RLock()
	addr := relay.listener.Addr().String()
	relay.mu.RUnlock()

	ctx := context.Background()

	peerA := NewP2PClient(addr, secret)
	if err := peerA.Register(ctx); err != nil {
		b.Fatal(err)
	}
	defer peerA.Close()

	peerB := NewP2PClient(addr, secret)

	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := peerA.WaitForPartner(ctx)
		if err != nil {
			errCh <- err
			return
		}
		connCh <- c
	}()

	connB, err := peerB.ConnectTo(ctx, peerA.PeerID())
	if err != nil {
		b.Fatal(err)
	}
	defer connB.Close()

	var connA net.Conn
	select {
	case connA = <-connCh:
	case err := <-errCh:
		b.Fatal(err)
	case <-time.After(5 * time.Second):
		b.Fatal("timeout waiting for partner")
	}
	defer connA.Close()

	data := make([]byte, 1400)
	resp := make([]byte, 1400)

	b.SetBytes(1400 * 2)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := connB.Write(data); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(connA, resp); err != nil {
			b.Fatal(err)
		}
		if _, err := connA.Write(data); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(connB, resp); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkP2PRelay_ConnectHandshake(b *testing.B) {
	secret := []byte("bench-secret-key")
	relay := NewP2PRelay(&P2PRelayConfig{
		ListenAddr:   "127.0.0.1:0",
		Secret:       secret,
		MaxPeers:     4096,
		PeerTimeout:  30 * time.Second,
		MaxBandwidth: 1 << 30,
	})

	if err := relay.Start(); err != nil {
		b.Fatal(err)
	}
	defer relay.Stop()

	relay.mu.RLock()
	addr := relay.listener.Addr().String()
	relay.mu.RUnlock()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		peerA := NewP2PClient(addr, secret)
		if err := peerA.Register(ctx); err != nil {
			b.Fatal(err)
		}

		done := make(chan struct{})
		go func() {
			_, _ = peerA.WaitForPartner(ctx)
			close(done)
		}()

		peerB := NewP2PClient(addr, secret)
		connB, err := peerB.ConnectTo(ctx, peerA.PeerID())
		if err != nil {
			peerA.Close()
			b.Fatal(err)
		}

		<-done
		connB.Close()
		peerA.Close()
	}
}

func BenchmarkBuildRegisterMessage(b *testing.B) {
	secret := []byte("bench-secret")
	peerID := GeneratePeerID()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildRegisterMessage(peerID, secret)
	}
}

func BenchmarkBuildConnectMessage(b *testing.B) {
	secret := []byte("bench-secret")
	from := GeneratePeerID()
	to := GeneratePeerID()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildConnectMessage(from, to, secret)
	}
}
