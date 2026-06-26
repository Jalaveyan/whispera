package protocol

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

func TestRTAddrRoundTrip(t *testing.T) {
	cases := []struct {
		host string
		port uint16
	}{
		{"203.0.113.7", 51820},
		{"2001:db8::1", 443},
		{"game.example.com", 27015},
	}
	for _, c := range cases {
		enc := encodeRTAddr(c.host, c.port)
		host, port, rest, ok := decodeRTAddr(append(enc, 0xAA, 0xBB))
		if !ok {
			t.Fatalf("decode failed for %s:%d", c.host, c.port)
		}
		if host != c.host || port != c.port {
			t.Fatalf("got %s:%d, want %s:%d", host, port, c.host, c.port)
		}
		if !bytes.Equal(rest, []byte{0xAA, 0xBB}) {
			t.Fatalf("rest mismatch: %v", rest)
		}
	}
}

func TestRTFECRecoversFullBlockWithLosses(t *testing.T) {
	sender := newRTFECSender()
	receiver := newRTFECReceiver()

	payloads := make([][]byte, rtFECK)
	for i := range payloads {
		payloads[i] = []byte(fmt.Sprintf("payload-%02d-game-datagram", i))
	}

	var allPkts [][]byte
	for _, p := range payloads {
		allPkts = append(allPkts, sender.encode(p)...)
	}
	if len(allPkts) != rtFECK+rtFECM {
		t.Fatalf("got %d packets, want %d", len(allPkts), rtFECK+rtFECM)
	}

	dropped := map[int]bool{1: true, 3: true, rtFECK: true, rtFECK + 1: true}
	if len(dropped) != rtFECM {
		t.Fatalf("test setup: dropped %d, want %d", len(dropped), rtFECM)
	}

	for i, pkt := range allPkts {
		if dropped[i] {
			continue
		}
		receiver.ingest(pkt)
	}

	var delivered [][]byte
	receiver.deliverBlock(0, func(p []byte) {
		delivered = append(delivered, append([]byte{}, p...))
	})

	if len(delivered) != rtFECK {
		t.Fatalf("recovered %d payloads, want %d", len(delivered), rtFECK)
	}
	for i, p := range delivered {
		if !bytes.Equal(p, payloads[i]) {
			t.Fatalf("payload %d mismatch: got %q want %q", i, p, payloads[i])
		}
	}
}

func TestRTFECTooManyLossesDoesNotRecover(t *testing.T) {
	sender := newRTFECSender()
	receiver := newRTFECReceiver()

	var allPkts [][]byte
	for i := 0; i < rtFECK; i++ {
		allPkts = append(allPkts, sender.encode([]byte(fmt.Sprintf("p%02d", i)))...)
	}

	dropped := map[int]bool{}
	for i := 0; i < rtFECM+1; i++ {
		dropped[i] = true
	}
	for i, pkt := range allPkts {
		if dropped[i] {
			continue
		}
		receiver.ingest(pkt)
	}

	var delivered [][]byte
	receiver.deliverBlock(0, func(p []byte) {
		delivered = append(delivered, p)
	})

	if len(delivered) != rtFECK-len(dropped) {
		t.Fatalf("delivered %d directly-received payloads, want %d", len(delivered), rtFECK-len(dropped))
	}
}

func TestRTFECRandomLossAcrossManyBlocks(t *testing.T) {
	blockSize := rtFECK + rtFECM
	rng := rand.New(rand.NewSource(1))

	const numBlocks = 2000
	const lossRate = 0.15

	sender := newRTFECSender()
	receiver := newRTFECReceiver()

	type expected struct {
		payload []byte
		dropped bool
	}

	recoverable := 0
	recoveredOK := 0

	for b := 0; b < numBlocks; b++ {
		var allPkts [][]byte
		exp := make([]expected, rtFECK)
		for i := 0; i < rtFECK; i++ {
			p := []byte(fmt.Sprintf("block-%04d-payload-%02d", b, i))
			exp[i] = expected{payload: p}
			allPkts = append(allPkts, sender.encode(p)...)
		}

		lost := 0
		var kept [][]byte
		for i, pkt := range allPkts {
			if rng.Float64() < lossRate {
				lost++
				if i < rtFECK {
					exp[i].dropped = true
				}
				continue
			}
			kept = append(kept, pkt)
		}

		for _, pkt := range kept {
			receiver.ingest(pkt)
		}

		blockStart := uint32(b * blockSize)
		var delivered [][]byte
		receiver.deliverBlock(blockStart, func(p []byte) {
			delivered = append(delivered, append([]byte{}, p...))
		})

		if lost <= rtFECM {
			recoverable++
			ok := len(delivered) == rtFECK
			if !ok {
				t.Errorf("block %d: delivered %d payloads, want %d", b, len(delivered), rtFECK)
			}
			for i := 0; ok && i < rtFECK; i++ {
				if !bytes.Equal(delivered[i], exp[i].payload) {
					ok = false
					t.Errorf("block %d data %d: payload mismatch: got %q want %q", b, i, delivered[i], exp[i].payload)
				}
			}
			if ok {
				recoveredOK++
			}
		}
	}

	rate := float64(recoveredOK) / float64(recoverable) * 100
	t.Logf("blocks within FEC tolerance (loss<=%d/%d): %d/%d, correctly recovered: %d (%.1f%%)",
		rtFECM, blockSize, recoverable, numBlocks, recoveredOK, rate)

	if recoveredOK != recoverable {
		t.Fatalf("expected all %d in-tolerance blocks to recover, got %d (%.1f%%)", recoverable, recoveredOK, rate)
	}
}

func TestRTFECOversizedPayloadSentRaw(t *testing.T) {
	sender := newRTFECSender()
	receiver := newRTFECReceiver()

	big := bytes.Repeat([]byte{0x55}, rtDatagramMaxProtected+50)
	pkts := sender.encode(big)
	if len(pkts) != 1 || pkts[0][0] != rtMarkerRaw {
		t.Fatalf("expected single raw packet, got %d packets", len(pkts))
	}

	var delivered []byte
	processIncomingRTDatagram(pkts[0], receiver, func(p []byte) { delivered = p })
	if !bytes.Equal(delivered, big) {
		t.Fatal("raw payload mismatch")
	}
}
