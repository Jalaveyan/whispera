package protocol

import (
	"bytes"
	"testing"
)

func TestQUICVarintRoundTrip(t *testing.T) {
	values := []uint64{0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903}
	for _, v := range values {
		b := quicVarintAppend(nil, v)
		got, n, err := quicVarintParse(b)
		if err != nil {
			t.Fatalf("parse(%d): %v", v, err)
		}
		if n != len(b) {
			t.Fatalf("parse(%d): consumed %d, want %d", v, n, len(b))
		}
		if got != v {
			t.Fatalf("parse(%d): got %d", v, got)
		}
	}
}

func TestQUICCamoProbeRoundTrip(t *testing.T) {
	camoKey := deriveCamoKey(bytes.Repeat([]byte{0x42}, 32))
	if camoKey == nil {
		t.Fatal("deriveCamoKey returned nil")
	}

	probe, err := buildQUICCamoProbe(camoKey, "example.com")
	if err != nil {
		t.Fatalf("buildQUICCamoProbe: %v", err)
	}
	if len(probe) < quicMinInitialPacket {
		t.Fatalf("probe packet too short: %d bytes, want >= %d", len(probe), quicMinInitialPacket)
	}

	parsed, err := parseQUICInitialClientHello(probe)
	if err != nil {
		t.Fatalf("parseQUICInitialClientHello: %v", err)
	}
	if parsed.sni != "example.com" {
		t.Fatalf("sni = %q, want example.com", parsed.sni)
	}
	if len(parsed.random) != 32 {
		t.Fatalf("random len = %d, want 32", len(parsed.random))
	}
	if len(parsed.keyShare) == 0 {
		t.Fatal("keyShare empty")
	}

	if !camoMarkerMatches([][]byte{camoKey}, parsed.random, parsed.keyShare) {
		t.Fatal("camoMarkerMatches: expected match with correct key")
	}

	wrongKey := deriveCamoKey(bytes.Repeat([]byte{0x99}, 32))
	if camoMarkerMatches([][]byte{wrongKey}, parsed.random, parsed.keyShare) {
		t.Fatal("camoMarkerMatches: unexpected match with wrong key")
	}
}

func TestQUICCamoProbeGarbageRejected(t *testing.T) {
	garbage := bytes.Repeat([]byte{0xAA}, 1200)
	if _, err := parseQUICInitialClientHello(garbage); err == nil {
		t.Fatal("expected error parsing garbage as quic initial")
	}
}
