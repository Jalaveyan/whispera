package dns

import (
	"errors"
	"net"
	"testing"
)

func TestBuildDNSMsgQType(t *testing.T) {
	msgA, _ := buildDNSMsg("example.com", dnsTypeA)
	msgAAAA, _ := buildDNSMsg("example.com", dnsTypeAAAA)

	qtypeOffset := len(msgA) - 4
	gotA := uint16(msgA[qtypeOffset])<<8 | uint16(msgA[qtypeOffset+1])
	if gotA != dnsTypeA {
		t.Fatalf("A query qtype = 0x%04x, want 0x%04x", gotA, dnsTypeA)
	}

	qtypeOffset = len(msgAAAA) - 4
	gotAAAA := uint16(msgAAAA[qtypeOffset])<<8 | uint16(msgAAAA[qtypeOffset+1])
	if gotAAAA != dnsTypeAAAA {
		t.Fatalf("AAAA query qtype = 0x%04x, want 0x%04x", gotAAAA, dnsTypeAAAA)
	}
}

// buildFakeResponse constructs a minimal wire-format DNS response with a
// single answer record pointing back at the question name via compression.
func buildFakeResponse(id [2]byte, rtype uint16, rdata []byte) []byte {
	resp := []byte{
		id[0], id[1],
		0x81, 0x80, // response, no error
		0x00, 0x01, // qdcount
		0x00, 0x01, // ancount
		0x00, 0x00,
		0x00, 0x00,
	}
	// question: 7example3com0, type A, class IN
	resp = append(resp, 7)
	resp = append(resp, "example"...)
	resp = append(resp, 3)
	resp = append(resp, "com"...)
	resp = append(resp, 0x00)
	resp = append(resp, 0x00, 0x01, 0x00, 0x01)

	// answer: name = pointer to offset 12, type, class IN, ttl, rdlength, rdata
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, byte(rtype>>8), byte(rtype))
	resp = append(resp, 0x00, 0x01) // class IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C) // ttl=60
	resp = append(resp, byte(len(rdata)>>8), byte(len(rdata)))
	resp = append(resp, rdata...)
	return resp
}

func TestParseDNSResponseAAAA(t *testing.T) {
	id := [2]byte{0x12, 0x34}
	want := net.ParseIP("2001:db8::1").To16()
	resp := buildFakeResponse(id, dnsTypeAAAA, want)

	ips, err := parseDNSResponse(resp, id)
	if err != nil {
		t.Fatalf("parseDNSResponse: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IP(want)) {
		t.Fatalf("got %v want %v", ips, want)
	}
}

func TestParseDNSResponseA(t *testing.T) {
	id := [2]byte{0x56, 0x78}
	want := net.IPv4(203, 0, 113, 9).To4()
	resp := buildFakeResponse(id, dnsTypeA, want)

	ips, err := parseDNSResponse(resp, id)
	if err != nil {
		t.Fatalf("parseDNSResponse: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IP(want)) {
		t.Fatalf("got %v want %v", ips, want)
	}
}

func TestMergeDualStackCombinesBothFamilies(t *testing.T) {
	v4 := net.IPv4(203, 0, 113, 9)
	v6 := net.ParseIP("2001:db8::1")

	ips, err := mergeDualStack(func(qtype uint16) ([]net.IP, error) {
		if qtype == dnsTypeA {
			return []net.IP{v4}, nil
		}
		return []net.IP{v6}, nil
	})
	if err != nil {
		t.Fatalf("mergeDualStack: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("got %d ips, want 2 (%v)", len(ips), ips)
	}
}

func TestMergeDualStackSucceedsIfOneFamilyFails(t *testing.T) {
	v4 := net.IPv4(203, 0, 113, 9)

	ips, err := mergeDualStack(func(qtype uint16) ([]net.IP, error) {
		if qtype == dnsTypeA {
			return []net.IP{v4}, nil
		}
		return nil, errors.New("no AAAA record")
	})
	if err != nil {
		t.Fatalf("mergeDualStack: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(v4) {
		t.Fatalf("got %v want [%v]", ips, v4)
	}
}

func TestMergeDualStackFailsIfBothFamiliesFail(t *testing.T) {
	_, err := mergeDualStack(func(qtype uint16) ([]net.IP, error) {
		return nil, errors.New("no records")
	})
	if err == nil {
		t.Fatal("expected error when both families fail")
	}
}
