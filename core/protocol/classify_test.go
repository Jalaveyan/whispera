package protocol

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func rawClientHello(t *testing.T, id utls.ClientHelloID) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	uc := utls.UClient(c1, &utls.Config{ServerName: "example.com"}, id)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Skipf("BuildHandshakeState %s: %v", id.Client, err)
	}
	if uc.HandshakeState.Hello == nil || len(uc.HandshakeState.Hello.Raw) == 0 {
		t.Skipf("no marshaled ClientHello for %s", id.Client)
	}
	return uc.HandshakeState.Hello.Raw
}

func TestClassifyClientHello(t *testing.T) {
	cases := []struct {
		id   utls.ClientHelloID
		want browserKind
	}{
		{utls.HelloChrome_133, kindChromium},
		{utls.HelloFirefox_148, kindFirefox},
		{utls.HelloSafari_16_0, kindSafari},
	}
	for _, c := range cases {
		raw := rawClientHello(t, c.id)
		if got := classifyClientHello(raw); got != c.want {
			t.Errorf("classifyClientHello(%s) = %d, want %d", c.id.Client, got, c.want)
		}
	}
}

func TestClassifyClientHelloMalformed(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, {0x16, 0x03}, {0x01, 0x00, 0x00}} {
		if got := classifyClientHello(raw); got != kindChromium {
			t.Errorf("classifyClientHello(% x) = %d, want default kindChromium", raw, got)
		}
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false, want true", v)
		}
	}
	for _, v := range []uint16{0x0000, 0x1301, 0x001c, 0x4469, 0x0a0b} {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true, want false", v)
		}
	}
}
