package crypto

import (
	"bytes"
	"testing"
)

func newTestProvider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestDeriveKeys_ClientServerMirror(t *testing.T) {
	p := newTestProvider(t)
	seed := bytes.Repeat([]byte{0x5A}, SaltSize)

	cSend, cRecv, err := p.DeriveKeys(seed, false)
	if err != nil {
		t.Fatalf("client DeriveKeys: %v", err)
	}
	sSend, sRecv, err := p.DeriveKeys(seed, true)
	if err != nil {
		t.Fatalf("server DeriveKeys: %v", err)
	}

	if !bytes.Equal(cSend, sRecv) {
		t.Fatalf("client send key != server recv key (mirror broken)")
	}
	if !bytes.Equal(cRecv, sSend) {
		t.Fatalf("client recv key != server send key (mirror broken)")
	}
	if bytes.Equal(cSend, cRecv) {
		t.Fatalf("send and recv keys identical — directions not separated")
	}
}

func TestDeriveKeys_Deterministic(t *testing.T) {
	p := newTestProvider(t)
	seed := bytes.Repeat([]byte{0x11}, SaltSize)
	s1, r1, _ := p.DeriveKeys(seed, false)
	s2, r2, _ := p.DeriveKeys(seed, false)
	if !bytes.Equal(s1, s2) || !bytes.Equal(r1, r2) {
		t.Fatalf("DeriveKeys not deterministic for same seed")
	}
}

func TestDeriveKeys_ShortSeedRejected(t *testing.T) {
	p := newTestProvider(t)
	if _, _, err := p.DeriveKeys(make([]byte, SaltSize-1), false); err == nil {
		t.Fatalf("expected error on short seed")
	}
}

func TestAEAD_EndToEndRoundTrip(t *testing.T) {
	p := newTestProvider(t)
	seed := bytes.Repeat([]byte{0x7C}, SaltSize)

	cSend, cRecv, _ := p.DeriveKeys(seed, false)
	sSend, sRecv, _ := p.DeriveKeys(seed, true)

	client, err := p.NewAEADState(cSend, cRecv)
	if err != nil {
		t.Fatalf("client AEADState: %v", err)
	}
	server, err := p.NewAEADState(sSend, sRecv)
	if err != nil {
		t.Fatalf("server AEADState: %v", err)
	}

	const seq = uint32(42)
	aad := []byte("header")
	pt := []byte("the quick brown fox")

	ct, err := client.Encrypt(seq, aad, pt)
	if err != nil {
		t.Fatalf("client Encrypt: %v", err)
	}
	got, err := server.Decrypt(seq, aad, ct)
	if err != nil {
		t.Fatalf("server Decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("c->s round-trip mismatch: got %q want %q", got, pt)
	}

	ct2, err := server.Encrypt(seq, aad, pt)
	if err != nil {
		t.Fatalf("server Encrypt: %v", err)
	}
	got2, err := client.Decrypt(seq, aad, ct2)
	if err != nil {
		t.Fatalf("client Decrypt: %v", err)
	}
	if !bytes.Equal(got2, pt) {
		t.Fatalf("s->c round-trip mismatch")
	}
}

func TestAEAD_TamperDetected(t *testing.T) {
	p := newTestProvider(t)
	seed := bytes.Repeat([]byte{0x3E}, SaltSize)
	cSend, cRecv, _ := p.DeriveKeys(seed, false)
	sSend, sRecv, _ := p.DeriveKeys(seed, true)
	client, _ := p.NewAEADState(cSend, cRecv)
	server, _ := p.NewAEADState(sSend, sRecv)

	const seq = uint32(7)
	aad := []byte("aad")
	pt := []byte("secret payload")
	ct, _ := client.Encrypt(seq, aad, pt)

	bad := append([]byte(nil), ct...)
	bad[0] ^= 0xFF
	if _, err := server.Decrypt(seq, aad, bad); err == nil {
		t.Fatalf("tampered ciphertext accepted")
	}
	if _, err := server.Decrypt(seq+1, aad, ct); err == nil {
		t.Fatalf("wrong seq accepted")
	}
	if _, err := server.Decrypt(seq, []byte("other"), ct); err == nil {
		t.Fatalf("wrong aad accepted")
	}
}

func TestAEAD_BothCiphers(t *testing.T) {
	for _, c := range []CipherType{CipherChaCha20Poly1305, CipherAESGCM} {
		p, err := New(&Config{DefaultCipher: c, KeyPoolSize: 1})
		if err != nil {
			t.Fatalf("New(%s): %v", c, err)
		}
		seed := bytes.Repeat([]byte{0x22}, SaltSize)
		cSend, cRecv, _ := p.DeriveKeys(seed, false)
		sSend, sRecv, _ := p.DeriveKeys(seed, true)
		client, _ := p.NewAEADState(cSend, cRecv)
		server, _ := p.NewAEADState(sSend, sRecv)
		pt := []byte("cipher check")
		ct, err := client.Encrypt(1, nil, pt)
		if err != nil {
			t.Fatalf("Encrypt(%s): %v", c, err)
		}
		got, err := server.Decrypt(1, nil, ct)
		if err != nil {
			t.Fatalf("Decrypt(%s): %v", c, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round-trip mismatch for cipher %s", c)
		}
	}
}
