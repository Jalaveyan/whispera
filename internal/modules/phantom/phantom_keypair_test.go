package phantom

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateKeyPair_ValidX25519(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(priv) != 32 || len(pub) != 32 {
		t.Fatalf("key sizes: priv=%d pub=%d, want 32/32", len(priv), len(pub))
	}
	want, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519: %v", err)
	}
	if !bytes.Equal(pub, want) {
		t.Fatalf("public key does not match priv*basepoint")
	}
}

func TestGenerateKeyPair_ECDHSymmetry(t *testing.T) {
	aPriv, aPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen a: %v", err)
	}
	bPriv, bPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen b: %v", err)
	}

	s1, err := curve25519.X25519(aPriv, bPub)
	if err != nil {
		t.Fatalf("ecdh1: %v", err)
	}
	s2, err := curve25519.X25519(bPriv, aPub)
	if err != nil {
		t.Fatalf("ecdh2: %v", err)
	}

	if !bytes.Equal(s1, s2) {
		t.Fatalf("ECDH shared secrets differ")
	}
	if bytes.Equal(s1, make([]byte, 32)) {
		t.Fatalf("shared secret is all-zero (degenerate)")
	}
}
