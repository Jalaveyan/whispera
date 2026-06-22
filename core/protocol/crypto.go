package protocol

import (
	"crypto/sha256"
	"io"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/crypto/hkdf"
)

type Keys struct {
	Auth     []byte
	Behavior []byte
}

var deriveKeysCache = func() *lru.Cache[[32]byte, *Keys] {
	c, _ := lru.New[[32]byte, *Keys](1024)
	return c
}()

func DeriveKeys(sharedSecret []byte) *Keys {
	cacheKey := sha256.Sum256(sharedSecret)
	if v, ok := deriveKeysCache.Get(cacheKey); ok {
		return v
	}

	derive := func(info string) []byte {
		r := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))
		k := make([]byte, 32)
		if _, err := io.ReadFull(r, k); err != nil {
			panic("whispera hkdf: " + err.Error())
		}
		return k
	}

	keys := &Keys{
		Auth:     derive("whispera-auth-v1"),
		Behavior: derive("whispera-behavior-v1"),
	}
	deriveKeysCache.Add(cacheKey, keys)
	return keys
}
