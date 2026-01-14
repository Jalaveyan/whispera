package main

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func main() {
	privateKeyHex := "0c728faebc9f9b327da53d7eb0b04f608d779b98958aad76f1fa3fe9bcc68eed"
	privateKey, _ := hex.DecodeString(privateKeyHex)
	publicKey, _ := curve25519.X25519(privateKey, curve25519.Basepoint)
	fmt.Printf("Public Key: %x\n", publicKey)
}
