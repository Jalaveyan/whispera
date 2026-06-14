package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"golang.org/x/crypto/curve25519"
)

func main() {
	mode := flag.String("mode", "psk", "psk|x25519")
	privateKey := flag.String("privateKey", "", "when set with -mode x25519, derive publicKey from given privateKey hex32")
	flag.Parse()
	switch *mode {
	case "psk":
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatal(err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(key))
	case "x25519":
		if *privateKey != "" {
			private, err := hex.DecodeString(*privateKey)
			if err != nil || len(private) != 32 {
				log.Fatal("-privateKey must be hex32")
			}
			pub, err := curve25519.X25519(private, curve25519.Basepoint)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("pub=%s\n", hex.EncodeToString(pub))
			return
		}
		private := make([]byte, 32)
		if _, err := rand.Read(private); err != nil {
			log.Fatal(err)
		}
		public, err := curve25519.X25519(private, curve25519.Basepoint)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("privateKey=%s\n", hex.EncodeToString(private))
		fmt.Printf("publicKey=%s\n", hex.EncodeToString(public))
	default:
		log.Fatalf("unknown: %s", *mode)
	}
}
