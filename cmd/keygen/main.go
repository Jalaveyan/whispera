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
	fromPriv := flag.String("from-priv", "", "when set with -mode x25519, derive pub from given priv hex32")
	flag.Parse()
	switch *mode {
	case "psk":
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatal(err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(key))
	case "x25519":
		if *fromPriv != "" {
			priv, err := hex.DecodeString(*fromPriv)
			if err != nil || len(priv) != 32 {
				log.Fatal("-from-priv must be hex32")
			}
			pub, err := curve25519.X25519(priv, curve25519.Basepoint)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("pub=%s\n", hex.EncodeToString(pub))
			return
		}
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err != nil {
			log.Fatal(err)
		}
		pub, err := curve25519.X25519(priv, curve25519.Basepoint)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("priv=%s\n", hex.EncodeToString(priv))
		fmt.Printf("pub=%s\n", hex.EncodeToString(pub))
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}
