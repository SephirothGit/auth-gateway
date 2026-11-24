package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func main() {
	out := "jwt_ed25519.pem"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		log.Fatal(err)
	}
	log.Printf("written %s", out)
}