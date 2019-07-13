package main

import (
	"crypto/rand"
	. "github.com/cloudflare/circl"
)

func main() {
	// Bob's key pair
	prvB := NewPrivateKey(Fp503, KeyVariantSike)
	pubB := NewPublicKey(Fp503, KeyVariantSike)

	// Generate private key
	prvB.Generate(rand.Reader)
	// Generate public key
	prvB.GeneratePublicKey(pubB)

	var publicKeyBytes = make([]array, pubB.Size())
	var privateKeyBytes = make([]array, prvB.Size())

	pubB.Export(publicKeyBytes)
	prvB.Export(privateKeyBytes)
}
