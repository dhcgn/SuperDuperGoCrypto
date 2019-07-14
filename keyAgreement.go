package main

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/cloudflare/circl/dh/x448"
)

func createKeyAgreementAndEphemeral(public *KeyPairs) (*KeyPairs, []byte) {
	privateEphemeral, _ := createKeyPairs(sidhKeyVariantB)
	sharedX448 := CreateSharedX448(public.X448.Public, privateEphemeral.X448.Private)
	sharedSidh := CreateSharedSidhFp751(public.Sike.Public, privateEphemeral.Sike.Private)
	// fmt.Println("sharedX448", base64.StdEncoding.EncodeToString(sharedX448))
	// fmt.Println("sharedSidh", base64.StdEncoding.EncodeToString(sharedSidh))
	shared := CreateSharedKey(sharedX448, sharedSidh)
	privateEphemeral.Sike.Private = nil
	privateEphemeral.X448.Private = nil
	return privateEphemeral, shared
}

func createKeyAgreement(ephemeral *KeyPairs, private *KeyPairs) ([]byte) {

	return nil
}

func CreateSharedKey(sharedKeys ...[]byte) (combinedKey []byte) {
	hash := sha512.New()

	combinedKey = make([]byte, 512/8)
	for _, key := range sharedKeys {
		hash.Write(key)
		iteratedHash := hash.Sum(nil)
		combinedKey, _ = XORBytes(iteratedHash, combinedKey)
	}
	return combinedKey
}

// XORBytes takes two byte slices and XORs them together, returning the final
// byte slice. It is an error to pass in two byte slices that do not have the
// same length.
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("length of byte slices is not equivalent: %d != %d", len(a), len(b))
	}

	buf := make([]byte, len(a))

	for i, _ := range a {
		buf[i] = a[i] ^ b[i]
	}

	return buf, nil
}

func CreateSharedX448(public []byte, secret []byte) (sharedSecret []byte) {
	var publicKey, privateKey, ahredSecretKey x448.Key

	copy(publicKey[:], public[:])
	copy(privateKey[:], secret[:])

	x448.Shared(&ahredSecretKey, &privateKey, &publicKey)

	return ahredSecretKey[:]
}

func CreateSharedSidhFp751(public []byte, private []byte) (sharedSecret []byte) {

	privateKey := sidh.NewPrivateKey(sidhKeyId, sidhKeyVariantB)
	e := privateKey.Generate(rand.Reader)
	if e != nil {
		panic("Can't generate private key")
	}

	publicKey := sidh.NewPublicKey(sidhKeyId, sidhKeyVariantA)
	e = publicKey.Import(public)
	if e != nil {
		panic("Can't import public key")
	}

	var ss [2 * 94]byte
	privateKey.DeriveSecret(ss[:], publicKey)

	return ss[:]
}

