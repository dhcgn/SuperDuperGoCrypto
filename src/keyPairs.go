package main

import (
	"crypto/rand"
	"encoding/json"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/cloudflare/circl/dh/x448"
	"io"
	"io/ioutil"
)

func readKeyPairs(filePath string) (*KeyPairs, error) {
	dat, _ := ioutil.ReadFile(filePath)
	var keyPairs KeyPairs
	if err := json.Unmarshal(dat, &keyPairs); err != nil {
		return nil, err
	}
	return &keyPairs, nil
}

func createKeyPairs(sidhKeyVariant sidh.KeyVariant) (keyPairs *KeyPairs, err error) {
	// sidh
	privateKey := sidh.NewPrivateKey(sidhKeyId, sidhKeyVariant)
	publicKey := sidh.NewPublicKey(sidhKeyId, sidhKeyVariant)
	privateKey.Generate(rand.Reader)
	privateKey.GeneratePublicKey(publicKey)

	publicKeyBytes := make([]byte, publicKey.Size())
	privateKeyBytes := make([]byte, privateKey.Size())

	publicKey.Export(publicKeyBytes)
	privateKey.Export(privateKeyBytes)

	// x448

	var public, secret x448.Key
	_, _ = io.ReadFull(rand.Reader, secret[:])
	x448.KeyGen(&public, &secret)

	keyPairs = &KeyPairs{
		Version: 1,
		Sike: KeyPair{
			Public:  publicKeyBytes,
			Private: privateKeyBytes,
		},
		X448: KeyPair{
			Public:  public[:],
			Private: secret[:],
		},
	}
	return keyPairs, nil
}
