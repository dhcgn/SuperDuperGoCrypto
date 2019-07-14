package main

import (
	"crypto/rand"
	"golang.org/x/crypto/chacha20poly1305"
)

func decrypt(ephemeral []byte, bytes []byte) []byte {
	return nil
}

func encrypt(key []byte, plain []byte) []byte {
	aead, _ := chacha20poly1305.NewX(key[0:chacha20poly1305.KeySize])
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ciphertext := aead.Seal(nil, nonce, plain, nil)
	return ciphertext
}

