package main

import (
	"crypto/rand"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
)

func decrypt(key []byte, cipher []byte, nonce []byte) (plain []byte) {
	usedKey := key[0:chacha20poly1305.KeySize]
	aead, err := chacha20poly1305.NewX(usedKey)

	if err != nil {
		log.Fatalln("Failed to instantiate XChaCha20-Poly1305:", err)
	}
	plaintext, err := aead.Open(nil, nonce, cipher, nil)
	if err != nil {
		log.Fatalln("Failed to decrypt or authenticate message:", err)
	}

	return plaintext
}

func encrypt(key []byte, plain []byte) (cipher []byte, nonce []byte) {
	usedKey := key[0:chacha20poly1305.KeySize]
	aead, _ := chacha20poly1305.NewX(usedKey)
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ciphertext := aead.Seal(nil, nonce, plain, nil)

	return ciphertext, nonce
}
