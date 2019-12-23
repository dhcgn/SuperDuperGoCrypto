package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
)

func decrypt(key []byte, cipher []byte, nonce []byte) (plain []byte) {
	usedKey := key[0:chacha20poly1305.KeySize]
	fmt.Println("Key: ", base64.StdEncoding.EncodeToString(usedKey))
	fmt.Println("Nonce: ", base64.StdEncoding.EncodeToString(nonce))
	aead, err := chacha20poly1305.NewX(usedKey)

	fmt.Println("ciphertext: ", base64.StdEncoding.EncodeToString(cipher))

	if err != nil {
		log.Fatalln("Failed to instantiate XChaCha20-Poly1305:", err)
	}
	plaintext, err := aead.Open(nil, nonce, cipher, nil)
	if err != nil {
		log.Fatalln("Failed to decrypt or authenticate message:", err)
	}

	fmt.Println("plaintext: ", base64.StdEncoding.EncodeToString(plaintext), "base64")
	fmt.Println("plaintext: ", string(plaintext), "utf8")

	return plaintext
}

func encrypt(key []byte, plain []byte) ( cipher []byte, nonce []byte  ) {
	usedKey := key[0:chacha20poly1305.KeySize]
	fmt.Println("Key: ", base64.StdEncoding.EncodeToString(usedKey))
	aead, _ := chacha20poly1305.NewX(usedKey)
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	fmt.Println("Nonce: ", base64.StdEncoding.EncodeToString(nonce))
	ciphertext := aead.Seal(nil, nonce, plain, nil)
	fmt.Println("ciphertext: ", base64.StdEncoding.EncodeToString(ciphertext))
	return ciphertext, nonce
}
