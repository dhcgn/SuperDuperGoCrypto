package main

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func Test_encrypt_decrypt(t *testing.T) {
	key ,_:=base64.StdEncoding.DecodeString("AN+NlMXQaj0RNQdyepZrGMXkIruN5ieP3satu1LP3YU=")
	plain := []byte("Hello World!")

	cipher, nonce := encrypt(key, plain)
	decrypted := decrypt(key, cipher, nonce)

	if !reflect.DeepEqual(plain, decrypted){
		t.Errorf("decrypt() = %v, want %v", string(plain), string(decrypted))
	}

}

func Test_decrypt(t *testing.T) {
	type args struct {
		key    []byte
		cipher []byte
		nonce []byte
	}

	key ,_:=base64.StdEncoding.DecodeString("AN+NlMXQaj0RNQdyepZrGMXkIruN5ieP3satu1LP3YU=")
	cipher ,_:=base64.StdEncoding.DecodeString("2fSbZJw7T8MooYzpET7QRj9oiYc2VaMmW1RT")
	nonce ,_:=base64.StdEncoding.DecodeString("u0I0R6oH4/EDhKvKavalf9muOl/vdYuJ")

	plain := []byte("Hello World")

	tests := []struct {
		name      string
		args      args
		wantPlain []byte
	}{
		{"Simple", args{
			key:    key,
			cipher: cipher,
			nonce:nonce,
		},
			plain,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotPlain := decrypt(tt.args.key, tt.args.cipher, tt.args.nonce); !reflect.DeepEqual(gotPlain, tt.wantPlain) {
				t.Errorf("decrypt() = %v, want %v", gotPlain, tt.wantPlain)
			}
		})
	}
}

func Test_encrypt(t *testing.T) {
	type args struct {
		key   []byte
		plain []byte
	}

	randomKey ,_:=base64.StdEncoding.DecodeString("/YJGVz5Tz7Ldqe0MHPlvRCW6hnyh2o1R2DAs2vogGW4=")

	tests := []struct {
		name       string
		args       args
		wantCipherLength int
	}{
		{"Simple", args{
			key:   randomKey,
			plain: []byte("Hello World"),
		}, 27 },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotCipher ,_:= encrypt(tt.args.key, tt.args.plain); len(gotCipher) != tt.wantCipherLength {
				t.Errorf("encrypt() = %v, want %v", len(gotCipher), tt.wantCipherLength)
			}
		})
	}
}
