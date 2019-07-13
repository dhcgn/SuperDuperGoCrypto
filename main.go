package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/cloudflare/circl/dh/x448"
	"io"
	"io/ioutil"
)

type User struct {
	Version int
	Sike KeyPair
	X448 KeyPair
}

type KeyPair struct {
	Public  []byte
	Private []byte
}

func main() {
	flagCreateKeyPair := flag.Bool("GenerateKeyPair", false, "a bool")
	flagCreatePublicKeyPair := flag.Bool("ExtractPublicKey", false, "a bool")

	flagCreateKeyAgreement := flag.Bool("CreateKeyAgreement", false, "a bool")
	flagCreateKeyAgreementPublicKeyFile := flag.String("PublicKeyFile", "undef", "a string")
	flagCreateKeyAgreementPrivateKeyFile := flag.String("PrivateKeyFile", "undef", "a string")

	flag.Parse()

	if *flagCreateKeyPair {
		user, _ := createUser()
		b, _ := json.MarshalIndent(user, "", "    ")

		if *flagCreateKeyAgreementPrivateKeyFile == "undef" {
			fmt.Println(string(b))
		}else{
			ioutil.WriteFile(*flagCreateKeyAgreementPrivateKeyFile, b, 0644)
		}
		return
	}

	if *flagCreatePublicKeyPair {
		user,_  := ReadUser(*flagCreateKeyAgreementPrivateKeyFile)

		user.Sike.Private = nil
		user.X448.Private = nil

		b, _ := json.MarshalIndent(user, "", "    ")
		if *flagCreateKeyAgreementPublicKeyFile == "undef" {
			fmt.Println(string(b))
		}else{
			ioutil.WriteFile(*flagCreateKeyAgreementPublicKeyFile, b, 0644)
		}
		return
	}

	if *flagCreateKeyAgreement {
		public,_  := ReadUser(*flagCreateKeyAgreementPublicKeyFile)
		private,_  := ReadUser(*flagCreateKeyAgreementPrivateKeyFile)

		sharedX448 := CreateKey(public.X448.Public, private.X448.Private)
		shared := CreateSharedKey(sharedX448)
		encoded := base64.StdEncoding.EncodeToString(shared)
		fmt.Println(encoded)

		return
	}

	alice, _ := createUser()
	bob, _ := createUser()

	SaveUserToDisk(alice, `C:\Temp\test\alice.json`)
	SaveUserToDisk(bob, `C:\Temp\test\bob.json`)

	// Alice create shared secret with bobs public key
	sharedSecretAlice, cipherText, _ := encapsulate(bob.Sike.Public)
	sharedSecretAlicex448 := CreateKey(alice.X448.Public, bob.X448.Private)

	sharedCombinedKey := CreateSharedKey(sharedSecretAlice, sharedSecretAlicex448)
	fmt.Println("sharedCombinedKey", sharedCombinedKey)

	/*
		fmt.Println("cipher", cipherText)
		fmt.Println("shared secret from Alice", sharedSecretAlice)
		fmt.Println("shared secret from Alice", sharedSecretAlicex448)
	*/
	// Bob decapsulate shared secret with his private key
	sharedSecretBob, _ := decapsulate(bob.Sike.Public, bob.Sike.Private, cipherText)
	sharedSecretBobx448 := CreateKey(bob.X448.Public, alice.X448.Private)

	sharedCombinedKey2 := CreateSharedKey(sharedSecretBob, sharedSecretBobx448)
	fmt.Println("sharedCombinedKey", sharedCombinedKey2)

	/*
		fmt.Println("shared secret from Bob  ", sharedSecretBob)
		fmt.Println("shared secret len in bit:", len(sharedSecretBob)*8)
		fmt.Println("shared secret from Bob  ", sharedSecretBobx448)
		fmt.Println("shared secret len in bit:", len(sharedSecretBobx448)*8)
	*/
}

func ReadUser(filePath string) (*User, error) {
	dat, _ := ioutil.ReadFile(filePath)
	var user User
	if err := json.Unmarshal(dat, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func CreateSharedKey(sharedKeys ...[]byte) (combinedKey []byte){
	hash := sha512.New()

	combinedKey = make([]byte, 512/8)
	for _, key := range sharedKeys {
		hash.Write(key)
		iteratedHash := hash.Sum(nil)
		combinedKey ,_= XORBytes(iteratedHash, combinedKey)
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

func CreateKey(public []byte, secret []byte) (sharedSecret []byte ) {
	var publicKey, privateKey, ahredSecretKey x448.Key

	copy(publicKey[:], public[:])
	copy(privateKey[:], secret[:])

	x448.Shared(&ahredSecretKey, &privateKey, &publicKey )

	return ahredSecretKey[:]
}

func decapsulate(publicKeyBytes []byte, privateKeyBytes []byte, cipherText []byte) (sharedSecret []byte, err error) {
	publicKey := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	err = publicKey.Import(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	var privateKey = sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
	err = privateKey.Import(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	var kem = sidh.NewSike751(rand.Reader)
	sharedSecret = make([]byte, kem.SharedSecretSize())

	err = kem.Decapsulate(sharedSecret, privateKey, publicKey, cipherText)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

func encapsulate(publicKeyBytes []byte) (sharedSecret []byte, cipherText []byte, err error) {
	publicKey := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	err = publicKey.Import(publicKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	var kem = sidh.NewSike751(rand.Reader)

	sharedSecret = make([]byte, kem.SharedSecretSize())
	cipherText = make([]byte, kem.CiphertextSize())

	err = kem.Encapsulate(cipherText, sharedSecret[:], publicKey)
	if err != nil {
		return nil, nil, err
	}

	return sharedSecret, cipherText, nil
}

func SaveUserToDisk(user *User, path string) (err error) {
	b, _ := json.MarshalIndent(user, "", "    ")
	err = ioutil.WriteFile(path, b, 0644)
	if err != nil {
		return err
	}
	return nil
}

func createUser() (user *User, err error) {

	privateKey := sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
	publicKey := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)

	var public, secret x448.Key
	_, _ = io.ReadFull(rand.Reader, secret[:])
	x448.KeyGen(&public, &secret)



	err = privateKey.Generate(rand.Reader)
	if err != nil {
		return nil, err
	}
	privateKey.GeneratePublicKey(publicKey)

	publicKeyBytes := make([]byte, publicKey.Size())
	privateKeyBytes := make([]byte, privateKey.Size())

	publicKey.Export(publicKeyBytes)
	privateKey.Export(privateKeyBytes)

	user = &User{
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
	return user, nil
}
