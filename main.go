package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudflare/circl/dh/sidh"
	"io/ioutil"
)

type Cargo struct {
	Version    int
	Ephemeral  KeyPairs
	CipherText []byte
}

type KeyPairs struct {
	Version int
	Sike KeyPair
	X448 KeyPair
}

type KeyPair struct {
	Public  []byte
	Private []byte
}

const(
	sidhKeyVariantA = sidh.KeyVariantSidhA
	sidhKeyVariantB  = sidh.KeyVariantSidhB
	sidhKeyId       = sidh.Fp751
)

func main() {
	flagCreateKeyPair := flag.Bool("GenerateKeyPair", false, "a bool")
	flagCreatePublicKeyPair := flag.Bool("ExtractPublicKey", false, "a bool")

	flagCreateKeyAgreement := flag.Bool("CreateKeyAgreement", false, "a bool")
	flagCreateKeyAgreementPublicKeyFile := flag.String("PublicKeyFile", "undef", "a string")
	flagCreateKeyAgreementPrivateKeyFile := flag.String("PrivateKeyFile", "undef", "a string")

	flagEncrypt := flag.Bool("Encrypt", false, "a bool")
	flagDecrypt := flag.Bool("Decrypt", false, "a bool")

	flagCipherFile := flag.String("CipherFile", "undef", "a string")
	flagPlainFile := flag.String("PlainFile", "undef", "a string")

	flag.Parse()

	if *flagCreateKeyPair {
		user, _ := createKeyPairs(sidhKeyVariantA)
		b, _ := json.MarshalIndent(user, "", "    ")

		if *flagCreateKeyAgreementPrivateKeyFile == "undef" {
			fmt.Println(string(b))
		}else{
			ioutil.WriteFile(*flagCreateKeyAgreementPrivateKeyFile, b, 0644)
		}
		return
	}

	if *flagCreatePublicKeyPair {
		user,_  := readKeyPairs(*flagCreateKeyAgreementPrivateKeyFile)

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
		public,_  := readKeyPairs(*flagCreateKeyAgreementPublicKeyFile)
		ephemeral, encoded := createKeyAgreementAndEphemeral(public)

		b, _ := json.MarshalIndent(ephemeral, "", "    ")
		fmt.Println(base64.StdEncoding.EncodeToString(encoded))
		fmt.Println(string(b))

		return
	}

	if *flagEncrypt {
		public,_  := readKeyPairs(*flagCreateKeyAgreementPublicKeyFile)
		ephemeral, sharedSecret := createKeyAgreementAndEphemeral(public)

		plain, _ := ioutil.ReadFile(*flagPlainFile)
		cipher := encrypt(sharedSecret, plain)

		cargo := Cargo{
			Version:    0,
			Ephemeral:  *ephemeral,
			CipherText: cipher,
		}

		b, _ := json.MarshalIndent(cargo, "", "    ")
		ioutil.WriteFile(*flagCipherFile, b, 0644)
	}

	if *flagDecrypt {
		private,_  := readKeyPairs(*flagCreateKeyAgreementPrivateKeyFile)

		cipherData, _ := ioutil.ReadFile(*flagCipherFile)
		var cargo Cargo
		json.Unmarshal(cipherData, &cargo)

		sharedSecret := createKeyAgreement(&cargo.Ephemeral, private)
		plain := decrypt(sharedSecret, cipherData)
		ioutil.WriteFile(*flagCipherFile, plain, 0644)
	}

}