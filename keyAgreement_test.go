package main

import (
	"encoding/json"
	"github.com/cloudflare/circl/dh/sidh"
	"reflect"
	"testing"
)

const AlicePrivateKeyPair  = `{
    "Version": 1,
    "Sike": {
        "Public": "AlJAyUzW0vvmsuXj97ZWJK9Rq+0aA7xL7yRXii9p2OZKVIhWzAS+5VgC9B165sbMdttQ5dt4jsmgx22wbOftdBsF74z3nvOgmnSC74682b7C9qfyepbVfYImTn1XVvB3nYRwp/RXWDnodxXZhne8ftcMpZXoe4eYWSHv6DNCbjjonDUCZk3IgnwibgxY5Z7eH3Io45VswuU+xtvR2wuw0hO2+t0hlcRx+hz768wtqrcB/B0O6xkstzTU9ki1Sq+UjFUBJSl6kLJTqgRPCuk2TyWgSe78SnLV3dhirzTeSfSAkj5Z9TLRIG1BinFc+QTl4zD9YdUdMoNTxHXL0vLNLGgklnTcxvlUwiia54Aq57VcFZ1DCKQUaTlQKO8D23hRVUC2586IdFjr+QbXnV1knKUST3D2ZvUI/yfJwM14LFa/oLXS4MYsjegCPB59GmKd8dAZpTixVWipQe5SoQeSaGilQSFSYwYtCmOZ4g5kFbWv1f5UjO3IKPCMcV2Z0wTFTAtM5A5nf0Pld/Bwy9xYd0J2zDwdkyUNdw7Rjuf9XVwkUVOOzed/WhZ/OxnM59x+7Hkpl8/FwVczo5o9LD1VQ1QscwdEKqv9SCZPRqz7mKZn2621AACG/GT8bCH0O1I1ObA3tvuCwgkRPFI2lbk+Gu5qkhPbwqM3PMOh5IdgiOLqXqSdOaOqAVxZ8i0+YXBLJ6p4F5D+t2Luf7EqZ0jmw/h8iLNHtdK3b2EweljWt3+GZWkt",
        "Private": "5gqfYwHmTP4YjgIXmKIovn7VdUBxyjKDZqXdnQNSaohSrbMwiHr9sz8q1YKbvg8="
    },
    "X448": {
        "Public": "Lr4B5Pzn1+pN1qwJjP+lysEOUSb+CVsxu9Al7VeFru6Pncyo52/hA+eNf+f5xnDCmDFOjusRbZU=",
        "Private": "Zp+DGzRBJUoVfnhc3H+pgnhtxCRs7MMWTiYNRvyAMv9BEhvBcMKpuj7jbOD4Trfuu0LGD3arpiQ="
    }
}`

const BobPrivateKeyPair  = `{
    "Version": 1,
    "Sike": {
        "Public": "usI9Wh/NBuheHDIiHDjLaviOlWtz8APBZUp2PudMQVaSSeMyWgAbI/MZZLweA5aeGZF/URXqGBrzfYXZqqe5Wa7wM+RRTklwSDRIO7G9046YS7kMj6OfY6jkfLqJVvwc4W072oUcuuROKEEncwdAb0CDsdh8ChcOvC6lfvgRqN7naMMbAQzXVVmcNwGYMfX1kYSvhpVAPb3nNPHQOHiUMlkY8i9oJ6iqbIoGnSg35hETmWrtMXzI3zrx6UFZephVjJGmHDjH05bfVP2k0BwDEN76DPQ5VZf+sIOiZiC4Hf3qngen95Vq1hszXMWEMf+Ds0jN/YZyiYo204Vuh4WAde7DH2TTkji3uFu2nv+c/KZIdwrBGeej4u8frpcTBYCGs3IUloVnltfhjsAas9uQ4bGCUyWOMRbkzBGWROTK5sTA75cE5how8BBYDdRD2rAJkRNp96ds04qDLsUj/XlW0CW+YO/JOFS/8g8uzIB6lzPQhK1ZRUZ6AOKRl8CGPyCYHpAYHJxUqQMHxFP49CxLLtRIRjz4mgkQc3Os94wsAkHqroste5k7GMqBzP1mAY57+hqgV4bzUZweNf2r2NhaL+5vaWvAP6R7rkfp3ysnqX/R8FLChzxhe59BdbDP3GGILRv85uL7u1cf2DqO+kuq46kPPPssNyQMIgZAWc8bc6h3O8/LdOFw/5wkbVvewhF22cnwvrFRD7ueMPkPpuDlYMocYt3Rf8BkLIMonad7klfx/Lsx",
        "Private": "LyNcm5puzAoytQhFbQllOu8ctU/dmoL9Jp8yxsWFg9Nkqxxgvw1cmzCVOawWvQo="
    },
    "X448": {
        "Public": "dy7OEUlhJhOB2Uv1wN+OmJ/UYrgWVZ0QKlhxx8WcGPZMiHKqJurkFj4jIGYCxPB6gQLzQqdGGiE=",
        "Private": "4Xnro8CQnJfU1NFmVx7akDFhMJoEzCH17XOkYfg3syzqfk018c8XTSRiHddyblVjNs2+YJNK0EE="
    }
}`

func getAlice() *KeyPairs {
	var keyPairs KeyPairs
	json.Unmarshal([]byte(AlicePrivateKeyPair), &keyPairs)
	return &keyPairs
}

func getBob() *KeyPairs {
	var keyPairs KeyPairs
	json.Unmarshal([]byte(BobPrivateKeyPair), &keyPairs)
	return &keyPairs
}

func Test_createKeyAgreementAndEphemeral(t *testing.T) {
	type args struct {
		public *KeyPairs
	}
	tests := []struct {
		name  string
		args  args
	}{
		{"Simple", args{
			public:getAlice(),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			createKeyAgreementAndEphemeral(tt.args.public)
		})
	}
}

func Test_createKeyAgreement(t *testing.T) {
	type args struct {
		ephemeral *KeyPairs
		private   *KeyPairs
	}

	ephemeral, _ := createKeyPairs(sidhKeyVariantB)

	tests := []struct {
		name string
		args args
		wantLen int
	}{
		{"Simple", args{private:getAlice(), ephemeral: ephemeral}, 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createKeyAgreement(tt.args.ephemeral, tt.args.private); len(got) != tt.wantLen {
				t.Errorf("createKeyAgreement() = %v, want %v", len(got), tt.wantLen)
			}
		})
	}
}

func TestCreateSharedKey(t *testing.T) {
	type args struct {
		sharedKeys [][]byte
	}
	tests := []struct {
		name            string
		args            args
		wantCombinedKey []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotCombinedKey := CreateSharedKey(tt.args.sharedKeys...); !reflect.DeepEqual(gotCombinedKey, tt.wantCombinedKey) {
				t.Errorf("CreateSharedKey() = %v, want %v", gotCombinedKey, tt.wantCombinedKey)
			}
		})
	}
}

func TestXORBytes(t *testing.T) {
	type args struct {
		a []byte
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := XORBytes(tt.args.a, tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("XORBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("XORBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateSharedX448(t *testing.T) {
	type args struct {
		public []byte
		secret []byte
	}
	tests := []struct {
		name             string
		args             args
		wantSharedSecret []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotSharedSecret := CreateSharedX448(tt.args.public, tt.args.secret); !reflect.DeepEqual(gotSharedSecret, tt.wantSharedSecret) {
				t.Errorf("CreateSharedX448() = %v, want %v", gotSharedSecret, tt.wantSharedSecret)
			}
		})
	}
}

func TestCreateSharedSidhFp751(t *testing.T) {
	type args struct {
		public  []byte
		publicKeyVariant  sidh.KeyVariant
		private []byte
		privateKeyVariant  sidh.KeyVariant
	}
	tests := []struct {
		name             string
		args             args
		wantSharedSecret []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotSharedSecret := CreateSharedSidhFp751(tt.args.public,tt.args.publicKeyVariant, tt.args.private, tt.args.privateKeyVariant); !reflect.DeepEqual(gotSharedSecret, tt.wantSharedSecret) {
				t.Errorf("CreateSharedSidhFp751() = %v, want %v", gotSharedSecret, tt.wantSharedSecret)
			}
		})
	}
}
