package main

import (
	"testing"

	"github.com/cloudflare/circl/dh/sidh"
)

func Test_createKeyPairs(t *testing.T) {
	type args struct {
		sidhKeyVariant sidh.KeyVariant
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"KeyVariantSidhA", args{
			sidhKeyVariant: sidh.KeyVariantSidhA,
		}, false},
		{"KeyVariantSidhB", args{
			sidhKeyVariant: sidh.KeyVariantSidhB,
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, err := createKeyPairs(tt.args.sidhKeyVariant)
			if (err != nil) != tt.wantErr {
				t.Errorf("createKeyPairs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {

				if gotUser == nil {
					t.Errorf("createKeyPairs() - KeyPairs is nill %v", gotUser)
				}
			}
		})
	}
}
