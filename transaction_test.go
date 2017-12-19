package core

import (
	"crypto/rand"
	"reflect"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestSignedTransaction_ValidateSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tx := Transaction{
		From:     []byte(pub),
		To:       []byte{0x07, 0x08},
		Amount:   1,
		Nonce:    2,
		Parrents: [][]byte{[]byte{0x03, 0x07}, []byte{0x11, 0x23}},
	}
	data, _ := tx.MarshalBinary()
	sig := ed25519.Sign(priv, data)
	type fields struct {
		Transaction Transaction
		Signature   []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{name: "default",
			fields: fields{
				Transaction: tx,
				Signature:   sig,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stx := SignedTransaction{
				Transaction: tt.fields.Transaction,
				Signature:   tt.fields.Signature,
			}
			if err := stx.ValidateSignature(); (err != nil) != tt.wantErr {
				t.Errorf("SignedTransaction.ValidateSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTransaction_MarshalBinary(t *testing.T) {
	type fields struct {
		From     []byte
		To       []byte
		Amount   uint64
		Nonce    uint64
		Parrents [][]byte
	}
	tests := []struct {
		name     string
		fields   fields
		wantData []byte
		wantErr  bool
	}{
		{
			name: "default",
			fields: fields{
				From:     []byte{0x05, 0x06},
				To:       []byte{0x07, 0x08},
				Amount:   1,
				Nonce:    2,
				Parrents: [][]byte{[]byte{0x03, 0x07}, []byte{0x11, 0x23}},
			},
			wantData: []byte{0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x07, 0x11, 0x23},
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := Transaction{
				From:     tt.fields.From,
				To:       tt.fields.To,
				Amount:   tt.fields.Amount,
				Nonce:    tt.fields.Nonce,
				Parrents: tt.fields.Parrents,
			}
			gotData, err := tx.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("Transaction.MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotData, tt.wantData) {
				t.Errorf("Transaction.MarshalBinary() = %v, want %v", gotData, tt.wantData)
			}
		})
	}
}

func TestSignedTransaction_MarshalBinary(t *testing.T) {
	type fields struct {
		Transaction Transaction
		Signature   []byte
	}
	tests := []struct {
		name     string
		fields   fields
		wantData []byte
		wantErr  bool
	}{
		{
			name: "default",
			fields: fields{
				Transaction: Transaction{
					From:     []byte{0x05, 0x06},
					To:       []byte{0x07, 0x08},
					Amount:   1,
					Nonce:    2,
					Parrents: [][]byte{[]byte{0x03, 0x07}, []byte{0x11, 0x23}},
				},
				Signature: []byte{0x11, 0x98},
			},
			wantData: []byte{0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x07, 0x11, 0x23, 0x11, 0x98},
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stx := SignedTransaction{
				Transaction: tt.fields.Transaction,
				Signature:   tt.fields.Signature,
			}
			gotData, err := stx.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("SignedTransaction.MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotData, tt.wantData) {
				t.Errorf("SignedTransaction.MarshalBinary() = %v, want %v", gotData, tt.wantData)
			}
		})
	}
}

func TestHashedTransaction_ValidateHash(t *testing.T) {
	type fields struct {
		SignedTransaction SignedTransaction
		Hash              []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "default",
			fields: fields{
				SignedTransaction: SignedTransaction{
					Transaction: Transaction{
						From:     []byte{0x05, 0x06},
						To:       []byte{0x07, 0x08},
						Amount:   1,
						Nonce:    2,
						Parrents: [][]byte{[]byte{0x03, 0x07}, []byte{0x11, 0x23}},
					},
					Signature: []byte{0x11, 0x98},
				},
				Hash: []byte{0x15, 0xa6, 0xab, 0xb3, 0x04, 0xee, 0x37, 0x71, 0x5c, 0xad, 0xf9, 0x98, 0x9a, 0x1b, 0xde, 0x3d, 0x7e, 0xc7, 0xcd, 0x55, 0xa2, 0x13, 0x93, 0xc4, 0x54, 0xe7, 0x7a, 0xe8, 0xf1, 0x9b, 0x5e, 0x6a},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			htx := HashedTransaction{
				SignedTransaction: tt.fields.SignedTransaction,
				Hash:              tt.fields.Hash,
			}
			if err := htx.ValidateHash(); (err != nil) != tt.wantErr {
				t.Errorf("HashedTransaction.ValidateHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
