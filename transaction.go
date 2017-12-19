package core

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

// AddressSize size of account address (ed25519 public key size)
const AddressSize = 32

// SignatureSize size of signature (ed25519 signature size)
const SignatureSize = 32

// HashSize size of hash (BLAKE2 hash size)
const HashSize = 64

// Transaction represents a transaction in the whole DAG
type Transaction struct {
	From     []byte   // ed25519 public key of the sender
	To       []byte   // ed25519 public key of the receiver
	Amount   uint64   // amount of traffic, in killo-byte
	Nonce    uint64   // amount of transactions by the sender, except this one
	Parrents [][]byte // array of parrent hashes
}

// MarshalBinary marshal binary
func (tx Transaction) MarshalBinary() (data []byte, err error) {
	b := &bytes.Buffer{}
	b.Write(tx.From)
	b.Write(tx.To)
	binary.Write(b, binary.BigEndian, tx.Amount)
	binary.Write(b, binary.BigEndian, tx.Nonce)
	for _, h := range tx.Parrents {
		b.Write(h)
	}
	data = b.Bytes()
	return
}

// SignedTransaction a signed transaction
type SignedTransaction struct {
	Transaction
	Signature []byte
}

// MarshalBinary marshal binary
func (stx SignedTransaction) MarshalBinary() (data []byte, err error) {
	var txdata []byte
	if txdata, err = stx.Transaction.MarshalBinary(); err != nil {
		return
	}
	b := bytes.NewBuffer(txdata)
	b.Write(stx.Signature)
	data = b.Bytes()
	return
}

// ValidateSignature validate the signature
func (stx SignedTransaction) ValidateSignature() (err error) {
	var message []byte
	if message, err = stx.Transaction.MarshalBinary(); err != nil {
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(stx.From), message, stx.Signature) {
		err = errors.New("signature invalid")
		return
	}
	return
}

// HashedTransaction signed transaction with hash
type HashedTransaction struct {
	SignedTransaction
	Hash []byte
}

// ValidateHash validate the hash
func (htx HashedTransaction) ValidateHash() (err error) {
	var data []byte
	if data, err = htx.SignedTransaction.MarshalBinary(); err != nil {
		return
	}
	sum := blake2b.Sum256(data)
	if !bytes.Equal(sum[:], htx.Hash) {
		err = errors.New("hash invalid")
		return
	}
	return nil
}
