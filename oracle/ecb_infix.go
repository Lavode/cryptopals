package oracle

import (
	"crypto/rand"
	"fmt"

	"github.com/Lavode/cryptopals/cipher"
	"github.com/Lavode/cryptopals/padding"
)

// ECBInfix provides an oracle allowing for a chosen-message attack on AES-128
// in ECB mode.
//
// The user may specify a string which will be used as an infix between a fixed
// postfix, and a random (but statically chosen) prefix.
type ECBInfix struct {
	key          *[]byte
	Postfix      []byte
	PrefixLength int
	prefix       *[]byte
}

// Encrypt encrypts a message where the user-supplied message is used as an
// infix with AES in ECB mode.
//
// The exact message will be of the following form:
//   PAD(random prefix || user supplied message || static postfix)
//
// Where the random prefix is generated on the first oracle call, and reused
// subsequently. The static postfix is used as supplied by the user.
//
// The pad function aligns the message to the next multiple of the AES block
// size.
//
// The AES key is chosen randomly on the first oracle call, and reused
// subsequently.
func (or *ECBInfix) Encrypt(msg []byte) (ctxt cipher.AESCiphertext, err error) {
	if or.key == nil {
		key, err := cipher.NewKey()
		if err != nil {
			return ctxt, err
		}

		or.key = &key
	}

	if or.prefix == nil {
		prefix := make([]byte, or.PrefixLength)
		_, err = rand.Read(prefix)
		if err != nil {
			return ctxt, fmt.Errorf("Error generating random prefix: %v", err)
		}

		or.prefix = &prefix
	}

	prefixBytes := 0
	postfixBytes := len(or.Postfix)
	infixedMsg := make([]byte, prefixBytes+len(msg)+postfixBytes)

	copy(infixedMsg[prefixBytes:], msg)
	copy(infixedMsg[prefixBytes+len(msg):], or.Postfix)

	// Fill to next multiple of AES block size
	paddedMsg := padding.PKCS7Pad(infixedMsg, cipher.AESBlockSize)

	ecb := cipher.AESECB{Key: *or.key}
	rawCtxt, err := ecb.Encrypt(paddedMsg)
	if err != nil {
		return ctxt, err
	}
	ctxt.Bytes = rawCtxt

	return ctxt, nil
}
