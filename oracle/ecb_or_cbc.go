package oracle

import (
	"fmt"
	"math/rand"

	"github.com/Lavode/cryptopals/cipher"
	"github.com/Lavode/cryptopals/padding"
)

// ECBOrCBC provides an oracle which encrypts a given message in either ECB or
// CBC mode.
type ECBOrCBC struct {
}

// Encrypt encrypts the given message in either ECB or CBC mode with a random
// key.
//
// When doing so it also adds a small (5 - 10 bytes) amount of random data
// before and after the provided message before encryption. The message will
// then be padded to the next multiple of the block size using PKCS#7 padding.
//
// The key (and IV, in case of CBC) are chosen at random every invocation.
//
// Every invocation has a chance of 50% of using either ECB or CBC.
func (or *ECBOrCBC) Encrypt(msg []byte) (ctxt cipher.AESCiphertext, err error, wasECB bool) {
	key, err := cipher.NewKey()
	if err != nil {
		return ctxt, err, wasECB
	}

	// [0, 6) => [5, 11)
	prefixBytes := rand.Intn(6) + 5
	postfixBytes := rand.Intn(6) + 5

	prefixedMsg := make([]byte, len(msg)+prefixBytes+postfixBytes)

	// This is not a CSPRNG, but good enough for the purpose of this
	// exercise.
	// Fill with random prefix
	_, err = rand.Read(prefixedMsg[:prefixBytes])
	if err != nil {
		return ctxt, fmt.Errorf("Error padding message with random bytes: %v", err), wasECB
	}
	// Fill with random postfix
	_, err = rand.Read(prefixedMsg[prefixBytes+len(msg):])
	if err != nil {
		return ctxt, fmt.Errorf("Error padding message with random bytes: %v", err), wasECB
	}

	// Fill to next multiple of AES block size
	paddedMsg := padding.PKCS7Pad(prefixedMsg, cipher.AESBlockSize)

	wasECB = rand.Intn(2) == 0
	if wasECB {
		ecb := cipher.AESECB{Key: key}

		rawCtxt, err := ecb.Encrypt(paddedMsg)
		if err != nil {
			return ctxt, err, wasECB
		}
		ctxt.Bytes = rawCtxt
	} else {
		iv, err := cipher.NewKey()
		if err != nil {
			return ctxt, err, wasECB
		}

		cbc := cipher.AESCBC{Key: key, IV: iv}

		rawCtxt, err := cbc.Encrypt(paddedMsg)
		if err != nil {
			return ctxt, err, wasECB
		}
		ctxt.Bytes = rawCtxt
	}

	return ctxt, nil, wasECB
}
