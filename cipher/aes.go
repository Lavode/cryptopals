package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// AESKeySize specifies the length of an AES-128 key in bytes.
//
// No other members of the AES family of functions are supported for now.
const AESKeySize = 16

// AESBlockSize specifies the length of an AES block in bytes.
const AESBlockSize = 16

func newAES(key []byte) (cipher.Block, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return aes, fmt.Errorf("Unable to instantiate AES: %v", err)
	}

	return aes, nil
}

// NewKey generates a new byte slice suitable for use with AES, using a
// cryptographially secure PRNG.
//
// The returned byte slice is also suitable for use as an IV of a block cipher
// mode of operation, although it may be overkill for those modes of operations
// which only require IVs to not be reused, but do not require them to be
// chosen at random.
//
// An error is returned if the underlying CSPRNG failed to provide a sufficient
// amount of random bytes.
func NewKey() (key []byte, err error) {
	key = make([]byte, AESKeySize)

	_, err = rand.Read(key)
	if err != nil {
		return key, fmt.Errorf("Error generating AES key: %v", err)
	}

	return key, nil
}
