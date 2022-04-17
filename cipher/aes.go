package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const aesBlockSize = 16

func newAES(key []byte) (cipher.Block, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return aes, fmt.Errorf("Unable to instantiate AES: %v", err)
	}

	return aes, nil
}
