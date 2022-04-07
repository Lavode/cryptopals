package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const aesBlockSize = 16

// AESECBEncrypt encrypts the message with the AES-128 block cipher in ECB
// mode.
//
// The length of the message must be a multiple of AES-128's blocksize of 16
// bytes. Apply a padding if it is not.
//
// The key must be exactly 16 bytes in size.
func AESECBEncrypt(msg, key []byte) ([]byte, error) {
	if len(msg)%aesBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Message must be a multiple of AES blocksize %d, but was %d",
			aesBlockSize,
			len(msg),
		)
	}

	aes, err := newAES(key)
	if err != nil {
		return []byte{}, err
	}

	ctxt := make([]byte, len(msg))
	for i := 0; i < len(msg)/aesBlockSize; i++ {
		blockStart := i * aesBlockSize
		aes.Encrypt(
			ctxt[blockStart:blockStart+aesBlockSize],
			msg[blockStart:blockStart+aesBlockSize],
		)
	}

	return ctxt, nil
}

// AESECBDecrypt decrypts the ciphertext with the AES-128 block cipher in ECB
// mode.
//
// The length of the ciphertet must be a multiple of AES-128's blocksize of 16
// bytes.
//
// The key must be exactly 16 bytes in size.
func AESECBDecrypt(ctxt, key []byte) ([]byte, error) {
	if len(ctxt)%aesBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Ciphertext must be a multiple of AES blocksize %d, but was %d",
			aesBlockSize,
			len(ctxt),
		)
	}

	aes, err := newAES(key)
	if err != nil {
		return []byte{}, err
	}

	msg := make([]byte, len(ctxt))
	for i := 0; i < len(ctxt)/aesBlockSize; i++ {
		blockStart := i * aesBlockSize
		aes.Decrypt(
			msg[blockStart:blockStart+aesBlockSize],
			ctxt[blockStart:blockStart+aesBlockSize],
		)
	}

	return msg, nil
}

func newAES(key []byte) (cipher.Block, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return aes, fmt.Errorf("Unable to instantiate AES: %v", err)
	}

	return aes, nil
}
