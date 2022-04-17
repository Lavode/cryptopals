package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/Lavode/cryptopals/bitwise"
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

func AESCBCEncrypt(msg, key []byte, iv []byte) ([]byte, error) {
	if len(msg)%aesBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Ciphertext must be a multiple of AES blocksize %d, but was %d",
			aesBlockSize,
			len(msg),
		)
	}

	if len(iv) != aesBlockSize {
		return []byte{}, fmt.Errorf(
			"Expected IV of length %d, but got %d",
			aesBlockSize,
			len(iv),
		)
	}

	aes, err := newAES(key)
	if err != nil {
		return []byte{}, err
	}

	ctxtIV := make([]byte, len(msg)+aesBlockSize)
	copy(ctxtIV[0:aesBlockSize], iv)

	for i := 0; i < len(msg)/aesBlockSize; i++ {
		// Start of the current block in the plaintext slice.
		mBlockStart := i * aesBlockSize
		// Corresponding block in ciphertext + IV slice starts
		// aesBlockSize bytes later.
		cBlockStart := (i + 1) * aesBlockSize

		// m_{i} XOR c_{i-1}
		intermediate := bitwise.Xor(
			msg[mBlockStart:mBlockStart+aesBlockSize],
			ctxtIV[cBlockStart-aesBlockSize:cBlockStart],
		)

		// c_i = ENC(m_i XOR m_{i-1})
		aes.Encrypt(
			ctxtIV[cBlockStart:cBlockStart+aesBlockSize],
			intermediate,
		)

	}

	// Remove IV
	ctxt := ctxtIV[aesBlockSize:]

	return ctxt, nil
}

func AESCBCDecrypt(ctxt, key []byte, iv []byte) ([]byte, error) {
	if len(ctxt)%aesBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Ciphertext must be a multiple of AES blocksize %d, but was %d",
			aesBlockSize,
			len(ctxt),
		)
	}

	if len(iv) != aesBlockSize {
		return []byte{}, fmt.Errorf(
			"Expected IV of length %d, but got %d",
			aesBlockSize,
			len(iv),
		)
	}

	aes, err := newAES(key)
	if err != nil {
		return []byte{}, err
	}

	msg := make([]byte, len(ctxt))
	ctxtIV := make([]byte, len(ctxt)+aesBlockSize)
	copy(ctxtIV[0:aesBlockSize], iv)
	copy(ctxtIV[aesBlockSize:], ctxt)

	// We'll skip 'decryption' of the IV
	for i := 0; i < len(msg)/aesBlockSize; i++ {
		// Start of the current block in the plaintext slice.
		mBlockStart := i * aesBlockSize
		// Corresponding block in ciphertext + IV slice starts
		// aesBlockSize bytes later.
		cBlockStart := (i + 1) * aesBlockSize

		// m_i = DEC(c_i) XOR c_{i-1}
		aes.Decrypt(
			msg[mBlockStart:mBlockStart+aesBlockSize],
			ctxtIV[cBlockStart:cBlockStart+aesBlockSize],
		)

		copy(
			msg[mBlockStart:mBlockStart+aesBlockSize],
			bitwise.Xor(
				msg[mBlockStart:mBlockStart+aesBlockSize],
				ctxtIV[cBlockStart-aesBlockSize:cBlockStart],
			),
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
