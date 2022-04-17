package cipher

import (
	"fmt"

	"github.com/Lavode/cryptopals/bitwise"
)

// AESCBC encapsulates an instance of the AES-128 block cipher in CBC mode.
//
// The key must be chosen as a random byte slice of length 16, as done by e.g
// NewKey(), and be kept secret.
// The IV must be chosen as a random byte slice of length 16 and may not be
// reused across multiple encryptions. It need however not be kept secret, and
// can be transmitted in public along with the ciphertext.
type AESCBC struct {
	Key []byte
	IV  []byte
}

// Encrypt encrypts the message with the AES-128 block cipher in CBC mode.
//
// The length of the message must be a multiple of AES-128's blocksize of 16
// bytes. Apply a padding if it is not.
//
// The key must be exactly 16 bytes in size.
func (cbc *AESCBC) Encrypt(msg []byte) (ctxt []byte, err error) {
	if len(msg)%aesBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Ciphertext must be a multiple of AES blocksize %d, but was %d",
			aesBlockSize,
			len(msg),
		)
	}

	if len(cbc.IV) != aesBlockSize {
		return []byte{}, fmt.Errorf(
			"Expected IV of length %d, but got %d",
			aesBlockSize,
			len(cbc.IV),
		)
	}

	aes, err := newAES(cbc.Key)
	if err != nil {
		return []byte{}, err
	}

	ctxtIV := make([]byte, len(msg)+aesBlockSize)
	copy(ctxtIV[0:aesBlockSize], cbc.IV)

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
	ctxt = ctxtIV[aesBlockSize:]

	return ctxt, nil

}

// Decrypt decrypts the ciphertext with the AES-128 block cipher in ECB
// mode.
//
// The length of the ciphertet must be a multiple of AES-128's blocksize of 16
// bytes.
//
// The key must be exactly 16 bytes in size.
func (cbc *AESCBC) Decrypt(ctxt []byte) (msg []byte, err error) {
	if len(ctxt)%aesBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Ciphertext must be a multiple of AES blocksize %d, but was %d",
			aesBlockSize,
			len(ctxt),
		)
	}

	if len(cbc.IV) != aesBlockSize {
		return []byte{}, fmt.Errorf(
			"Expected IV of length %d, but got %d",
			aesBlockSize,
			len(cbc.IV),
		)
	}

	aes, err := newAES(cbc.Key)
	if err != nil {
		return []byte{}, err
	}

	msg = make([]byte, len(ctxt))
	ctxtIV := make([]byte, len(ctxt)+aesBlockSize)
	copy(ctxtIV[0:aesBlockSize], cbc.IV)
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
