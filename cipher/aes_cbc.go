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
	if len(msg)%AESBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Ciphertext must be a multiple of AES blocksize %d, but was %d",
			AESBlockSize,
			len(msg),
		)
	}

	if len(cbc.IV) != AESBlockSize {
		return []byte{}, fmt.Errorf(
			"Expected IV of length %d, but got %d",
			AESBlockSize,
			len(cbc.IV),
		)
	}

	aes, err := newAES(cbc.Key)
	if err != nil {
		return []byte{}, err
	}

	ctxtIV := make([]byte, len(msg)+AESBlockSize)
	copy(ctxtIV[0:AESBlockSize], cbc.IV)

	for i := 0; i < len(msg)/AESBlockSize; i++ {
		// Start of the current block in the plaintext slice.
		mBlockStart := i * AESBlockSize
		// Corresponding block in ciphertext + IV slice starts
		// aesBlockSize bytes later.
		cBlockStart := (i + 1) * AESBlockSize

		// m_{i} XOR c_{i-1}
		intermediate := bitwise.Xor(
			msg[mBlockStart:mBlockStart+AESBlockSize],
			ctxtIV[cBlockStart-AESBlockSize:cBlockStart],
		)

		// c_i = ENC(m_i XOR m_{i-1})
		aes.Encrypt(
			ctxtIV[cBlockStart:cBlockStart+AESBlockSize],
			intermediate,
		)

	}

	// Remove IV
	ctxt = ctxtIV[AESBlockSize:]

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
	if len(ctxt)%AESBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Ciphertext must be a multiple of AES blocksize %d, but was %d",
			AESBlockSize,
			len(ctxt),
		)
	}

	if len(cbc.IV) != AESBlockSize {
		return []byte{}, fmt.Errorf(
			"Expected IV of length %d, but got %d",
			AESBlockSize,
			len(cbc.IV),
		)
	}

	aes, err := newAES(cbc.Key)
	if err != nil {
		return []byte{}, err
	}

	msg = make([]byte, len(ctxt))
	ctxtIV := make([]byte, len(ctxt)+AESBlockSize)
	copy(ctxtIV[0:AESBlockSize], cbc.IV)
	copy(ctxtIV[AESBlockSize:], ctxt)

	// We'll skip 'decryption' of the IV
	for i := 0; i < len(msg)/AESBlockSize; i++ {
		// Start of the current block in the plaintext slice.
		mBlockStart := i * AESBlockSize
		// Corresponding block in ciphertext + IV slice starts
		// aesBlockSize bytes later.
		cBlockStart := (i + 1) * AESBlockSize

		// m_i = DEC(c_i) XOR c_{i-1}
		aes.Decrypt(
			msg[mBlockStart:mBlockStart+AESBlockSize],
			ctxtIV[cBlockStart:cBlockStart+AESBlockSize],
		)

		copy(
			msg[mBlockStart:mBlockStart+AESBlockSize],
			bitwise.Xor(
				msg[mBlockStart:mBlockStart+AESBlockSize],
				ctxtIV[cBlockStart-AESBlockSize:cBlockStart],
			),
		)
	}

	return msg, nil
}
