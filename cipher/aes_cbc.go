package cipher

import (
	"fmt"

	"github.com/Lavode/cryptopals/bitwise"
)

type AESCBC struct {
	Key []byte
	IV  []byte
}

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
