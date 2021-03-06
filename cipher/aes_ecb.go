package cipher

import "fmt"

// AESECB encapsulates an instance of the AES-128 block cipher in ECB mode.
//
// The key must be chosen as a random byte slice of length 16, as done by e.g
// NewKey(), and be kept secret.
type AESECB struct {
	Key []byte
}

// Encrypt encrypts the message with the AES-128 block cipher in ECB mode.
//
// The length of the message must be a multiple of AES-128's blocksize of 16
// bytes. Apply a padding if it is not.
//
// The key must be exactly 16 bytes in size.
func (ecb *AESECB) Encrypt(msg []byte) (ctxt []byte, err error) {
	if len(msg)%AESBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Message must be a multiple of AES blocksize %d, but was %d",
			AESBlockSize,
			len(msg),
		)
	}

	aes, err := newAES(ecb.Key)
	if err != nil {
		return []byte{}, err
	}

	ctxt = make([]byte, len(msg))
	for i := 0; i < len(msg)/AESBlockSize; i++ {
		blockStart := i * AESBlockSize
		aes.Encrypt(
			ctxt[blockStart:blockStart+AESBlockSize],
			msg[blockStart:blockStart+AESBlockSize],
		)
	}

	return ctxt, nil
}

// Decrypt decrypts the ciphertext with the AES-128 block cipher in ECB
// mode.
//
// The length of the ciphertet must be a multiple of AES-128's blocksize of 16
// bytes.
//
// The key must be exactly 16 bytes in size.
func (ecb *AESECB) Decrypt(ctxt []byte) (msg []byte, err error) {
	if len(ctxt)%AESBlockSize != 0 {
		return []byte{}, fmt.Errorf(
			"Ciphertext must be a multiple of AES blocksize %d, but was %d",
			AESBlockSize,
			len(ctxt),
		)
	}

	aes, err := newAES(ecb.Key)
	if err != nil {
		return []byte{}, err
	}

	msg = make([]byte, len(ctxt))
	for i := 0; i < len(ctxt)/AESBlockSize; i++ {
		blockStart := i * AESBlockSize
		aes.Decrypt(
			msg[blockStart:blockStart+AESBlockSize],
			ctxt[blockStart:blockStart+AESBlockSize],
		)
	}

	return msg, nil
}
