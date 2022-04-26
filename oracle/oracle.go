package oracle

import "github.com/Lavode/cryptopals/cipher"

type EncryptionOracle interface {
	Encrypt(msg []byte) (ctxt cipher.AESCiphertext, err error)
}

type DecryptionOracle interface {
	Decrypt(msg []byte) (ctxt []byte, err error)
}
