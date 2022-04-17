package cipher

type BlockCipher interface {
	Encrypt(msg []byte) (ctxt []byte, err error)
	Decrypt(ctxt []byte) (msg []byte, err error)
}
