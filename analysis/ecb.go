package analysis

const AesBlockSize = 16

type AesBlock [AesBlockSize]byte

func DetectEcb(ctxt []byte) bool {
	// AES in ECB mode is guaranteed to produce block-aligned ciphertexts
	if len(ctxt)%AesBlockSize != 0 {
		return false
	}

	// Two blocks being equal is a strong indication of ECB having been used.
	// If a mode of operation which produces ciphertext indistinguishable
	// from uniform random had been used, then the probability of two 16
	// byte blocks being equal is 2^(-128), which is negligible.

	seenBlocks := make(map[AesBlock]bool)
	for i := 0; i < len(ctxt)/AesBlockSize; i++ {
		block := [AesBlockSize]byte{}

		copy(block[:], ctxt[i*AesBlockSize:(i+1)*AesBlockSize])
		_, ok := seenBlocks[block]
		if ok {
			// Block seen before
			return true
		} else {
			seenBlocks[block] = true
		}
	}

	return false
}
