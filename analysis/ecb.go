package analysis

const AesBlockSize = 16

type AesBlock [AesBlockSize]byte

// DetectEcb attempts to detect if the provided ciphertext is the result of AES
// in ECB mode.
//
// It does so by checking if any two blocks of ciphertext are equal. As such
// this detection method is not perfect.
// There is a small chance of 2^(-128) that two random blocks of ciphertext are
// equal without ECB being involved. As such there is a non-zero, albeit tiny,
// chance that any random ciphertext consisting of n blocks will have one block
// repeating, leading to a false-positive.
// A bound for the false-positivity rate can be gotten by looking at
// bounds for P(Binom(n, 2^(-128)) > 0 of the binomial distriubtion.
//
// Similarly there is a possibility of a false negative, which will happen if
// the original plaintext message had no repeating blocks.
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
