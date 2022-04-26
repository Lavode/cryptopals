package analysis

import (
	"fmt"
	"log"

	"github.com/Lavode/cryptopals/cipher"
	"github.com/Lavode/cryptopals/oracle"
)

// AESBlockSize defines the block size, in bytes, of AES
const AESBlockSize = 16

// AESBlock is a block of ciphertext or plaintext which can be fed into
// the AES block cipher.
type AESBlock [AESBlockSize]byte

// DetectECB attempts to detect if the provided ciphertext is the result of AES
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
func DetectECB(ctxt []byte) bool {
	// AES in ECB mode is guaranteed to produce block-aligned ciphertexts
	if len(ctxt)%AESBlockSize != 0 {
		return false
	}

	// Two blocks being equal is a strong indication of ECB having been used.
	// If a mode of operation which produces ciphertext indistinguishable
	// from uniform random had been used, then the probability of two 16
	// byte blocks being equal is 2^(-128), which is negligible.

	seenBlocks := make(map[AESBlock]bool)
	for i := 0; i < len(ctxt)/AESBlockSize; i++ {
		block := [AESBlockSize]byte{}

		copy(block[:], ctxt[i*AESBlockSize:(i+1)*AESBlockSize])
		_, ok := seenBlocks[block]
		if ok {
			// Block seen before
			return true
		}

		seenBlocks[block] = true
	}

	return false
}

// DecryptECBPostfix attempts to decrypt an unkonwn ECB postfix, given access to an
// encryption oracle providing encryptions of a chosen infix.
func DecryptECBPostfix(oracle *oracle.ECBInfix, blockSize int) ([]byte, error) {
	var postfix []byte

	postfixLength, err := DetectECBPostfixLength(oracle, blockSize)
	if err != nil {
		return postfix, err
	}
	log.Printf("Detected length of unknown postfix: %dB", postfixLength)
	postfix = make([]byte, 0, postfixLength)

	// For the first 16 bytes we'll care about the first ciphertext block,
	// for the next 16 bytes about the second, and so on.
	relevantCtxtBlock := 0
	// We'll start with a known message one block shy of a full block.
	knownMessage := make([]byte, blockSize-1)
	for {
		for i := 15; i >= 0; i-- {
			msg := make([]byte, i)
			ctxt, err := oracle.Encrypt(msg)
			if err != nil {
				return postfix, fmt.Errorf("Error querying oracle: %v", err)
			}

			knownBlock := knownMessage[len(knownMessage)-blockSize+1:]

			postfixByte, err := bruteForceByte(oracle, knownBlock, ctxt.Block(relevantCtxtBlock), blockSize)
			if err != nil {
				return postfix, err
			}

			postfix = append(postfix, postfixByte)
			knownMessage = append(knownMessage, postfixByte)
			if len(postfix) == postfixLength {
				return postfix, nil
			}
		}

		relevantCtxtBlock++
	}
}

// DetectECBPostfixLength attempts to detect the length of an unknown postfix,
// given an encryption oracle allowing to specify the infix of a message with a
// fixed-size unknown pre- and postfix.
func DetectECBPostfixLength(oracle *oracle.ECBInfix, blockSize int) (int, error) {
	// We first figure out the length of the unknown infix. To do so,
	// starting with a chosen-plaintext length of 0, we increase it one
	// byte at a time until the length of the ciphertext increases by one
	// block.
	// At this point, the full plaintext has the following form:
	// chosen_plaintext || postfix || 0x0F .... 0x0F
	// That is the chosen plaintext and postfix together are block_aligned,
	// followed by one full block of PKCS#7 padding.

	msg := make([]byte, 0)
	aesCtxt, err := oracle.Encrypt(msg)
	if err != nil {
		return 0, fmt.Errorf("Error querying oracle: %v", err)
	}
	ctxt := aesCtxt.Bytes

	initialCtxtLength := len(ctxt)
	for {
		msg = append(msg, 0x00)
		aesCtxt, err = oracle.Encrypt(msg)
		if err != nil {
			return 0, fmt.Errorf("Error querying oracle: %v", err)
		}
		ctxt = aesCtxt.Bytes

		if len(ctxt) != initialCtxtLength {
			break
		}
	}

	ctxtLength := len(ctxt)
	if ctxtLength-initialCtxtLength != blockSize {
		return 0, fmt.Errorf(
			"Unexpected increase in ciphertext length from %dB to %dB: Expected increase of %dB",
			initialCtxtLength, ctxtLength, blockSize,
		)
	}

	postfixLength := ctxtLength - blockSize - len(msg)

	return postfixLength, nil
}

// bruteForceByte will, given access to an infix encryption oracle and a known
// message prefix, brute-force the last byte of the ciphertext block.
//
// This involves 2^8 calls to the encryption oracle.
func bruteForceByte(oracle *oracle.ECBInfix, knownPrefix []byte, ctxtBlock cipher.AESBlock, blockSize int) (byte, error) {
	if len(knownPrefix) != blockSize-1 {
		return 0, fmt.Errorf("Known-prefix must be of length %d; was %d", blockSize-1, len(knownPrefix))
	}

	for i := 0; i < 256; i++ {
		msg := make([]byte, blockSize)
		copy(msg, knownPrefix)
		msg[blockSize-1] = byte(i)

		ctxt, err := oracle.Encrypt(msg)
		if err != nil {
			return 0, fmt.Errorf("Error querying oracle: %v", err)
		}

		if ctxtBlock == ctxt.Block(0) {
			return byte(i), nil
		}
	}

	// If we got until here, then something went terribly wrong
	return 0, fmt.Errorf("Unable to brute-force last byte of ciphertext")
}
