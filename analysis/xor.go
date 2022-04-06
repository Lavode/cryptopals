package analysis

import (
	"log"

	"github.com/Lavode/cryptopals/bitwise"
	"github.com/Lavode/cryptopals/language"
	"github.com/Lavode/cryptopals/sliceutil"
)

// SingleByteXor attempts to recover key and message of a single-byte XOR
// cipher.
//
// The plaintext is assumed to be ASCII-encoded English, and the key is assumed
// to be a single byte.
func SingleByteXor(ctxt []byte) (msg []byte, key byte, distance float64) {
	distance = 2 // Hellinger distance has an upper bound of 1

	for keyCandidate := 0; keyCandidate <= 255; keyCandidate++ {
		msgCandidate, distanceCandidate := evaluateSingleByteXor(ctxt, byte(keyCandidate))
		if distanceCandidate < distance {
			distance = distanceCandidate
			msg = msgCandidate
			key = byte(keyCandidate)
		}
	}

	return msg, key, distance
}

func evaluateSingleByteXor(ctxt []byte, key byte) (msg []byte, distance float64) {
	msg = bitwise.Xor(ctxt, []byte{key})
	freqs := language.FrequencyAnalysis(string(msg))
	distance = language.HistogramDifference(freqs, language.EnglishMonographFrequencies)

	return msg, distance
}

func RepeatingByteXor(ctxt []byte) (msg []byte, key []byte, distance float64) {
	keySize, dist := findRepeatingByteXorKeysize(ctxt)
	log.Printf("Guessed key size = %d, distance = %f", keySize, dist)

	key = make([]byte, keySize)
	msg = make([]byte, len(ctxt))

	// Split ciphertext into 'columns' of bytes which are all encrypted
	// with the same byte of the key.
	ctxtColumns := sliceutil.Alternating(ctxt, keySize)
	for i, ctxtCol := range ctxtColumns {
		// Each column is now encoded with a single-byte XOR, so we'll use that to break it
		msgCol, keyByte, keyDist := SingleByteXor(ctxtCol)
		distance += keyDist
		key[i] = keyByte

		// Store the bytes of the message column in the appropriate
		// place in the full message.
		for j, m := range msgCol {
			msg[j*keySize+i] = m
		}
	}

	// We'll just report the average distance
	distance /= float64(keySize)
	return msg, key, distance
}

func findRepeatingByteXorKeysize(ctxt []byte) (int, float64) {
	// Error handling? What do I look like?
	if len(ctxt) < 160 {
		panic("Must have at least 160 bytes of ciphertext")
	}

	// Normalized average hamming distance per keysize
	distances := make(map[int]float64)

	for keySize := 1; keySize <= 40; keySize++ {
		for i := 0; i < 4; i++ {
			firstBlock := ctxt[i*keySize : (i+1)*keySize]

			for j := i; j < 4; j++ {
				secondBlock := ctxt[j*keySize : (j+1)*keySize]

				distances[keySize] += float64(bitwise.HammingDistance(firstBlock, secondBlock))
			}
		}
	}

	// Average and normalize distances
	for keySize, _ := range distances {
		// There are 3+2+1 = 7 possible (unordered) pairs of two blocks, when picking from four.
		distances[keySize] /= 7
		distances[keySize] /= float64(keySize)
	}

	keySize := 1
	minDist := distances[keySize]
	for k, v := range distances {
		if v < minDist {
			keySize = k
			minDist = v
		}
	}

	return keySize, minDist
}
