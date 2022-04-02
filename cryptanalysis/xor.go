package cryptanalysis

import (
	"github.com/Lavode/cryptopals/bitwise"
	"github.com/Lavode/cryptopals/language"
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
