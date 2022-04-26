package analysis

import (
	"fmt"

	"github.com/Lavode/cryptopals/oracle"
)

// DetectBlockSize attempts to detect the block size when given access to an
// encryption oracle.
//
// It does so be repeatedly increasing the size of the message passed to the
// encryption oracle, and calculating the number of bytes by which the message
// sized increased inbetween two subsequent times where the resulting
// ciphertext increased in size.
func DetectBlockSize(cipher oracle.EncryptionOracle) (int, error) {
	msg := make([]byte, 0)

	ctxt, err := cipher.Encrypt(msg)
	if err != nil {
		return 0, fmt.Errorf("Error querying encryption oracle: %v", err)
	}
	initialCtxtLength := len(ctxt.Bytes)

	for {
		// Feed every-growing messages to the oracle until we observe
		// that the size of the ciphertext changes.
		msg = append(msg, 0x00)

		newCtxt, err := cipher.Encrypt(msg)
		if err != nil {
			return 0, fmt.Errorf("Error querying encryption oracle: %v", err)
		}

		if len(newCtxt.Bytes) > initialCtxtLength {
			// Size of the cipher text just grew, allowing us to
			// deduce the block size.
			return len(newCtxt.Bytes) - initialCtxtLength, nil
		}
	}
}
