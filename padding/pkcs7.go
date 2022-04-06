package padding

import "fmt"

// PKCS7Pad pads the message to the next multiple of the given length by using
// PKCS#7 padding.
//
// It does so by adding x bytes of value x, where x is the number required to
// get to the *next larger* multiple of 16. This means that a message with a
// length which already is a multiple of 16 will be padded with 16 bytes of
// value 0x10.
func PKCS7Pad(msg []byte, length int) []byte {
	padBytes := length - (len(msg) % length)

	padded := make([]byte, len(msg)+padBytes)
	copy(padded, msg)
	for i := len(msg); i < len(padded); i++ {
		padded[i] = byte(padBytes)
	}

	return padded
}

// PKCS7Unpad removes PKCS#7-style padding from the supplied message.
//
// If the padding is invalid, an error is returned.
func PKCS7Unpad(msg []byte) ([]byte, error) {
	msgLength := len(msg)
	padBytes := msg[msgLength-1]

	// We'll verify the padding by checking that the last padBytes bytes
	// are equal to padBytes.
	for i := 0; i < int(padBytes); i++ {
		if msg[msgLength-1-i] != padBytes {
			return []byte{}, fmt.Errorf(
				"Invalid padding in message, got %x byte, expected %x",
				msg[msgLength-1-i],
				padBytes,
			)
		}
	}

	unpadded := make([]byte, len(msg)-int(padBytes))
	copy(unpadded, msg)

	return unpadded, nil
}
