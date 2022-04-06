package bitwise

// Xor calculates the XOR of the two byte slices.
//
// The length of the output is equal to the length of the first slice. If the
// second slice is shorter, access to it wraps around. If it is longer, any
// bytes left over are ignored.
func Xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	bLength := len(b)

	for i, x := range a {
		out[i] = x ^ b[i%bLength]
	}

	return out
}
