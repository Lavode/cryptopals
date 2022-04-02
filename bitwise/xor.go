package bitwise

func Xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	bLength := len(b)

	for i, x := range a {
		out[i] = x ^ b[i%bLength]
	}

	return out
}
