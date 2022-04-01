package bitwise

func Xor(a, b []byte) []byte {
	out := make([]byte, len(a))

	for i, x := range a {
		out[i] = x ^ b[i]
	}

	return out
}
