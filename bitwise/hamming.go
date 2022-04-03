package bitwise

// HammingDistance calculates the Hamming distance - that is the number of
// differing bits - between the two passed strings.
//
// If the strings differ in length, only their truncation to the smaller of the
// two lengths is considered.
func HammingDistance(a, b []byte) int {
	length := len(a)
	if len(b) < len(a) {
		length = len(b)
	}

	distance := 0
	for i := 0; i < length; i++ {
		// XOR will yield a byte with the differing bits set to 1, then
		// we only need to count them.
		distance += OneBits(a[i] ^ b[i])
	}

	return distance
}

// OneBits returns the number of bits set to 1.
func OneBits(b byte) int {
	var mask byte = 1
	count := 0

	for i := 0; i < 8; i++ {
		if b&(mask<<i) != 0 {
			count++
		}
	}

	return count
}
