package sliceutil

// Alternating splits the provided slice into `n` slices, where members of the
// slice will be split into the output slices alternatingly.
//
// As an example with n=3, the first, fourth, seventh etc item will end up in
// the first output slice, the second, fifth, eight etc in the second, and the
// third, sixth, ninth etc in the third.
func Alternating[T any](ts []T, n int) [][]T {
	out := make([][]T, n)

	for idx, t := range ts {
		out[idx%n] = append(out[idx%n], t)
	}

	return out
}

// Split splits the provided slice by the given separator. The separators will
// not be part of the output.
//
// If there are multiple separators in sequence, or at the beginning or end of
// the slice, then the output will contain empty slices.
//
// If the separator is not present, the output will be a single slice.
func Split[T comparable](ts []T, separator T) [][]T {
	out := make([][]T, 0)
	out = append(out, make([]T, 0))

	for _, t := range ts {
		if t == separator {
			out = append(out, make([]T, 0))
		} else {
			lastIdx := len(out) - 1
			out[lastIdx] = append(out[lastIdx], t)
		}
	}

	return out
}
