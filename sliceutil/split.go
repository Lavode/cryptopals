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
