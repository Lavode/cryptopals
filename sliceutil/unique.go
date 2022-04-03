package sliceutil

// Unique returns a new slice containing only the unique values of the passed
// slice.
func Unique[T comparable](x []T) []T {
	out := make([]T, 0)
	seen := make(map[T]bool)

	for _, v := range x {
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}

	return out
}
