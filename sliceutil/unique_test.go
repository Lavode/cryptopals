package sliceutil

import (
	"fmt"
	"testing"

	"github.com/Lavode/cryptopals/expect"
)

func TestUnique(t *testing.T) {
	expect.Equals(
		t,
		[]byte{1, 2, 3, 4},
		Unique([]byte{1, 2, 3, 4}),
	)

	expect.Equals(
		t,
		[]string{"Hello", "hello", "world"},
		Unique([]string{"Hello", "Hello", "hello", "world", "world"}),
	)

	expect.Equals(
		t,
		[]float64{1.23, 45.2, 27},
		Unique([]float64{1.23, 45.2, 1.23, 27, 1.23}),
	)

	expect.Equals(
		t,
		[]int{},
		Unique([]int{}),
	)
}

func ExampleUnique() {
	fmt.Println(Unique([]int{1, 2, 1, 3, 4, 2, 1}))
	// Output: [1 2 3 4]
}
