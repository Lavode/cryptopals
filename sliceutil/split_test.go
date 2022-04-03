package sliceutil

import (
	"fmt"
	"testing"

	"github.com/Lavode/cryptopals/expect"
)

func TestAlternating(t *testing.T) {
	in := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}

	expect.Equals(
		t,
		[][]int{in},
		Alternating(in, 1),
	)

	expect.Equals(
		t,
		[][]int{
			[]int{1, 4, 7, 10, 13},
			[]int{2, 5, 8, 11, 14},
			[]int{3, 6, 9, 12},
		},
		Alternating(in, 3),
	)

}

func ExampleAlternating() {
	fmt.Println(Alternating([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 3))
	// Output: [[1 4 7 10] [2 5 8] [3 6 9]]
}
