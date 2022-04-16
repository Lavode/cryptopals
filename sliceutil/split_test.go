package sliceutil

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlternating(t *testing.T) {
	in := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}

	assert.Equal(
		t,
		[][]int{in},
		Alternating(in, 1),
	)

	assert.Equal(
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

func TestSplit(t *testing.T) {
	in := []int{1, 2, 5, 3, 5, 7, 8, 9, 5, 5}
	assert.Equal(
		t,
		[][]int{
			[]int{1, 2},
			[]int{3},
			[]int{7, 8, 9},
			[]int{},
			[]int{},
		},
		Split(in, 5),
	)

	in2 := []byte{0x20, 0x10, 0x15, 0x20, 0x12}
	assert.Equal(
		t,
		[][]byte{
			[]byte{},
			[]byte{0x10, 0x15},
			[]byte{0x12},
		},
		Split(in2, 0x20),
	)
}

func TestSplitEmptyInput(t *testing.T) {
	in := []string{}
	assert.Equal(
		t,
		[][]string{in},
		Split(in, " "),
	)
}

func TestSplitSeparatorNotPresent(t *testing.T) {
	in := []int{1, 2, 3, 4}
	assert.Equal(
		t,
		[][]int{in},
		Split(in, 5),
	)
}

func ExampleSplit() {
	fmt.Println(Split([]int{1, 2, 3, 4, 5, 6, 7, 5, 9, 5}, 5))
	// Output: [[1 2 3 4] [6 7] [9] []]
}

func ExampleSplit_noseparator() {
	fmt.Println(Split([]int{1, 2, 3, 4, 5, 6, 7, 5, 9, 5}, 10))
	// Output: [[1 2 3 4 5 6 7 5 9 5]]
}
