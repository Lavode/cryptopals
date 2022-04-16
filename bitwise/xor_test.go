package bitwise

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXor(t *testing.T) {
	// Both inputs of same length
	a := []byte{27, 120, 23, 69, 16, 20}
	assert.Equal(
		t,
		Xor(a, []byte{46, 78, 32, 38, 124, 11}),
		[]byte{53, 54, 55, 99, 108, 31},
	)

	// Single byte
	c := []byte{13}
	expected := []byte{22, 117, 26, 72, 29, 25}
	out := Xor(a, c)
	assert.Equal(t, out, expected)

	// Second input shorter
	assert.Equal(
		t,
		Xor(a, []byte{13, 14, 15, 16}),
		[]byte{22, 118, 24, 85, 29, 26},
	)

	// First input shorter
	assert.Equal(
		t,
		Xor([]byte{13, 14, 15, 16}, a),
		[]byte{22, 118, 24, 85},
	)
}
