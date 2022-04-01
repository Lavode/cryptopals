package bitwise

import (
	"testing"

	"github.com/Lavode/cryptopals/expect"
)

func TestXor(t *testing.T) {
	a := []byte{27, 120, 23, 69, 16, 20}
	b := []byte{46, 78, 32, 38, 124, 11}
	expected := []byte{53, 54, 55, 99, 108, 31}

	out := Xor(a, b)
	expect.Equals(t, out, expected)
}
