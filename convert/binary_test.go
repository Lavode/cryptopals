package convert

import (
	"testing"

	"github.com/Lavode/cryptopals/expect"
)

func TestHexToBase64(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	out, err := HexToBase64(in)

	expect.NoError(t, err)
	expect.Equals(t, out, expected)

	in = "48656c6c6f20776f726c642c207468697320697320796f75722070696c6f7420737065616b696e672e"
	expected = "SGVsbG8gd29ybGQsIHRoaXMgaXMgeW91ciBwaWxvdCBzcGVha2luZy4="
	out, err = HexToBase64(in)

	expect.NoError(t, err)
	expect.Equals(t, out, expected)
}

func TestHexToBase64WithInvalidInput(t *testing.T) {
	in := "abZ"
	_, err := HexToBase64(in)
	expect.Error(t, err)
}
