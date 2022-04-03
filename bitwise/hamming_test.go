package bitwise

import (
	"testing"

	"github.com/Lavode/cryptopals/expect"
)

func TestHammingDistance(t *testing.T) {
	dist := HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	expect.Equals(t, 37, dist)

	dist = HammingDistance([]byte("Hello world"), []byte("Hello world"))
	expect.Equals(t, 0, dist)

	// If inputs are not of equal length, we expect it to only consider truncated inputs
	dist = HammingDistance([]byte("this is a test this is a test"), []byte("wokka wokka!!!"))
	expect.Equals(t, 37, dist)

	dist = HammingDistance([]byte("this is a test"), []byte("wokka wokka!!! bok bok bok"))
	expect.Equals(t, 37, dist)
}

func TestOneBits(t *testing.T) {
	expect.Equals(t, 0, OneBits(0))
	expect.Equals(t, 1, OneBits(1))
	expect.Equals(t, 1, OneBits(8))
	expect.Equals(t, 3, OneBits(42))
	expect.Equals(t, 8, OneBits(255))
}
