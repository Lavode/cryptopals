package bitwise

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHammingDistance(t *testing.T) {
	dist := HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	assert.Equal(t, 37, dist)

	dist = HammingDistance([]byte("Hello world"), []byte("Hello world"))
	assert.Equal(t, 0, dist)

	// If inputs are not of equal length, we assert it to only consider truncated inputs
	dist = HammingDistance([]byte("this is a test this is a test"), []byte("wokka wokka!!!"))
	assert.Equal(t, 37, dist)

	dist = HammingDistance([]byte("this is a test"), []byte("wokka wokka!!! bok bok bok"))
	assert.Equal(t, 37, dist)
}

func TestOneBits(t *testing.T) {
	assert.Equal(t, 0, OneBits(0))
	assert.Equal(t, 1, OneBits(1))
	assert.Equal(t, 1, OneBits(8))
	assert.Equal(t, 3, OneBits(42))
	assert.Equal(t, 8, OneBits(255))
}
