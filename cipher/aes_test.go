package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKey(t *testing.T) {
	key, err := NewKey()

	assert.Nil(t, err)
	assert.Equal(t, 16, len(key))
}
