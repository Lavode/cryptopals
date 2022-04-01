package expect

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Equals(t *testing.T, a, b interface{}) {
	if !cmp.Equal(a, b) {
		t.Errorf("Expected %v = %v", a, b)
	}
}

func NoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Expected no error; got %v", err)
	}
}

func Error(t *testing.T, err error) {
	if err == nil {
		t.Errorf("Expected error; got none")
	}
}
