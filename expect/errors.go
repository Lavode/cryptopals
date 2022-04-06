package expect

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Equals ensures that a and b are equal, and will cause a test failure
// otherwise.
func Equals(t *testing.T, a, b interface{}) {
	if !cmp.Equal(a, b) {
		t.Errorf("Expected %v = %v. Difference:\n%s", a, b, cmp.Diff(a, b))
	}
}

// NoError expects that err is nil, and will cause a test failure otherwise.
func NoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Expected no error; got %v", err)
	}
}

// Error expects that err is not nil, and will cause a test failure otherwise.
func Error(t *testing.T, err error) {
	if err == nil {
		t.Errorf("Expected error; got none")
	}
}
