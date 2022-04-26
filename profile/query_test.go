package profile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseQuery(t *testing.T) {
	out := ParseQuery("foo=bar&baz=baraba&answer=42")
	expected := map[string]string{
		"foo":    "bar",
		"baz":    "baraba",
		"answer": "42",
	}
	assert.Equal(t, expected, out)

	out = ParseQuery("foo=bar")
	expected = map[string]string{
		"foo": "bar",
	}
	assert.Equal(t, expected, out)
}

func TestParseQueryIgnoresLeadingAndTrailingSeparators(t *testing.T) {
	out := ParseQuery("&&foo=bar&&&")
	expected := map[string]string{
		"foo": "bar",
	}
	assert.Equal(t, expected, out)
}

func TestParseQuerySkipsInvalidTuples(t *testing.T) {
	out := ParseQuery("a=1&b=2=3")
	expected := map[string]string{
		"a": "1",
	}
	assert.Equal(t, expected, out)
}

func TestParseQueryOverwritesDuplicates(t *testing.T) {
	out := ParseQuery("a=1&b=2&a=3")
	expected := map[string]string{
		"a": "3",
		"b": "2",
	}
	assert.Equal(t, expected, out)
}
