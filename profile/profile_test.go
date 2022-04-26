package profile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProfileFromString(t *testing.T) {
	input := "email=john@doe.com&uid=20&role=admin"
	profile, err := ProfileFromString(input)
	expected := Profile{
		Email: "john@doe.com",
		UID:   20,
		Role:  "admin",
	}

	assert.Nil(t, err)
	assert.Equal(t, expected, profile)
}

func TestProfileFromStringWithInvalidInput(t *testing.T) {
	// Missing input
	input := "email=john@doe.com&uid=20"
	_, err := ProfileFromString(input)
	assert.Error(t, err)

	// UID not an int
	input = "email=john@doe.com&uid=a20b&role=admin"
	_, err = ProfileFromString(input)
	assert.Error(t, err)
}

func TestProfileFor(t *testing.T) {
	profile := ProfileFor("john@doe.com")
	assert.Equal(
		t,
		"email=john@doe.com&uid=10&role=user",
		profile,
	)
}

func TestProfileForStripsMetaCharacters(t *testing.T) {
	profile := ProfileFor("john&role=admin")
	assert.Equal(
		t,
		"email=johnroleadmin&uid=10&role=user",
		profile,
	)
}
