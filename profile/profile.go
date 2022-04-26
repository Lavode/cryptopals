package profile

import (
	"fmt"
	"strconv"
	"strings"
)

type Profile struct {
	Email string
	UID   int
	Role  string
}

func (prof *Profile) String() string {
	return fmt.Sprintf("email=%s&uid=%d&role=%s", prof.Email, prof.UID, prof.Role)
}

func ProfileFromString(input string) (Profile, error) {
	attributes := ParseQuery(input)
	profile := Profile{}

	email, ok := attributes["email"]
	if !ok {
		return profile, fmt.Errorf("Missing attribute 'email'")
	}
	profile.Email = email

	uidString, ok := attributes["uid"]
	if !ok {
		return profile, fmt.Errorf("Missing attribute 'uid'")
	}

	uid, err := strconv.Atoi(uidString)
	if err != nil {
		return profile, fmt.Errorf("Non-integer value for UID: %s", uidString)
	}
	profile.UID = uid

	role, ok := attributes["role"]
	if !ok {
		return profile, fmt.Errorf("Missing attribute 'role'")
	}
	profile.Role = role

	return profile, nil
}

func ProfileFor(email string) string {
	// We'll simply strip meta characters of URI-style queries
	email = strings.ReplaceAll(email, "&", "")
	email = strings.ReplaceAll(email, "=", "")

	prof := Profile{
		Email: email,
		UID:   10,
		Role:  "user",
	}

	return prof.String()
}
