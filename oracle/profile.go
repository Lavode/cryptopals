package oracle

import (
	"fmt"

	"github.com/Lavode/cryptopals/cipher"
	"github.com/Lavode/cryptopals/padding"
	"github.com/Lavode/cryptopals/profile"
)

// Profile provides an oracle allowing to get ECB-encrypted profiles for a
// user-chosen e-mail address, and decrypt user-supplied ciphertexts to produce
// such oracles again.
type Profile struct {
	key *[]byte
}

func (or *Profile) Encrypt(email string) (cipher.AESCiphertext, error) {
	ctxt := cipher.AESCiphertext{}

	if or.key == nil {
		key, err := cipher.NewKey()
		if err != nil {
			return ctxt, err
		}

		or.key = &key
	}

	profile := profile.ProfileFor(email)

	// Fill to next multiple of AES block size
	padded := padding.PKCS7Pad([]byte(profile), cipher.AESBlockSize)

	ecb := cipher.AESECB{Key: *or.key}
	rawCtxt, err := ecb.Encrypt(padded)
	if err != nil {
		return ctxt, err
	}
	ctxt.Bytes = rawCtxt

	return ctxt, nil
}

func (or *Profile) Decrypt(ctxt []byte) (profile.Profile, error) {
	if or.key == nil {
		key, err := cipher.NewKey()
		if err != nil {
			return profile.Profile{}, err
		}

		or.key = &key
	}

	ecb := cipher.AESECB{Key: *or.key}
	padded, err := ecb.Decrypt(ctxt)
	if err != nil {
		return profile.Profile{}, fmt.Errorf("Error decrypting profile: %v", err)
	}

	msg, err := padding.PKCS7Unpad(padded)
	if err != nil {
		return profile.Profile{}, fmt.Errorf("Error unpadding profile string: %v", err)
	}

	prof, err := profile.ProfileFromString(string(msg))
	if err != nil {
		return profile.Profile{}, fmt.Errorf("Error parsing profile string: %v", err)
	}

	return prof, nil
}
