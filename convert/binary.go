package convert

import (
	"encoding/base64"
	"encoding/hex"
)

func HexToBase64(s string) (string, error) {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}
