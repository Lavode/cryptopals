package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Lavode/cryptopals/sliceutil"
)

const dataRoot = "data"

// DataEncoding specifies the encoding of data in a file.
type DataEncoding int

const (
	// Base64 refers to binary data encoded with standard Base64 encoding
	// defined in RFC4648.
	Base64 DataEncoding = iota
	// Hex refers to binary data encoded as a hexadecimal string.
	Hex
	// Plain refers to unencoded binary data.
	Plain
)

// GetLines loads data stored in a file, splitting it by Unix-style ASCII
// newlines (that is the 0xA byte). It decodes the data based on the specified
// encoding, returning the resulting binary data.
//
// Splitting happens on Linux-style ASCII newlines, that is the 0xA byte.
func GetLines(challenge int, encoding DataEncoding) ([][]byte, error) {
	path := pathFor(challenge)
	encData, err := readFromFile(path)
	if err != nil {
		return [][]byte{}, err
	}

	encLines := sliceutil.Split(encData, 0xA) // Newline

	lines := make([][]byte, len(encLines))
	for i, encLine := range encLines {
		line, err := decode(encLine, encoding)
		if err != nil {
			return [][]byte{}, err
		}

		lines[i] = line
	}

	return lines, nil
}

// GetData loads data stored in a file. It decodes the data based on the
// specified encoding, and returns the resulting binary.data.
func GetData(challenge int, encoding DataEncoding) ([]byte, error) {
	path := pathFor(challenge)
	encData, err := readFromFile(path)
	if err != nil {
		return []byte{}, err
	}

	return decode(encData, encoding)
}

func decode(data []byte, encoding DataEncoding) ([]byte, error) {
	switch encoding {
	case Base64:
		return decodeBase64(data)
	case Hex:
		return decodeHex(data)
	case Plain:
		return data, nil
	default:
		return []byte{}, fmt.Errorf("Invalid data encoding: %d", encoding)
	}
}

func readFromFile(path string) ([]byte, error) {
	var data []byte

	file, err := os.Open(path)
	if err != nil {
		return data, fmt.Errorf("Error opening %s: %v", path, err)
	}
	defer file.Close()

	data, err = io.ReadAll(file)
	if err != nil {
		return data, fmt.Errorf("Error reading from %s: %v", path, err)
	}

	return data, nil
}

func pathFor(challenge int) string {
	// Executable lives within the `cryptopals` directory, so we'll need to
	// navigate one level up.
	file := fmt.Sprintf("%d.txt", challenge)
	return filepath.Join("..", dataRoot, file)
}

func decodeBase64(encData []byte) ([]byte, error) {
	data := make([]byte, base64.StdEncoding.DecodedLen(len(encData)))
	n, err := base64.StdEncoding.Decode(data, encData)
	if err != nil {
		return data, fmt.Errorf("Error decoding base64: %v", err)
	}
	data = data[:n]

	return data, nil
}

func decodeHex(encData []byte) ([]byte, error) {
	data := make([]byte, hex.DecodedLen(len(encData)))
	n, err := hex.Decode(data, encData)
	if err != nil {
		return data, fmt.Errorf("Error decoding hex: %v", err)
	}
	data = data[:n]

	return data, nil
}
