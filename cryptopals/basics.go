package main

import (
	"encoding/hex"
	"log"

	"github.com/Lavode/cryptopals/convert"
)

func HexToBase64() {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	out, err := convert.HexToBase64(in)
	if err != nil {
		log.Fatalf("Error converting hex to base64: %v", err)
	}

	log.Printf("Converted hex value %s to base64: %s", in, out)
}

func FixedXor() {
	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"

	aBytes, err := hex.DecodeString(a)
	if err != nil {
		log.Fatalf("Error decoding hex: %v", err)
	}

	bBytes, err := hex.DecodedString(b)
	if err != nil {
		log.Fatalf("Error decoding hex: %v", err)
	}
}
