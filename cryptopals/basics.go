package main

import (
	"encoding/base64"
	"encoding/hex"
	"log"

	"github.com/Lavode/cryptopals/analysis"
	"github.com/Lavode/cryptopals/bitwise"
	"github.com/Lavode/cryptopals/cipher"
)

func hexToBase64() {
	header(1, "Convert hex to base64")

	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	bytes, err := hex.DecodeString(in)
	if err != nil {
		log.Fatalf("Error decoding hex string: %v", err)
	}

	out := base64.StdEncoding.EncodeToString(bytes)

	log.Printf("Converted hex value %s (= %s) to base64: %s", in, bytes, out)
}

func fixedXor() {
	header(2, "Fixed XOR")

	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"

	aBytes, err := hex.DecodeString(a)
	if err != nil {
		log.Fatalf("Error decoding hex: %v", err)
	}

	bBytes, err := hex.DecodeString(b)
	if err != nil {
		log.Fatalf("Error decoding hex: %v", err)
	}

	xor := bitwise.Xor(aBytes, bBytes)
	xorEnc := hex.EncodeToString(xor)
	log.Printf("%s XOR %s = %s", a, b, xorEnc)
}

func singleByteXor() {
	header(3, "Single-byte XOR cipher")

	ctxt := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	ctxtBytes, err := hex.DecodeString(ctxt)
	if err != nil {
		log.Fatalf("Error decoding hex: %v", err)
	}

	msg, key, dist := analysis.SingleByteXor(ctxtBytes)
	log.Printf("Most likely key: %x, distance = %f\nMessage: %s", key, dist, msg)
}

func detectSingleByteXor() {
	header(4, "Detect single-character XOR")

	ctxts, err := GetLines(4, Hex)
	if err != nil {
		log.Fatal(err)
	}

	var bestDist float64 = 2
	var bestKey byte
	var bestMsg []byte
	for _, ctxt := range ctxts {
		msg, key, dist := analysis.SingleByteXor(ctxt)
		if dist < bestDist {
			bestDist = dist
			bestKey = key
			bestMsg = msg
		}
	}

	log.Printf("Most likely Key = %x, distance = %f\nPlaintext = %s", bestKey, bestDist, bestMsg)
}

func repeatingKeyXor() {
	header(5, "Implementing repeating-key XOR")

	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")

	out := bitwise.Xor(input, key)
	log.Printf("Encoded %s to %x", input, out)
}

func breakRepeatingKeyXor() {
	header(6, "Break repeating-key XOR")

	ctxt, err := GetData(6, Base64)
	if err != nil {
		log.Fatal(err)
	}

	msg, key, distance := analysis.RepeatingByteXor(ctxt)
	log.Printf("Recovered key = %x, distance = %f, message = %s", key, distance, msg)
}

func decryptAesECB() {
	header(7, "AES in ECB mode")

	key := []byte("YELLOW SUBMARINE")

	ctxt, err := GetData(7, Base64)
	if err != nil {
		log.Fatal(err)
	}

	msg, err := cipher.AESECBDecrypt(ctxt, key)

	if err != nil {
		log.Fatalf("Error decrypting AES ciphertext: %v", err)
	}

	log.Printf("Decrypted message to:\n%s", msg)
}

func detectAesEcb() {
	header(8, "Detect AES in ECB mode")

	ctxts, err := GetLines(8, Hex)
	if err != nil {
		log.Fatal(err)
	}

	for _, ctxt := range ctxts {
		if analysis.DetectECB(ctxt) {
			log.Printf("Ciphertext %x is likely ECB encryption", ctxt)
		}

	}

}

func header(id int, name string) {
	log.Printf("==== Challenge %d: %s ====", id, name)
}
