package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"os"

	"github.com/Lavode/cryptopals/analysis"
	"github.com/Lavode/cryptopals/bitwise"
	"github.com/Lavode/cryptopals/convert"
)

func HexToBase64() {
	header(1, "Convert hex to base64")

	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	out, err := convert.HexToBase64(in)
	if err != nil {
		log.Fatalf("Error converting hex to base64: %v", err)
	}

	log.Printf("Converted hex value %s to base64: %s", in, out)
}

func FixedXor() {
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

func SingleByteXor() {
	header(3, "Single-byte XOR cipher")

	ctxt := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	ctxtBytes, err := hex.DecodeString(ctxt)
	if err != nil {
		log.Fatalf("Error decoding hex: %v", err)
	}

	msg, key, dist := analysis.SingleByteXor(ctxtBytes)
	log.Printf("Most likely key: %x, distance = %f\nMessage: %s", key, dist, msg)
}

func DetectSingleByteXor() {
	header(4, "Detect single-character XOR")

	file, err := os.Open("../data/4.txt")
	if err != nil {
		log.Fatalf("Error reading data/4.txt: %v", err)
	}
	defer file.Close()

	ctxts := make([][]byte, 0)
	scanner := bufio.NewScanner(file)
	i := 0
	for scanner.Scan() {
		i++
		hexString := scanner.Text()
		ctxt, err := hex.DecodeString(hexString)
		if err != nil {
			log.Fatalf("Error decoding hex: %v", err)
		}
		ctxts = append(ctxts, ctxt)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading from file: %v", err)
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

func RepeatingKeyXor() {
	header(5, "Implementing repeating-key XOR")

	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")

	out := bitwise.Xor(input, key)
	log.Printf("Encoded %s to %x", input, out)
}

func BreakRepeatingKeyXor() {
	header(6, "Break repeating-key XOR")

	file, err := os.Open("../data/6.txt")
	if err != nil {
		log.Fatalf("Error reading data/6.txt: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading from data/6.txt: %v", err)
	}

	ctxt := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(ctxt, data)
	if err != nil {
		log.Fatalf("Error decoding base64: %v", err)
	}
	ctxt = ctxt[:n]

	msg, key, distance := analysis.RepeatingByteXor(ctxt)
	log.Printf("Recovered key = %x, distance = %f, message = %s", key, distance, msg)
}

func header(id int, name string) {
	log.Printf("==== Challenge %d: %s ====", id, name)
}
