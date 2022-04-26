package main

import (
	"log"

	"github.com/Lavode/cryptopals/analysis"
	"github.com/Lavode/cryptopals/cipher"
	"github.com/Lavode/cryptopals/oracle"
	"github.com/Lavode/cryptopals/padding"
)

func pkcs7Padding() {
	header(9, "Implement PKCS#7 padding")

	msg := []byte("YELLOW SUBMARINE")
	padded := padding.PKCS7Pad(msg, 20)

	log.Printf("Message %x padded to %x", msg, padded)
}

func cbcDecrypt() {
	header(10, "Implement CBC mode")

	ctxt, err := GetData(10, Base64)
	if err != nil {
		log.Fatal(err)
	}

	key := []byte("YELLOW SUBMARINE")
	// IV is all zeroes
	iv := make([]byte, 16)

	aes := cipher.AESCBC{Key: key, IV: iv}
	msg, err := aes.Decrypt(ctxt)
	if err != nil {
		log.Fatalf("Error decrypting AES-CBC ciphertext: %v", err)
	}

	log.Printf("Decrypted AES-CBC ciphertext: %s", msg)
}

func ecbCbcOracle() {
	header(11, "An ECB/CBC detection oracle")

	// We might 'lose' up to (nearly) one block to the random prefix, one
	// to the random postfix.
	// Thus if we supply four blocks' worth of zero bytes, we are
	// guaranteed that there will be at least two equal blocks, which
	// allows to easily detect the usage of ECB.
	msg := make([]byte, 64)

	log.Println("Starting ECB/CBC detection challenge")
	oracle := oracle.ECBOrCBC{}

	attempts := 50
	correctGuesses := 0
	for i := 0; i < attempts; i++ {
		ctxt, err, wasECB := oracle.Encrypt(msg)
		if err != nil {
			log.Fatalf("Error querying oracle: %v", err)
		}

		guessECB := analysis.DetectECB(ctxt.Bytes)
		correct := guessECB == wasECB
		if correct {
			correctGuesses++
		}

		log.Printf(
			"Attempt %d: Was ECB: %t, Our guess: %t, Correct: %t",
			i,
			wasECB,
			guessECB,
			correct,
		)
	}
	log.Printf("%d / %d attempts correct", attempts, correctGuesses)

}

func ecbByteAtATime() {
	header(12, "Byte-at-a-time ECB decryption (Simple)")

	// 'Secret' payload we intend to decrypt
	payload, err := GetData(12, Base64)
	if err != nil {
		log.Fatal(err)
	}

	oracle := oracle.ECBInfix{Postfix: payload, PrefixLength: 0}

	blockSize, err := analysis.DetectBlockSize(&oracle)
	if err != nil {
		log.Fatalf("Error deducing block size: %v", err)
	}
	log.Printf("Deduced block size: %dB", blockSize)

	// With four blocks' worth of zero bytes we're guaranteed to have at
	// least two blocks full of zero bytes in the middle.
	msg := make([]byte, 4*blockSize)
	ctxt, err := oracle.Encrypt(msg)
	if err != nil {
		log.Fatalf("Error querying oracle: %v", err)
	}

	usesECB := analysis.DetectECB(ctxt.Bytes)
	if !usesECB {
		log.Fatalf("Oracle seems to not use ECB mode")
	}
	log.Printf("Oracle seems to be using ECB mode")

	postfix, err := analysis.DecryptECBPostfix(&oracle, blockSize)
	if err != nil {
		log.Fatalf("Error decrypting ECB postfix: %v", err)
	}
	log.Printf("Decrypted ECB postfix to: %s", postfix)
}
