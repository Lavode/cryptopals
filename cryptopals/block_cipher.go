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

	if blockSize != cipher.AESBlockSize {
		log.Fatalf("Deduced unsupported block size: %dB; must be 16B", blockSize)
	}

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

	postfix, err := analysis.DecryptECBPostfix(&oracle)
	if err != nil {
		log.Fatalf("Error decrypting ECB postfix: %v", err)
	}
	log.Printf("Decrypted ECB postfix to: %s", postfix)
}

func ecbCutAndPaste() {
	header(13, "ECB cut-and-paste")

	ctxt := make([]byte, 3*cipher.AESBlockSize)

	or := oracle.Profile{}

	// Recall the structure of the encrypted message:
	// email=%s&uid=10&role=user

	// First we need a ciphertext such that there will be a block boundary
	// after `&role=`. The fixed components of that string consist of 19
	// bytes, so we'll supply an e-mail address with 13 bytes, to hit 32
	// bytes.
	mailCtxt, err := or.Encrypt("johny@doe.com")
	if err != nil {
		log.Fatalf("Error querying encryption oracle: %v", err)
	}
	// We only care about the first two blocks
	copy(ctxt[:2*cipher.AESBlockSize], mailCtxt.Bytes[0:2*cipher.AESBlockSize])

	// Now we need a ciphertext such that there will be a block boundary
	// before `admin`, followed by valid PKCS#7 padding to fill up a block.
	// The fixed components in `email=` are 6 bytes, so we'll pick an
	// e-mail of 10 random characters, followed by `admin`, followed by a
	// valid padding to 16 bytes.
	email := "1234567890admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
	roleCtxt, err := or.Encrypt(email)
	if err != nil {
		log.Fatalf("Error querying encryption oracle: %v", err)
	}
	// We only care about the second block
	copy(ctxt[2*cipher.AESBlockSize:], roleCtxt.Bytes[1*cipher.AESBlockSize:])

	prof, err := or.Decrypt(ctxt)
	if err != nil {
		log.Fatalf("Error querying decryption oracle: %v", err)
	}

	log.Printf("Got profile: %+v", prof)
}
