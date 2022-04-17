package main

import (
	"log"

	"github.com/Lavode/cryptopals/cipher"
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

	msg, err := cipher.AESCBCDecrypt(ctxt, key, iv)
	if err != nil {
		log.Fatalf("Error decrypting AES-CBC ciphertext: %v", err)
	}

	log.Printf("Decrypted AES-CBC ciphertext: %s", msg)
}
