package main

import (
	"log"

	"github.com/Lavode/cryptopals/padding"
)

func pkcs7Padding() {
	header(9, "Implement PKCS#7 padding")

	msg := []byte("YELLOW SUBMARINE")
	padded := padding.PKCS7Pad(msg, 20)

	log.Printf("Message %x padded to %x", msg, padded)
}
