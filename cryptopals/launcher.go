package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	challenge, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("Invalid challenge\n")
		os.Exit(1)
	}

	switch challenge {
	case 1:
		hexToBase64()
	case 2:
		fixedXor()
	case 3:
		singleByteXor()
	case 4:
		detectSingleByteXor()
	case 5:
		repeatingKeyXor()
	case 6:
		breakRepeatingKeyXor()
	case 7:
		decryptAesECB()
	case 8:
		detectAesEcb()
	case 9:
		pkcs7Padding()
	case 10:
		cbcDecrypt()
	default:
		fmt.Println("Challenge outside of allowed range")
	}
}

func usage() {
	fmt.Printf("Usage: ./cryptopals <challenge>\n")
	fmt.Printf("Example: ./cryptopals 3\n")
	os.Exit(1)
}
