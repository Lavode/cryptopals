package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		usage()
	}

	set, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("Invalid set\n")
		os.Exit(1)
	}

	challenge, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Printf("Invalid challenge\n")
		os.Exit(1)
	}

	switch set {
	case 1:
		switch challenge {
		case 1:
			HexToBase64()
		case 2:
			FixedXor()
		default:
			fmt.Println("Challenge outside of allowed range for given set")
		}
	default:
		fmt.Println("Set outside of allowed range.")
	}
}

func usage() {
	fmt.Printf("Usage: ./cryptopals <set> <challenge>\n")
	fmt.Printf("Example: ./cryptopals 1 3\n")
	os.Exit(1)
}
