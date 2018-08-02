package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	utils "github.com/loonos/govanad/govanadutils"
)

func main() {
	// parse the flags
	vh := flag.String("v", "", "Your wanted bitcoin vanity address head string, the first character '1' will be added automatically.")
	pw := flag.String("p", "", "The password to encrypt your private key, do Not set if you want to get unencrypted private key.")
	qr := flag.Bool("q", false, "Do you want to create the QR code images?")
	tf := flag.Bool("t", false, "Do you want to create a text file that includes your keys & addersses?")
	flag.Parse()

	// set the address head
	var vanityHead = "1" + *vh

	defer trace(vanityHead)()

	// look for the specified vanity address
	var bks utils.BtcKeySet
	for {
		(&bks).GenKeySet()
		addr, err := (&bks).GetAddr(false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Gohoad looking for the vanity address failed: %v", err)
			return
		}
		if strings.HasPrefix(addr, vanityHead) {
			break
		}
	}

	// set the encrypt function
	var encrp utils.Encryptor
	(&encrp).SetPassword(pw)
	bks.Encrp = &encrp

	timestamp := time.Now().Unix()

	// create QR code images
	if *qr {
		(&bks).CreateQR(timestamp)
	}

	// create text file
	if *tf {
		(&bks).CreateTxt(timestamp)
	}

	// print result to console if no file created
	if !(*qr) && !(*tf) {
		(&bks).PrintKeyAddr()
	}
}

// trace Print start and end with timestamps
func trace(msg string) func() {
	layout := "2006-01-02 15:04:05"
	start := time.Now()
	fmt.Printf("[%s]: Start looking for the vanity address starts with \"%s\"\n\n", start.Format(layout), msg)
	return func() {
		end := time.Now()
		fmt.Printf("\n[%s]: Stop looking for the vanity address, time costs: %s\n", end.Format(layout), time.Since(start))
	}
}
