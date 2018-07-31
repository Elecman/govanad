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
	head := flag.String("head", "", "Your wanted bitcoin vanity address head string, the first character '1' will be added automatically.")
	pwd := flag.String("pw", "", "The password to encrypt your private key, do Not set if you want to get unencrypted private key. !! UNFINISHED FEATURE !!")
	qrImg := flag.Bool("qr", false, "If you want to create QR code images?")
	flag.Parse()

	// set the address head
	var wantHead = "1"
	wantHead += *head

	// set the encrypt function
	var encrp utils.Encryptor
	(&encrp).SetPassword(pwd)

	// clock the process
	startTime := time.Now().Unix()

	// look for the specified vanity address
	var bks utils.BtcKeySet
	for {
		(&bks).GenKeySet()
		addr, err := (&bks).GetAddr(false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Gohoad looking for the vanity address failed: %v", err)
			return
		}
		if strings.HasPrefix(addr, wantHead) {
			break
		}
	}

	// print result
	fmt.Printf("Got the vanity address starts with \"%s\", time costs: %ds\n", wantHead, time.Now().Unix()-startTime)
	(&bks).PrintKeyAddr(&encrp)

	// create QR code images
	if *qrImg {
		(&bks).CreateQR(&encrp)
	}
}
