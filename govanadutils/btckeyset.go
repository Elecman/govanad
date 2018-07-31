package govanadutils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	qrcode "github.com/skip2/go-qrcode"
)

// BtcKeySet The struct which contains private key and public key
type BtcKeySet struct {
	privKey *btcec.PrivateKey
	pubKey  *btcec.PublicKey
}

// GenKeySet Generate a new bitcoin secret key set
func (bks *BtcKeySet) GenKeySet() {
	// generate a private key
	curve := btcec.S256()
	privKey, err := btcec.NewPrivateKey(curve)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Generating private key failed: %v", err)
	}

	bks.privKey = privKey
	bks.pubKey = privKey.PubKey()
}

// GetPrivKey Returns the private key encoded in the specified format
// format: ("decimal", "hex", "hex-compressed", "wif", "wif-compressed")
func (bks *BtcKeySet) GetPrivKey(format string) (string, error) {
	if bks.privKey == nil {
		return "", errors.New("the private key is nil")
	}
	switch format {
	case "decimal":
		return bks.privKey.D.String(), nil
	case "hex":
		return hex.EncodeToString(bks.privKey.Serialize()), nil
	case "hex-compressed":
		return hex.EncodeToString(bks.privKey.Serialize()) + "01", nil
	case "wif":
		return base58.CheckEncode(bks.privKey.Serialize(), 128), nil
	case "wif-compressed":
		return base58.CheckEncode(append(bks.privKey.Serialize(), 1), 128), nil
	default:
		return "", fmt.Errorf("%s is not a supported format", format)
	}
}

// GetPubKey Returns the public key encoded in the specified format
// format: ("hex", "hex-compressed", "point")
func (bks *BtcKeySet) GetPubKey(format string) (string, error) {
	if bks.pubKey == nil {
		return "", errors.New("the public key is nil")
	}
	switch format {
	case "hex":
		return hex.EncodeToString(bks.pubKey.SerializeUncompressed()), nil
	case "hex-compressed":
		return hex.EncodeToString(bks.pubKey.SerializeCompressed()), nil
	case "point":
		return fmt.Sprintf("(X: %d, Y: %d)", bks.pubKey.X, bks.pubKey.Y), nil
	default:
		return "", fmt.Errorf("%s is not a supported format", format)
	}
}

// GetAddr Get the bitcoin address by the given key
func (bks *BtcKeySet) GetAddr(isCompressed bool) (string, error) {
	if bks.pubKey == nil {
		return "", errors.New("the public key is nil")
	}

	var binPubKey []byte
	if isCompressed {
		binPubKey = bks.pubKey.SerializeCompressed()
	} else {
		binPubKey = bks.pubKey.SerializeUncompressed()
	}
	btcAddr := base58.CheckEncode(btcutil.Hash160(binPubKey), 0)
	return btcAddr, nil
}

// PrintKeyAddr Print the vanity address and the associated key set
func (bks *BtcKeySet) PrintKeyAddr(encrp *Encryptor) {
	if bks.privKey == nil || bks.pubKey == nil {
		return
	}

	// Private Key
	fmt.Println("------ Private Key ------")
	wifPrivKey, err := encrp.Encrypt(bks, false)
	cmpWIFPrivKey, err := encrp.Encrypt(bks, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Printing private key failed: %v", err)
		return
	}
	fmt.Printf("Private Key (WIF) is : %s\n", wifPrivKey)
	fmt.Printf("Private Key Compressed (WIF) is: %s\n\n", cmpWIFPrivKey)

	// Public Key
	fmt.Println("------ Public Key ------")
	hexPubKey, err := bks.GetPubKey("hex")
	cmpHexPubKey, err := bks.GetPubKey("hex-compressed")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Printing public key failed: %v", err)
		return
	}
	fmt.Printf("Public Key (hex) is:  %s\n", hexPubKey)
	fmt.Printf("Compressed Public Key (hex) is:  %s\n\n", cmpHexPubKey)

	// Bitcoin Addr
	fmt.Println("------ Bitcoin Address ------")
	btcAddr, err := bks.GetAddr(false)
	cmpBTCAddr, err := bks.GetAddr(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Printing bitcoin address failed: %v", err)
		return
	}
	fmt.Printf("Bitcoin Address (b58check) is:  %s\n", btcAddr)
	fmt.Printf("Compressed Bitcoin Address (b58check) is:  %s\n\n", cmpBTCAddr)
}

// CreateQR Create the QR code images
func (bks *BtcKeySet) CreateQR(encrp *Encryptor) {
	btcAddr, err := bks.GetAddr(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating bitcoin address QR image failed: %v", err)
		return
	}

	err = qrcode.WriteFile(btcAddr, qrcode.Medium, 256, "qr_bitcoin_addr.png")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating bitcoin address QR image failed: %v", err)
	}

	wifPrivKey, err := encrp.Encrypt(bks, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating private key QR image failed: %v", err)
		return
	}

	err = qrcode.WriteFile(wifPrivKey, qrcode.Medium, 256, "qr_private_key.png")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating bitcoin address QR image failed: %v", err)
	}
}
