package govanadutils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	qrcode "github.com/skip2/go-qrcode"
)

// BtcKeySet The struct which contains private key and public key
type BtcKeySet struct {
	privKey *btcec.PrivateKey
	pubKey  *btcec.PublicKey
	Encrp   *Encryptor
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
		return "", errors.New("GetPrivKey: the private key is nil")
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
		return "", fmt.Errorf("GetPrivKey: \"%s\" is not a supported format", format)
	}
}

// GetPubKey Returns the public key encoded in the specified format
// format: ("hex", "hex-compressed", "point")
func (bks *BtcKeySet) GetPubKey(format string) (string, error) {
	if bks.pubKey == nil {
		return "", errors.New("GetPubKey: the public key is nil")
	}
	switch format {
	case "hex":
		return hex.EncodeToString(bks.pubKey.SerializeUncompressed()), nil
	case "hex-compressed":
		return hex.EncodeToString(bks.pubKey.SerializeCompressed()), nil
	case "point":
		return fmt.Sprintf("(X: %d, Y: %d)", bks.pubKey.X, bks.pubKey.Y), nil
	default:
		return "", fmt.Errorf("GetPubKey: \"%s\" is not a supported format", format)
	}
}

// GetAddr Get the bitcoin address by the given key
func (bks *BtcKeySet) GetAddr(isCompressed bool) (string, error) {
	if bks.pubKey == nil {
		return "", errors.New("GetAddr: the public key is nil")
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

// stringifyOutput stringify the vanity and output to the specified IO writer
func (bks *BtcKeySet) stringifyOutput(out io.Writer) {
	// get keys and addresses
	var txtContent outputData
	err := txtContent.setOutputData(bks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stringifyOutput failed: %v", err)
		return
	}

	txtTmpl := template.Must(template.New("txt").Parse(tmpl))
	txtTmpl.Execute(out, txtContent)
}

// CreateQR Create the QR code images
func (bks *BtcKeySet) CreateQR(timestamp int64) {
	encrp := *bks.Encrp

	// create private key QR image
	if wifPrivKey, err := encrp.Encrypt(bks, false); err != nil {
		fmt.Fprintf(os.Stderr, "Creating private key QR image failed: %v", err)
	} else {
		privKeyImg := fmt.Sprintf("%d_qr_private_key.png", timestamp)
		err = qrcode.WriteFile(wifPrivKey, qrcode.Medium, 256, privKeyImg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Creating bitcoin address QR image failed: %v", err)
		}
	}

	// create bitcoin address QR image
	if btcAddr, err := bks.GetAddr(false); err != nil {
		fmt.Fprintf(os.Stderr, "Creating bitcoin address QR image failed: %v", err)
	} else {
		addrQRImg := fmt.Sprintf("%d_qr_bitcoin_addr.png", timestamp)
		err = qrcode.WriteFile(btcAddr, qrcode.Medium, 256, addrQRImg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Creating bitcoin address QR image failed: %v", err)
		}
	}
}

// CreateTxt Create text file that includes keys and addresses
func (bks *BtcKeySet) CreateTxt(timestamp int64) {
	// create text file
	fileName := fmt.Sprintf("%d_txt_keyaddr.txt", timestamp)
	f, err := os.Create(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating text file failed: %v", err)
		return
	}
	defer f.Close()

	// output
	bks.stringifyOutput(f)
}

// PrintKeyAddr Print the vanity address and the associated key set
func (bks *BtcKeySet) PrintKeyAddr() {
	if bks.privKey == nil || bks.pubKey == nil {
		return
	}

	// output
	bks.stringifyOutput(os.Stdout)
}
