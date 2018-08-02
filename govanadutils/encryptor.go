package govanadutils

import (
	"crypto/aes"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/scrypt"
)

const (
	n      = 16384
	r      = 8
	p      = 8
	length = 64
)

// Encryptor The struct which contains password to encrypt the private key
type Encryptor struct {
	password string
}

// SetPassword Set the password to encrypt the private key
func (e *Encryptor) SetPassword(pw *string) {
	if pw != nil && *pw != "" {
		(*e).password = *pw
	}
}

// EncryptPrivKey Encrypt a private key if a password is set
func (e *Encryptor) EncryptPrivKey(bts *BtcKeySet, isCompressed bool) (string, error) {
	if (*e).password != "" {
		encrypted, err := bip38((*e).password, bts, isCompressed)
		if err != nil {
			return "", fmt.Errorf("EncryptPrivKey failed: %v", err)
		}

		return encrypted, nil
	}

	var encodeFormat string
	if isCompressed {
		encodeFormat = "wif-compressed"
	} else {
		encodeFormat = "wif"
	}
	return bts.GetPrivKey(encodeFormat)
}

// bip38 Do encryption with no EC multiply flag used (BIP0038)
func bip38(pw string, bks *BtcKeySet, isCompressed bool) (string, error) {
	var flagByte byte
	if isCompressed {
		flagByte = byte(0xe0)
	} else {
		flagByte = byte(0xc0)
	}

	salt, err := getAddrHash(bks, isCompressed)
	if err != nil {
		return "", fmt.Errorf("bip38 failed: %v", err)
	}

	derived, err := scrypt.Key([]byte(pw), salt, n, r, p, length)
	if err != nil {
		return "", fmt.Errorf("bip38 failed: %v", err)
	}

	encrypted, err := encrypt((*bks).privKey.D.Bytes(), derived[:32], derived[32:])
	if err != nil {
		return "", fmt.Errorf("bip38 failed: %v", err)
	}

	privKey := make([]byte, 39)
	privKey[0], privKey[1], privKey[2] = byte(0x01), byte(0x42), flagByte
	copy(privKey[3:], salt)
	copy(privKey[7:], encrypted)

	return base58.Encode(addCheckSum(privKey)), nil
}

// getAddrHash Get the addresshash as a salt
func getAddrHash(bks *BtcKeySet, isCompressed bool) ([]byte, error) {
	addr, err := (*bks).GetAddr(isCompressed)
	if err != nil {
		return nil, fmt.Errorf("getAddrHash failed: %v", err)
	}

	completeHash := hash256([]byte(addr))
	return completeHash[:4], nil
}

// hash256 Do SHA256(SHA256(in)).
func hash256(in []byte) []byte {
	h1 := sha256.New()
	h2 := sha256.New()

	h1.Write(in)
	h2.Write(h1.Sum(nil))

	return h2.Sum(nil)
}

// encrypt Do encryption
func encrypt(pk, d1, d2 []byte) ([]byte, error) {
	c, err := aes.NewCipher(d2)
	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %v", err)
	}

	for i := range d1 {
		d1[i] ^= pk[i]
	}

	e1 := make([]byte, 16)
	e2 := make([]byte, 16)
	c.Encrypt(e1, d1[:16])
	c.Encrypt(e2, d1[16:])

	return append(e1, e2...), nil
}

// addCheckSum add the checksum for a []byte
func addCheckSum(in []byte) []byte {
	out := append(in, hash256(in)[:4]...)
	return out
}
