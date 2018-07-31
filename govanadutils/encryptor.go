package govanadutils

import (
	"fmt"
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

// Encrypt Encode and encrypt the private key
func (e *Encryptor) Encrypt(bts *BtcKeySet, isCompressed bool) (string, error) {
	var encodeFormat string
	if isCompressed {
		encodeFormat = "wif-compressed"
	} else {
		encodeFormat = "wif"
	}
	privKey, err := bts.GetPrivKey(encodeFormat)
	if err != nil {
		return "", fmt.Errorf("Encrypt private key failed: %v", err)
	}
	if e.password != "" {
		// todo: return encrypted (BIP0038) private key
	}
	return privKey, nil
}
