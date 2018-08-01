package govanadutils

const tmpl = `=========================================================================
                Bitcoin vanity address created by govanad
=========================================================================

Private Key (WIF):                     {{.PrivKey}}
Compressed Private Key (WIF) :         {{.CmpPrivKey}}

Public Key (hex):                      {{.PubKey}}
Compressed Public Key (hex):           {{.CmpPubKey}}

Bitcoin Address (b58check):            {{.BtcAddr}}
Compressed Bitcoin Address (b58check): {{.CmpBtcAddr}}

=========================================================================
`

type outputData struct {
	PrivKey    string
	CmpPrivKey string
	PubKey     string
	CmpPubKey  string
	BtcAddr    string
	CmpBtcAddr string
}

func (od *outputData) setOutputData(bks *BtcKeySet) error {
	var err error
	encrp := *bks.Encrp
	(*od).PrivKey, err = encrp.Encrypt(bks, false)
	(*od).CmpPrivKey, err = encrp.Encrypt(bks, true)
	(*od).PubKey, err = bks.GetPubKey("hex")
	(*od).CmpPubKey, err = bks.GetPubKey("hex-compressed")
	(*od).BtcAddr, err = bks.GetAddr(false)
	(*od).CmpBtcAddr, err = bks.GetAddr(true)
	return err
}
