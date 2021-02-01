package main

import (
	"fmt"
	"github.com/bernix/cosmos-key-sign/keys"
)

const (
	// the human readable part for bech32 encoding
	hrp string = "cosmos"
	// the default bip44 path
	// m / purpose' / coinType' / account' / change / addressIndex
	defaultHdPath string = "44'/118'/0'/0/0"
)

func main() {
	mnemonic, addr, privkey := keys.GenKey(hrp, defaultHdPath)
	fmt.Println(" ----------------------------- ")
	fmt.Println("mnemonic: ", mnemonic)
	fmt.Println("address:  ", addr)
	fmt.Printf("privkey:   %x\n", privkey)
}
