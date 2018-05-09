package hdkeychain

import (
	"testing"
	"fmt"
	"github.com/straysh/btcd/chaincfg"
)

func check(err error) {
	if err!=nil {
		panic(err)
	}
}

var testnet = chaincfg.TestNet3Params
func Test_01(t *testing.T) {
	path := "m/44'/1'/0'/0/0"
	paths, err := parsePaths(path);check(err)
	fmt.Println(paths)
}

// valid butter basic write swear festival wedding popular expect bird special ivory
func Test_derive_path(t *testing.T) {
	path := "m/44'/1'/0'/0/0"
	seedHex := "6c8f0b35024d97d3a009c7e3ada15a96068bdbd6fb2a9dce4a6a675023487a5382f5d2462651f895d5635a1f1b379ab74b0af78d035342871228e80b210b4c46"
	keypairs,err := FromSeedHex(seedHex, &testnet);check(err)
	addressNode,err := keypairs.DerivePath(path);check(err)
	address,err := addressNode.Address(0, false);check(err)

	fmt.Println(address.String())
	fmt.Println(address.ScriptAddress())
	fmt.Println(address.EncodeAddress())
	fmt.Println(address.IsForNet(&testnet))
}