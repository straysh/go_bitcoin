package keychain

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

var testnet = &chaincfg.TestNet3Params
var path = "m/44'/1'/0'/0/0"
func Test_01(t *testing.T) {
	path := "m/44'/1'/0'/0/0"
	paths, err := parsePaths(path);check(err)
	fmt.Println(paths)
}

// valid butter basic write swear festival wedding popular expect bird special ivory
// external mp2WCcAHXN1DfzBEQd2RDagMYiLkWQscfC
// internal mxesoura7aK46ho1io9Leo251uhL9jHZJD
func Test_derive_p2pkh_address(t *testing.T) {
	seedHex := "6c8f0b35024d97d3a009c7e3ada15a96068bdbd6fb2a9dce4a6a675023487a5382f5d2462651f895d5635a1f1b379ab74b0af78d035342871228e80b210b4c46"
	keypairs,err := FromSeedHex(seedHex, testnet);check(err)
	addressNode,err := keypairs.DerivePath(path);check(err)
	address,err := addressNode.Address(0, true);check(err)

	fmt.Println(address.Script())
	fmt.Println(address.String())
	fmt.Println(address.EncodeAddress())
	fmt.Println(address.IsForNet(testnet))
}

func Test_derive_p2sh_address(t *testing.T) {
	// extended private key
	keypairs, err := FromString("tprv8jfaEnjF5G7Ajoaxc17htZDRe4AqLusCqPWUHGPomMyyEskmXxKyb5Rjg8J4bDqNQ2CifwBiXkGFwocRNU7XHhjJkyQhK1w192AJV9BhZSr", testnet);check(err)
	address,err := keypairs.Address(0, false);check(err)
	fmt.Println(address.String())

	// extended public key
	keypairs, err = FromString("tpubDGMcPCmVDdnqdGckVenJHxsYD5gmWF47Qh7FZnS7BdnN5N1YAM9Zma3brJ9PCb3b9FF4JpEhijAHNsSTv7cQWYQBxUZ4wX95SDPCv2fVNyV", testnet);check(err)
	address, err = keypairs.Address(0, false);check(err)
	fmt.Println(address.String())
}