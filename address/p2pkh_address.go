package main

import (
	"github.com/straysh/btcd/chaincfg"
	"github.com/straysh/go_mnemonic"
	"fmt"
	"github.com/straysh/btcutil/hdkeychain"
)

var testnet = chaincfg.TestNet3Params

func check(err error){
	if err!=nil {
		panic(err)
	}
}

func main(){
	mm,err := mnemonic.NewMnemonic(mnemonic.English);check(err)
	m,err := mm.FromMnemonic("valid butter basic write swear festival wedding popular expect bird special ivory", "")

	masterNode,err := hdkeychain.NewMaster(m.Seed(), &testnet)
	// m/44'/1'/0'/0/0
	node,_ := masterNode.Child(hdkeychain.HardenedKeyStart + 44)
	node,_ = node.Child(hdkeychain.HardenedKeyStart + 1)
	node,_ = node.Child(hdkeychain.HardenedKeyStart + 0)
	node,_ = node.Child(0)
	node,_ = node.Child(0)
	fmt.Println(node.Address(&testnet))
}