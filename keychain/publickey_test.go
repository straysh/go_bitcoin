package keychain

import (
	"testing"
	"fmt"
)

func Test_priv_to_pub(t *testing.T) {
	//target 03b86353fb740d8ad5a7de211a0e4cb36431df251cd44b5182df4dc171c80a953e
	wif := "cPXN9T9fdZkQsqUs4BVhNLgFg5xU2TTvyh3F3tTrgUrTNDQJNWj5"
	privkey,err := FromWIF(wif, testnet);check(err)
	pubkey := privkey.PublicKey()
	fmt.Println(pubkey.String())
	fmt.Println(pubkey.Address())
}


func Test_Unserialize_compressed(t *testing.T) {
	pubCompressed := "03b86353fb740d8ad5a7de211a0e4cb36431df251cd44b5182df4dc171c80a953e"
	pub,err := UnserializeCompressed(pubCompressed, testnet);check(err)
	fmt.Println(pub.Address())
}

func Test_Unserialize_uncompressed(t *testing.T) {
	pubUncompressed := "04b86353fb740d8ad5a7de211a0e4cb36431df251cd44b5182df4dc171c80a953eee9de0166959d81687f3c3c0f9090a280db42de52d6bbaef05e3865ab1baf3f3"
	pub,err := UnserializeUncompressed(pubUncompressed, testnet);check(err)
	fmt.Println(pub.Address())
}