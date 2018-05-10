package keychain

import (
	"testing"
	"fmt"
)

func Test_from_wif(t *testing.T) {
	wif := "cPXN9T9fdZkQsqUs4BVhNLgFg5xU2TTvyh3F3tTrgUrTNDQJNWj5"
	privkey,err := FromWIF(wif, testnet);check(err)
	fmt.Println(privkey.Address())
}
