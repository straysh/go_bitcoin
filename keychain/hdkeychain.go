package keychain

import (
	"github.com/straysh/btcutil/hdkeychain"
	"github.com/straysh/btcd/chaincfg"
	"strings"
	"errors"
	"strconv"
	"encoding/hex"
	"github.com/straysh/btcutil"
)

type keypairs struct {
	masterNode *hdkeychain.ExtendedKey  // root node
	wif *btcutil.WIF
	node *hdkeychain.ExtendedKey // address node
	network *chaincfg.Params
	privKey *PrivateKey
	pubKey *PublicKey
}

func parsePaths(path string) ([]int, error) {
	paths := strings.Split(path, "/")
	if paths[0]!="m" && paths[0]!="M" {
		return nil, errors.New("path should leadingg with m or M")
	}

	var results [5]int
	for p,seg := range paths[1:] {
		isHarden := false
		if l:=len(seg); seg[l-1:] == "'" {
			isHarden = true
			seg = seg[:l-1]
		}
		index,err := strconv.ParseUint(seg, 0, 32)
		if err!=nil { return nil, err }
		if isHarden {
			index += hdkeychain.HardenedKeyStart
		}

		results[p] = int(index)
	}

	return results[:], nil
}

// seed 512 bits or 64 bytes
func FromSeed(seed []byte, network *chaincfg.Params) (*keypairs, error) {
	masterNode,err := hdkeychain.NewMaster(seed, network)
	if err!=nil { return nil, err }

	keypair := &keypairs{}
	keypair.masterNode = masterNode
	keypair.network = network
	return keypair, nil
}
func FromSeedHex(seedHex string, network *chaincfg.Params) (*keypairs, error) {
	seed,err := hex.DecodeString(seedHex)
	if err!=nil { return nil, err }
	return FromSeed(seed, network)
}

func FromString(key string, network *chaincfg.Params) (*keypairs, error) {
	node,err := hdkeychain.NewKeyFromString(key)
	if err!=nil { return nil, err }

	keypair := &keypairs{}
	keypair.node = node
	keypair.network = network
	return keypair, nil
}

// strict BIP44 protocol
func (keypair *keypairs) DerivePath(path string) (*keypairs, error) {
	// m/44'/1'/0'/0/0
	paths,_ := parsePaths(path)
	node,_ := keypair.masterNode.Child(hdkeychain.HardenedKeyStart + 44)
	node,_ = node.Child(hdkeychain.HardenedKeyStart + 1)
	node,_ = node.Child(hdkeychain.HardenedKeyStart + 0)
	node,_ = node.Child( uint32(paths[3]) )
	node,_ = node.Child( uint32(paths[4]) )
	keypair.node = node
	return keypair, nil
}

func (keypair *keypairs) PrivateKey(network *chaincfg.Params) (*PrivateKey, error) {
	if keypair.privKey!=nil {
		return keypair.privKey, nil
	}

	privKey,err := keypair.node.ECPrivKey()
	if err!=nil { return nil, err}
	keypair.privKey = &PrivateKey{
		Network: network,
		PrivateKey: privKey,
	}
	return keypair.privKey, nil
}

func (keypair *keypairs) PublicKey(network *chaincfg.Params) (*PublicKey, error) {
	if keypair.pubKey!=nil {
		return keypair.pubKey, nil
	}

	pubKey, err := keypair.node.ECPubKey()
	if err!=nil { return nil, err }
	keypair.pubKey = &PublicKey{
		Network: network,
		PublicKey: pubKey,
	}
	return keypair.pubKey, nil
}