package keychain

import (
	"github.com/straysh/btcutil/hdkeychain"
	"github.com/straysh/btcd/chaincfg"
	"strings"
	"errors"
	"strconv"
	"encoding/hex"
	"github.com/straysh/go_bitcoin/address"
	"github.com/straysh/btcutil"
)

type keypairs struct {
	masterNode *hdkeychain.ExtendedKey
	accountNode *hdkeychain.ExtendedKey
	index int
	isChange bool
	wif *btcutil.WIF
	node *hdkeychain.ExtendedKey
	network *chaincfg.Params
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
	masterNode,err := hdkeychain.NewKeyFromString(key)
	if err!=nil { return nil, err }

	keypair := &keypairs{}
	keypair.masterNode = masterNode
	keypair.network = network
	return keypair, nil
}

// strict BIP44 protocol
func (keypair *keypairs) DerivePath(path string) (*keypairs, error) {
	// m/44'/1'/0'/0/0
	paths,_ := parsePaths(path)
	node,_ := keypair.getAccountNode(paths[:3])

	node,_ = node.Child( uint32(paths[3]) )
	node,_ = node.Child( uint32(paths[4]) )
	keypair.node = node
	keypair.index = paths[3]
	keypair.isChange = false;if paths[4]==1 {keypair.isChange=true}
	return keypair, nil
}
func (keypair *keypairs) getAccountNode(paths []int) (*hdkeychain.ExtendedKey, error) {
	var node *hdkeychain.ExtendedKey
	if keypair.accountNode == nil {
		node,_ = keypair.masterNode.Child(hdkeychain.HardenedKeyStart + 44)
		node,_ = node.Child(hdkeychain.HardenedKeyStart + 1)
		node,_ = node.Child(hdkeychain.HardenedKeyStart + 0)
		keypair.accountNode = node
	} else {
		node = keypair.accountNode
	}
	return node, nil
}

func (keypair *keypairs) Address(index int, isChange bool) (*address.Address, error) {
	if keypair.node != nil {
		if keypair.accountNode!=nil && (keypair.index!=index || keypair.isChange!=isChange) {
			change := uint32(0);if isChange {change = uint32(1)}
			node,_ := keypair.accountNode.Child(change)
			node,_ = node.Child(uint32(index))
			keypair.node = node
			keypair.index = index
			keypair.isChange = isChange
			addr,err := keypair.node.Address(keypair.network)
			if err!=nil { return nil, err }
			return &address.Address{Address: addr}, nil
		} else {
			addr,err := keypair.node.Address(keypair.network)
			if err!=nil { return nil, err }
			return &address.Address{Address: addr}, nil
		}
	} else if keypair.masterNode!=nil {
		addr,err := keypair.masterNode.Address(keypair.network)
		if err!=nil { return nil, err }
		return &address.Address{Address: addr}, nil
	} else {
		return nil, errors.New("uninitiated keypair")
	}
}
