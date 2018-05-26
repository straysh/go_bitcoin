package keychain

import (
	"testing"
	"fmt"
	"github.com/straysh/btcd/chaincfg"
	"github.com/straysh/btcd/txscript"
	"github.com/straysh/btcutil"
	"encoding/hex"
	"sort"
	"encoding/binary"
)

func check(err error) {
	if err!=nil {
		panic(err)
	}
}

var testnet = &chaincfg.TestNet3Params
var livenet = &chaincfg.MainNetParams
var network = livenet
var path = "m/44'/1'/0'/0/0"
func Test_01(t *testing.T) {
	path := "m/44'/1'/0'/0/0"
	paths, err := parsePaths(path);check(err)
	fmt.Println(paths)
}

func Test_02(t *testing.T) {
	buf := []byte{0x01, 0x02}
	fmt.Println(buf[0])
	fmt.Println(buf[1])

	fmt.Println(binary.LittleEndian.Uint16(buf))
	var a uint16 = 258
	binary.LittleEndian.PutUint16(buf, a)
	fmt.Println(buf)
}

func Test_derive_xpriv_xpub_to_address(t *testing.T) {
	// extended private key
	keypairs, err := FromString("tprv8jfaEnjF5G7Ajoaxc17htZDRe4AqLusCqPWUHGPomMyyEskmXxKyb5Rjg8J4bDqNQ2CifwBiXkGFwocRNU7XHhjJkyQhK1w192AJV9BhZSr", network);check(err)
	pubKey,err := keypairs.PublicKey(network)
	address,err := pubKey.AddressP2PKH();check(err)
	fmt.Println(address.String())

	// extended public key
	keypairs, err = FromString("tpubDGMcPCmVDdnqdGckVenJHxsYD5gmWF47Qh7FZnS7BdnN5N1YAM9Zma3brJ9PCb3b9FF4JpEhijAHNsSTv7cQWYQBxUZ4wX95SDPCv2fVNyV", network);check(err)
	pubKey,err = keypairs.PublicKey(network)
	address,err = pubKey.AddressP2PKH();check(err)
	fmt.Println(address.String())
}

// valid butter basic write swear festival wedding popular expect bird special ivory
// external mp2WCcAHXN1DfzBEQd2RDagMYiLkWQscfC
// internal mxesoura7aK46ho1io9Leo251uhL9jHZJD
func Test_derive_p2pkh_address(t *testing.T) {
	seedHex := "6c8f0b35024d97d3a009c7e3ada15a96068bdbd6fb2a9dce4a6a675023487a5382f5d2462651f895d5635a1f1b379ab74b0af78d035342871228e80b210b4c46"
	keypairs,err := FromSeedHex(seedHex, network);check(err)
	addressNode,err := keypairs.DerivePath(path);check(err)
	pubKey,err := addressNode.PublicKey(network);check(err)
	address,err := pubKey.AddressP2PKH();check(err)

	script, err := txscript.PayToAddrScript(address);check(err)
	disasm, err := txscript.DisasmString(script);check(err)
	fmt.Printf("address:%s\n", address)
	fmt.Println("Script Disassembly:", disasm)
}

// compressed pub: 03b86353fb740d8ad5a7de211a0e4cb36431df251cd44b5182df4dc171c80a953e
// 2N1kmtqVmshPhBq2bVHLWSEpE3bEvur2wQm
func Test_derive_p2sh_address(t *testing.T) {
	seedHex := "6c8f0b35024d97d3a009c7e3ada15a96068bdbd6fb2a9dce4a6a675023487a5382f5d2462651f895d5635a1f1b379ab74b0af78d035342871228e80b210b4c46"
	keypairs,err := FromSeedHex(seedHex, network);check(err)
	addressNode,err := keypairs.DerivePath(path);check(err)
	pubKey,err := addressNode.PublicKey(network);check(err)
	address,err := pubKey.AddressP2SH();check(err)

	script, err := txscript.PayToAddrScript(address);check(err)
	disasm, err := txscript.DisasmString(script);check(err)
	fmt.Printf("address:%s\n", address)
	fmt.Println("Script Disassembly:", disasm)
}

func Test_p2sh_address_1of1(t *testing.T) {
	privWIF := "cVJSo5oQQqRxiKUwUuF3SkakrM5PFz5rU2DijVsRM7TwEJMd2CrA"
	privKey,err := FromWIF(privWIF, network);check(err)
	pubKey := privKey.PublicKey();check(err)
	addrPubKey,err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(), network);check(err)
	addrPubKeySets := []*btcutil.AddressPubKey{addrPubKey}
	multiSigScript,err := txscript.MultiSigScript(addrPubKeySets, 1)

	address,err := btcutil.NewAddressScriptHash(multiSigScript, network);check(err)
	script, err := txscript.PayToAddrScript(address);check(err)
	fmt.Printf("Address: %s\n", address)
	disasm, err := txscript.DisasmString(script);check(err)
	fmt.Println("Script Disassembly:", disasm)
	fmt.Printf("script address:%x\n", address.ScriptAddress())
}

// polar lift divide evoke giraffe dance owner coil mention glance slow anger
// 03d562fe5c049396205711ebe77770f745375ab1c235f1b69d6875aa1aa0fecbec
// achieve trigger measure clap art intact wrist twice there absent purse behave
// 02868fef0aa17869fd132fda2a53823f71a4667468a0cc451b6a8534392acdf397
// age expose acid home copy horn olympic ask once vicious faint unique
// 03c25f23611ae6e898b6917ee24fd9d2b4224ac03a4f867ade7d0531c57a9e9cc8
func Test_p2sh_address_2of3(t *testing.T) {
	pub1,_ := hex.DecodeString("03d562fe5c049396205711ebe77770f745375ab1c235f1b69d6875aa1aa0fecbec")
	pub2,_ := hex.DecodeString("02868fef0aa17869fd132fda2a53823f71a4667468a0cc451b6a8534392acdf397")
	pub3,_ := hex.DecodeString("03c25f23611ae6e898b6917ee24fd9d2b4224ac03a4f867ade7d0531c57a9e9cc8")

	pubKey1,err := btcutil.NewAddressPubKey(pub1, network);check(err)
	pubKey2,err := btcutil.NewAddressPubKey(pub2, network);check(err)
	pubKey3,err := btcutil.NewAddressPubKey(pub3, network);check(err)
	addrPubKeySets := []*btcutil.AddressPubKey{pubKey1, pubKey2, pubKey3}
	sort.Slice(addrPubKeySets, func(i,j int) bool {
		a := addrPubKeySets[i]
		b := addrPubKeySets[j]
		return a.String() < b.String()
	})
	multiSigScript,err := txscript.MultiSigScript(addrPubKeySets, 2)

	address,err := btcutil.NewAddressScriptHash(multiSigScript, network);check(err)
	script, err := txscript.PayToAddrScript(address);check(err)
	fmt.Printf("Address: %s\n", address)
	disasm, err := txscript.DisasmString(script);check(err)
	fmt.Println("Script Disassembly:", disasm)
}

func Test_p2pkh_address_2of3(t *testing.T) {
	pub1,_ := hex.DecodeString("03d562fe5c049396205711ebe77770f745375ab1c235f1b69d6875aa1aa0fecbec")
	pub2,_ := hex.DecodeString("02868fef0aa17869fd132fda2a53823f71a4667468a0cc451b6a8534392acdf397")
	pub3,_ := hex.DecodeString("03c25f23611ae6e898b6917ee24fd9d2b4224ac03a4f867ade7d0531c57a9e9cc8")

	pubKey1,err := btcutil.NewAddressPubKey(pub1, network);check(err)
	pubKey2,err := btcutil.NewAddressPubKey(pub2, network);check(err)
	pubKey3,err := btcutil.NewAddressPubKey(pub3, network);check(err)
	addrPubKeySets := []*btcutil.AddressPubKey{pubKey1, pubKey2, pubKey3}
	sort.Slice(addrPubKeySets, func(i,j int) bool {
		a := addrPubKeySets[i]
		b := addrPubKeySets[j]
		return a.String() < b.String()
	})
	multiSigScript,err := txscript.MultiSigScript(addrPubKeySets, 2)
	disasm, err := txscript.DisasmString(multiSigScript);check(err)
	fmt.Println("Script Disassembly:", disasm)

	sha160 := btcutil.Hash160(multiSigScript)
	address,err := btcutil.NewAddressPubKeyHash(sha160, network);check(err)
	script, err := txscript.PayToAddrScript(address);check(err)
	fmt.Printf("Address: %s\n", address)
	disasm, err = txscript.DisasmString(script);check(err)
	fmt.Println("Script Disassembly:", disasm)
}

func Test_p2wpkh_address(t *testing.T) {
	//seedHex := "6c8f0b35024d97d3a009c7e3ada15a96068bdbd6fb2a9dce4a6a675023487a5382f5d2462651f895d5635a1f1b379ab74b0af78d035342871228e80b210b4c46"
	//keypairs,err := FromSeedHex(seedHex, network);check(err)
	//addressNode,err := keypairs.DerivePath(path);check(err)
	//pubKey,err := addressNode.PublicKey(network);check(err)

	//pubKey,err := UnserializeUncompressed("0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6", livenet)
	pubKey,err := UnserializeCompressed("0349608f455903be157dc4b94343d7df7a701b8cb3cfb923fbcebd122b2d7369d7", livenet)
	address,err := pubKey.AddressP2PKH();check(err)
	script, err := txscript.PayToAddrScript(address);check(err)
	disasm, err := txscript.DisasmString(script);check(err)
	fmt.Printf("address P2PKH:%s\n", address)
	fmt.Println("Script Disassembly:\n", disasm)

	address1,err := pubKey.AddressP2WPKH();check(err)
	fmt.Printf("P2WPKH %s:\n", address1.String())

	address2,err := pubKey.AddressP2WSH();check(err)
	fmt.Printf("P2WSH %s:\n", address2.String())
}
