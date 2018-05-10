package keychain

import (
	"github.com/straysh/btcd/btcec"
	"encoding/hex"
	"github.com/straysh/btcd/chaincfg"
	"github.com/straysh/go_bitcoin/address"
	"github.com/straysh/btcutil"
	"math/big"
	"errors"
)

const (
	pubkeyCompressed   byte = 0x2 // y_bit + x coord
	pubkeyUncompressed byte = 0x4 // x coord + y coord
	pubkeyHybrid       byte = 0x6 // y_bit + x coord + y coord
)

type PublicKey struct {
	*btcec.PublicKey
	Network *chaincfg.Params
	IsCompressed bool
}

func UnserializeCompressed(pubstr string, network *chaincfg.Params) (*PublicKey, error) {
	buf,err := hex.DecodeString(pubstr)
	if err!=nil { return nil, err }

	var y *big.Int
	xBuf := buf[1:]
	x := new(big.Int).SetBytes(xBuf)
	if buf[0] == pubkeyCompressed {
		y = fromX(x, false)
	} else if buf[0] == pubkeyCompressed|0x1 {
		y = fromX(x, true)
	} else {
		return nil, errors.New("invalid compressed pubkey")
	}

	pub := &PublicKey{
		PublicKey: &btcec.PublicKey{
			Curve: btcec.S256(),
			X: x,
			Y: y,
		},
		Network: network,
		IsCompressed: true,
	}
	return pub, nil
}

func UnserializeUncompressed(pubstr string, network *chaincfg.Params) (*PublicKey, error) {
	buf,err := hex.DecodeString(pubstr)
	if err!=nil { return nil, err }

	xBuf := buf[1 :33]
	yBuf := buf[33:65]
	if len(xBuf)!=32 || len(yBuf)!=32 || len(buf)!=65 {
		return nil, errors.New("length of x and y must be 32 bytes")
	}

	x := new(big.Int).SetBytes(xBuf)
	y := new(big.Int).SetBytes(yBuf)
	pub := &PublicKey{
		PublicKey: &btcec.PublicKey{
			Curve: btcec.S256(),
			X: x,
			Y: y,
		},
		Network: network,
		IsCompressed: false,
	}
	return pub, nil
}

func (pub *PublicKey) String() string {
	pubBuf := pub.PublicKey.SerializeCompressed()
	pubHex := hex.EncodeToString(pubBuf)
	return pubHex
}

func (pub *PublicKey) Address() (*address.Address, error) {
	pkHash := btcutil.Hash160(pub.SerializeCompressed())
	addr,err := btcutil.NewAddressPubKeyHash(pkHash, pub.Network)
	if err!=nil { return nil, err }
	return &address.Address{Address: addr}, nil
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// secp256k1: y² = x³ + 7
// https://en.bitcoin.it/wiki/Secp256k1
// https://bitcoin.stackexchange.com/questions/21907/what-does-the-curve-used-in-bitcoin-secp256k1-look-like
// https://bitcoin.stackexchange.com/questions/25382/bitcoin-private-key-location-on-ecc-curve
// https://bitcoin.stackexchange.com/questions/48544/how-do-i-convert-public-key-x-value-to-y-in-python-and-verify
// https://bitcoin.stackexchange.com/questions/38740/bitcoin-how-to-get-x-value-from-y
// https://bitcoin.stackexchange.com/questions/25024/how-do-you-get-a-bitcoin-public-key-from-a-private-key?rq=1
func fromX(x *big.Int, odd bool) *big.Int {
	B,_ := new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	P,_ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	x1 := new(big.Int).Mul(x, x)
	x1.Mul(x1, x)
	x1.Add(x1, B)
	//x2 := new(big.Int).Sqrt(x1)
	y := new(big.Int).ModSqrt(x1, P)
	//if left.Bit(0)!=0 {
	if odd!=isOdd(y) {
		y.Sub(P, y)
	}
	return y
}