package keychain

import (
	"github.com/straysh/btcd/btcec"
	"github.com/straysh/btcd/chaincfg"
	"github.com/straysh/btcutil/base58"
	"github.com/straysh/btcd/chaincfg/chainhash"
	"bytes"
	"errors"
	"github.com/straysh/go_bitcoin/address"
	"github.com/straysh/btcutil"
)

type PrivateKey struct {
	Network *chaincfg.Params
	*btcec.PrivateKey
}

// compressMagic is the magic byte used to identify a WIF encoding for
// an address created from a compressed serialized public key.
const compressMagic byte = 0x01

func FromWIF(wif string, network *chaincfg.Params) (*PrivateKey, error) {
	decoded := base58.Decode(wif)
	decodedLen := len(decoded)
	var compress bool

	// Length of base58 decoded WIF must be 32 bytes + an optional 1 byte
	// (0x01) if compressed, plus 1 byte for netID + 4 bytes of checksum.
	switch decodedLen {
	case 1 + btcec.PrivKeyBytesLen + 1 + 4:
		if decoded[33] != compressMagic {
			return nil, errors.New("malformed private key")
		}
		compress = true
	case 1 + btcec.PrivKeyBytesLen + 4:
		compress = false
	default:
		return nil, errors.New("malformed private key")
	}

	// Checksum is first four bytes of double SHA256 of the identifier byte
	// and privKey.  Verify this matches the final 4 bytes of the decoded
	// private key.
	var tosum []byte
	if compress {
		tosum = decoded[:1+btcec.PrivKeyBytesLen+1]
	} else {
		tosum = decoded[:1+btcec.PrivKeyBytesLen]
	}
	cksum := chainhash.DoubleHashB(tosum)[:4]
	if !bytes.Equal(cksum, decoded[decodedLen-4:]) {
		return nil, errors.New("checksum mismatch")
	}

	netID := decoded[0]
	privKeyBytes := decoded[1 : 1+btcec.PrivKeyBytesLen]
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	if network.PrivateKeyID != netID {
		return nil, errors.New("netid mismatch")
	}

	return &PrivateKey{Network: network, PrivateKey: privKey}, nil
}

func (priv *PrivateKey) WIF(compressed bool) string {
	// Precalculate size.  Maximum number of bytes before base58 encoding
	// is one byte for the network, 32 bytes of private key, possibly one
	// extra byte if the pubkey is to be compressed, and finally four
	// bytes of checksum.
	encodeLen := 1 + btcec.PrivKeyBytesLen + 4
	if compressed {
		encodeLen++
	}

	a := make([]byte, 0, encodeLen)
	a = append(a, priv.Network.PrivateKeyID)
	// Pad and append bytes manually, instead of using Serialize, to
	// avoid another call to make.
	a = paddedAppend(btcec.PrivKeyBytesLen, a, priv.PrivateKey.D.Bytes())
	if compressed {
		a = append(a, compressMagic)
	}
	cksum := chainhash.DoubleHashB(a)[:4]
	a = append(a, cksum...)
	return base58.Encode(a)
}

func (priv *PrivateKey) Address() (*address.Address, error) {
	pubkey := priv.PrivateKey.PubKey()
	pkHash := btcutil.Hash160(pubkey.SerializeCompressed())
	addr,err := btcutil.NewAddressPubKeyHash(pkHash, priv.Network)
	if err!=nil { return nil, err }
	return &address.Address{Address: addr}, nil
}

func (priv *PrivateKey) PublicKey() *PublicKey {
	pub := &PublicKey{PublicKey: priv.PrivateKey.PubKey(), Network: priv.Network}
	return pub
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}