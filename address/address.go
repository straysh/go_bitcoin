package address

import (
	"github.com/straysh/btcutil"
	"encoding/hex"
)

type Address struct {
	btcutil.Address
}


func (a *Address) Script() string {
	scriptBuf := a.ScriptAddress()
	return hex.EncodeToString(scriptBuf)
}