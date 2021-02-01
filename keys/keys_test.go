package keys

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenKeyByMnemonic(t *testing.T) {
	var exampleMnemonic = "icon hill guilt enter clog draft large meadow sun mother replace cream"
	var expectedAddress = "cosmos1entcrqzptj99neq3kx8cpg6mhxhshavk62xjl8"
	var expectedPrivkey = "39e029cc112a70d1b36aea05ea38b335fbed9d4169cf05e3340d16c1afa5c09c"

	addr, privkey := GenKeyByMnemonic(exampleMnemonic, "cosmos", "44'/118'/0'/0/0")
	privkeyHex := fmt.Sprintf("%x", privkey)

	fmt.Println("----------------------------- ")
	fmt.Println("mnemonic: ", exampleMnemonic)
	fmt.Println("address:  ", addr)
	fmt.Println("privkey:  ", privkeyHex)

	require.Equal(t, expectedAddress, addr)
	require.Equal(t, expectedPrivkey, privkeyHex)
}