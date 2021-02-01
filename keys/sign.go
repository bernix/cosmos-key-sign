package keys

import (
	"crypto/sha256"
	"encoding/hex"
	secp256k1 "github.com/btcsuite/btcd/btcec"
)

// SignBytesHex signs the given data with provided privkey, returns the signed data and the pubkey bytes
func SignBytesHex(privkeyHex string, dataHex string) ([]byte, []byte) {
	privkey, err := hex.DecodeString(privkeyHex)
	if err != nil {
		panic("invalid privkey hex string")
	}

	data, err := hex.DecodeString(dataHex)
	if err != nil {
		panic("invalid data hex string")
	}

	return SignBytes(privkey, data)
}

// SignBytes signs the given data with provided privkey
func SignBytes(privkey []byte, data []byte) ([]byte, []byte)  {
	privkeyObject, pubkeyObject := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privkey)

	// sha256 hash
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(data)
	dataHash := hasherSHA256.Sum(nil)

	signature, err := privkeyObject.Sign(dataHash)
	if err != nil {
		panic(err)
	}
	signed := serializeSig(signature)

	return signed, pubkeyObject.SerializeCompressed()
}

// Serialize signature to R || S.
// R, S are padded to 32 bytes respectively.
func serializeSig(sig *secp256k1.Signature) []byte {
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	sigBytes := make([]byte, 64)
	// 0 pad the byte arrays from the left if they aren't big enough.
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	return sigBytes
}
