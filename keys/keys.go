package keys

import (
	"fmt"
	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/bech32"

	"github.com/bernix/cosmos-key-sign/cosmos/bip39"
	"github.com/bernix/cosmos-key-sign/cosmos/hd"
)

const (
	// the mnemonic entropy bit size, 128 means a 12 words mnemonic
	mnemonicEntropySize int = 128
	// private key size
	privKeySize int = 32
	// public key size
	pubKeySize int = 33
	// uses the Bitcoin secp256k1 ECDSA algorithm for the key signing
	keyAlgorithm string = "secp256k1"
)

// GenKey generate a cosmos-sdk based account
func GenKey(hrp, hdpath string) (string, string, []byte) {
	// create a random entropy seed bytes
	entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
	if err != nil {
		panic(err)
	}
	// create the mnemonic words using the entropy seed
	mnemonic, err := bip39.NewMnemonic(entropySeed)
	if err != nil {
		panic(err)
	}

	address, privkey := GenKeyByMnemonic(mnemonic, hrp, hdpath)

	return mnemonic, address, privkey
}

// GenKeyByMnemonic generate a cosmos-sdk based account for the given mnemonic words
func GenKeyByMnemonic(mnemonic, hrp, hdpath string) (string, []byte) {
	if !bip39.IsMnemonicValid(mnemonic) {
		panic("invalid mnemonic")
	}
	// 根据助记词和bip44路径, 推导出私钥 (32个字节)
	privkey, err := derive(mnemonic, "", hdpath)
	if err != nil {
		panic(err)
	}

	// 根据私钥得到公钥
	_, pubkeyObject := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privkey)
	pubkey := pubkeyObject.SerializeCompressed()

	// 按bitcoin格式得到公钥哈希(RIPEMD160(SHA256(pubkey)))
	// 然后根据给定的HRP(用户可读部分), 输出为bech32编码格式的地址
	bech32Addr, err := bech32Encode(hrp, btcutil.Hash160(pubkey))
	if err != nil {
		panic(err)
	}

	return bech32Addr, privkey
}

func derive(mnemonic, bip39Passphrase, hdPath string) ([]byte, error) {
	// 使用 pbkdf2 算法对助记词进行密钥拉伸, 最终生成一个512位的密钥种子
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, err
	}

	// 分层推导, 第一步, 根据密钥种子推导主秘钥 (SHA512 HMAC算法)
	masterPriv, chainCode := hd.ComputeMastersFromSeed(seed)
	if len(hdPath) == 0 {
		panic("invalid hdpath")
	}

	// 第二步, 使用主密钥, 根据 bip44 路径, 推导子秘钥
	derivedKey, err := hd.DerivePrivateKeyForPath(masterPriv, chainCode, hdPath)
	return derivedKey, err
}

// converts from a base64 encoded byte string to base32 encoded byte string and then to bech32.
func bech32Encode(hrp string, data []byte) (string, error) {
	converted, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("encoding bech32 failed: %w", err)
	}

	return bech32.Encode(hrp, converted)
}

// decodes a bech32 encoded string and converts to base64 encoded bytes.
func bech32Decode(bech string) (string, []byte, error) {
	hrp, data, err := bech32.Decode(bech)
	if err != nil {
		return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
	}

	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
	}

	return hrp, converted, nil
}
