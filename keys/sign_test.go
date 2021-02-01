package keys

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

// 待签名消息示例:
// {
//   "account_number": "39217",
//   "chain_id": "cosmoshub-3",
//   "fee": {
//     "amount": [
//       {
//         "amount": "5000",
//         "denom": "uatom"
//       }
//     ],
//     "gas": "200000"
//   },
//   "memo": "",
//   "msgs": [
//     {
//       "type": "cosmos-sdk/MsgSend",
//       "value": {
//         "amount": [
//           {
//             "amount": "100000000",
//             "denom": "uatom"
//           }
//         ],
//         "from_address": "cosmos1entcrqzptj99neq3kx8cpg6mhxhshavk62xjl8",
//         "to_address": "cosmos1xhq898t0ltpgjzaayzm3u5znkm4yan5qseyr9d"
//       }
//     }
//   ],
//   "sequence": "7"
// }

// 注意:
// 1. 待签名交易消息的所有json字段,必须按字母顺序排列,也无须格式化(分行、缩进)
// 2. 请注意待签名交易消息和最终发送的交易消息的区别, 待签名消息里有account_number,chain_id,sequence等字段
//    从lcd的rest接口`http://127.0.0.1:1317/auth/accounts/{address}`可以获取`from_address`的`account_number`和`sequence`

func TestSignBytes(t *testing.T) {
	var tx = `{"account_number":"39217","chain_id":"cosmoshub-3","fee":{"amount":[{"amount":"5000","denom":"uatom"}],"gas":"200000"},"memo":"","msgs":[{"type":"cosmos-sdk/MsgSend","value":{"amount":[{"amount":"100000000","denom":"uatom"}],"from_address":"cosmos1entcrqzptj99neq3kx8cpg6mhxhshavk62xjl8","to_address":"cosmos1xhq898t0ltpgjzaayzm3u5znkm4yan5qseyr9d"}}],"sequence":"7"}`
	var privkeyHex = "39e029cc112a70d1b36aea05ea38b335fbed9d4169cf05e3340d16c1afa5c09c"

	privkey, _ := hex.DecodeString(privkeyHex)
	// 将待签名消息转换为字节数据
	txData := []byte(tx)
	// 进行离线签名
	signed, pubkey := SignBytes(privkey, txData)

	signBase64 := base64.StdEncoding.EncodeToString(signed)
	fmt.Println(">> signed: ", signBase64)

	pubkeyBase64 := base64.StdEncoding.EncodeToString(pubkey)
	fmt.Println(">> pubkey: ", pubkeyBase64)

	var expectedSignBase64 = "ny6xaIR6vvicP6QqN/fUVSmFb8/VS2P8eob/6eoEkOQPEzCN1Jglt1Yi5kpdaHZi1EI86BzXMe6+jyfRtMzRaQ=="
	require.Equal(t, expectedSignBase64, signBase64)

	var expectedPubkeyBase64 = "Axr3tksinUo6fIrrLIp1I8B7RGRWWC+FTN2ysiDFOcBX"
	require.Equal(t, expectedPubkeyBase64, pubkeyBase64)

	// 得到签名和公钥后, 构建已签名的离线交易消息, 然后通过lcd(轻客户端)的 /txs 接口进行交易发送
	// 注: 实际发送时, 无需格式化json(去掉换行和缩进)

	// 轻客户端 /txs 请求消息示例:
	// POST http://127.0.0.1:1317/txs
	// content-type: application/json
	//
	// {
	//   "tx": {
	//     "fee": {
	//       "amount": [
	//         {
	//           "amount": "5000",
	//           "denom": "uatom"
	//         }
	//       ],
	//       "gas": "200000"
	//     },
	//     "memo": "",
	//     "msg": [
	//       {
	//         "type": "cosmos-sdk/MsgSend",
	//         "value": {
	//           "amount": [
	//             {
	//               "amount": "100000000",
	//               "denom": "uatom"
	//             }
	//           ],
	//           "from_address": "cosmos1entcrqzptj99neq3kx8cpg6mhxhshavk62xjl8",
	//           "to_address": "cosmos1xhq898t0ltpgjzaayzm3u5znkm4yan5qseyr9d"
	//         }
	//       }
	//     ],
	//     "signatures": [
	//       {
	//         "account_number": "39217",
	//         "pub_key": {
	//           "type": "tendermint/PubKeySecp256k1",
	//           "value": "Axr3tksinUo6fIrrLIp1I8B7RGRWWC+FTN2ysiDFOcBX"
	//         },
	//         "sequence": "7",
	//         "signature": "ny6xaIR6vvicP6QqN/fUVSmFb8/VS2P8eob/6eoEkOQPEzCN1Jglt1Yi5kpdaHZi1EI86BzXMe6+jyfRtMzRaQ=="
	//       }
	//     ]
	//   },
	//   "mode": "async"
	// }
}

func TestSignBytesHex(t *testing.T) {
	var dataHex = "7b226163636f756e745f6e756d626572223a2231222c22636861696e5f6964223a22626e62636861696e2d31303030222c226d656d6f223a22222c226d736773223a5b7b226964223a22423635363144434331303431333030353941374330384634384336343631304331463646393036342d3130222c226f7264657274797065223a322c227072696365223a3130303030303030302c227175616e74697479223a313230303030303030302c2273656e646572223a22626e63316b6574706d6e71736779637174786e7570723667636572707073306b6c797279687a36667a6c222c2273696465223a312c2273796d626f6c223a224254432d3543345f424e42222c2274696d65696e666f726365223a317d5d2c2273657175656e6365223a2239227d"
	var privkeyHex = "30c5e838578a29e3e9273edddd753d6c9b38aca2446dd84bdfe2e5988b0da0a1"
	var expectedSig = "9c0421217ef92d556a14e3f442b07c85f6fc706dfcd8a72d6b58f05f96e95aa226b10f7cf62ccf7c9d5d953fa2c9ae80a1eacaf0c779d0253f1a34afd17eef34"
	var expectedPubkeyHex = "03baf53d1424f8ea83d03a82f6d157b5401c4ea57ffb8317872e15a19fc9b7ad7b"

	signed, pubkey := SignBytesHex(privkeyHex, dataHex)

	require.Equal(t, expectedSig, hex.EncodeToString(signed))
	require.Equal(t, expectedPubkeyHex, hex.EncodeToString(pubkey))
}
