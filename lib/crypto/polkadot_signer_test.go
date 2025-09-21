package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolkadotTransactionSigner_SignTransaction(t *testing.T) {
	// 测试Polkadot
	signer := &PolkadotTransactionSigner{IsKusama: false}

	// 测试用的私钥
	privateKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"

	// 构建Polkadot交易请求
	txReq := PolkadotTransactionRequest{
		Address:      "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5",
		CallModule:   "balances",
		CallFunction: "transfer",
		CallArgs: map[string]interface{}{
			"dest":   "14E5nqKAp3oAJcmzgZhUD2RcptBeUBScxKHgJKU4HPNcKVf3",
			"value":  1000000000000,
		},
		Nonce: 0,
		Tip:   0,
		Era:   "immortal",
	}

	rawTx, err := json.Marshal(txReq)
	assert.NoError(t, err)

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKeyHex)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, signedTx, "dot_signed_")
	assert.Contains(t, txHash, "dot_")

	// 测试Kusama
	signer = &PolkadotTransactionSigner{IsKusama: true}
	signedTx, txHash, err = signer.SignTransaction(string(rawTx), privateKeyHex)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, signedTx, "ksm_signed_")
	assert.Contains(t, txHash, "ksm_")
}