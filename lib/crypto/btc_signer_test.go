package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBtcTransactionSigner_SignTransaction(t *testing.T) {
	signer := &BtcTransactionSigner{}

	// 测试用的私钥
	privateKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"

	// 构建比特币交易请求
	txReq := BtcTransactionRequest{
		Inputs: []BtcTxInput{
			{
				TxID:        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
				Vout:        0,
				ScriptPubKey: "76a914432a3378b45e636c35242760171a513c50641a8288ac",
				Amount:      100000000,
			},
		},
		Outputs: []BtcTxOutput{
			{
				Address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
				Amount:  50000000,
			},
		},
	}

	rawTx, err := json.Marshal(txReq)
	assert.NoError(t, err)

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKeyHex)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, signedTx, "btc_signed_")
}

func TestBtcTransactionSigner_InvalidPrivateKey(t *testing.T) {
	signer := &BtcTransactionSigner{}

	// 无效的私钥
	privateKeyHex := "invalid_private_key"
	rawTx := `{"inputs":[],"outputs":[]}`

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(rawTx, privateKeyHex)

	// 验证错误
	assert.Error(t, err)
	assert.Empty(t, signedTx)
	assert.Empty(t, txHash)
}