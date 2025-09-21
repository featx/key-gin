package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTronTransactionSigner_SignTransaction(t *testing.T) {
	signer := &TronTransactionSigner{}

	// 测试用的私钥
	privateKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"

	// 构建TRON交易请求
	txReq := TronTransactionRequest{
		OwnerAddress: "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
		ToAddress:    "TWbcDLmz7Xg47LrFF9YH42h7Z8XfR6V9Vj",
		Amount:       1000000,
		FeeLimit:     100000000,
	}

	rawTx, err := json.Marshal(txReq)
	assert.NoError(t, err)

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKeyHex)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, signedTx, "tron_signed_")
	assert.Contains(t, txHash, "tron_")
}