package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTonTransactionSigner_SignTransaction(t *testing.T) {
	signer := &TonTransactionSigner{}

	// 测试用的私钥
	privateKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"

	// 构建TON交易请求
	txReq := TonTransactionRequest{
		Address:     "EQC9bWZd8dR7XJcQfZ5XWgZ5XWgZ5XWgZ5XWgZ5XWgZ5XWgZ5XWg",
		Destination: "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N",
		Amount:      1000000000,
		Seqno:       0,
	}

	rawTx, err := json.Marshal(txReq)
	assert.NoError(t, err)

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKeyHex)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, signedTx, "ton_signed_")
	assert.Contains(t, txHash, "ton_")
}