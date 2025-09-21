package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSuiTransactionSigner_SignTransaction(t *testing.T) {
	signer := &SuiTransactionSigner{}

	// 测试用的私钥
	privateKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"

	// 构建SUI交易请求
	txReq := SuiTransactionRequest{
		TransactionKind: "Transfer",
		GasBudget:       100000000,
		GasPrice:        1000,
		GasPayment:      []string{"0x0000000000000000000000000000000000000000000000000000000000000001"},
		InputObjects:    []string{"0x0000000000000000000000000000000000000000000000000000000000000002"},
		Data:            json.RawMessage(`{"recipient":"0x0000000000000000000000000000000000000000000000000000000000000003","amount":1000}`),
	}

	rawTx, err := json.Marshal(txReq)
	assert.NoError(t, err)

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKeyHex)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, signedTx, "sui_signed_")
	assert.Contains(t, txHash, "sui_")
}