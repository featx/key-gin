package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdaTransactionSigner_SignTransaction(t *testing.T) {
	signer := &AdaTransactionSigner{}

	// 测试用的私钥
	privateKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"

	// 构建Cardano交易请求
	txReq := AdaTransactionRequest{
		Inputs: []AdaTxInput{
			{
				TxID:   "61f0bdbd7df2425e5b1e2576d0be264986a08e9f7f2f6152f37c922b0638d023",
				Index:  0,
				Amount: 1000000000,
			},
		},
		Outputs: []AdaTxOutput{
			{
				Address: "addr1q8zu7j4f8v9g5705pql94z9s83p400kfku8n94v8t05m7k9a4t5s9q7g8j6h7f",
				Amount:  500000000,
			},
		},
		Fee: 170000,
		TTL: 8000000,
	}

	rawTx, err := json.Marshal(txReq)
	assert.NoError(t, err)

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKeyHex)

	// 验证结果 - 更新为与新实现兼容的断言
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Greater(t, len(signedTx), 100)  // 确保签名结果足够长
	assert.Equal(t, 64, len(txHash))       // 双SHA256哈希应该是64个十六进制字符
}