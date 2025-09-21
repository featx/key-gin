package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSolanaTransactionSigner_SignTransaction(t *testing.T) {
	signer := &SolanaTransactionSigner{}

	// 测试用的私钥
	privateKeyHex := "0000000000000000000000000000000000000000000000000000000000000001"

	// 构建Solana交易请求
	txReq := SolanaTransactionRequest{
		RecentBlockhash: "EETubP5AKHgjPAhzPAFcb8BAY1hMHc4py8gRqsAKSKiW",
		Signatures:      []string{""}, // 空签名，等待填充
		Instructions: []SolanaInstruction{
			{
				ProgramID: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
				Accounts:  []string{"2vJhN51FwR9pLVfFzGkXgW9xNCMdYQyH84ZtMvVwXQ9s", "11111111111111111111111111111111"},
				Data:      "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
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
	assert.Contains(t, signedTx, "sol_signed_")
	assert.Contains(t, txHash, "sol_")
}