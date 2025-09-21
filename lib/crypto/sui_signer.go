package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// SuiTransactionRequest SUI交易请求结构
type SuiTransactionRequest struct {
	TransactionKind string          `json:"transactionKind"`
	GasBudget       uint64          `json:"gasBudget"`
	GasPrice        uint64          `json:"gasPrice"`
	GasPayment      []string        `json:"gasPayment"`
	InputObjects    []string        `json:"inputObjects"`
	Data            json.RawMessage `json:"data"`
}

// SuiTransactionSigner SUI交易签名器
type SuiTransactionSigner struct{}

// SignTransaction 签名SUI交易
func (s *SuiTransactionSigner) SignTransaction(rawTx, privateKeyHex string) (signedTx string, txHash string, err error) {
	// 解码私钥
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key format: %w", err)
	}

	// 解析交易参数
	var txReq SuiTransactionRequest
	if err := json.Unmarshal([]byte(rawTx), &txReq); err != nil {
		return "", "", fmt.Errorf("invalid transaction data format: %w", err)
	}

	// SUI交易签名逻辑
	// 实际实现需要使用SUI特定库
	// github.com/MystenLabs/sui/crypto

	// 模拟签名过程
	signature := crypto.Keccak256(append(privateKeyBytes, []byte(rawTx)...))
	signedTx = fmt.Sprintf("sui_signed_%s", hex.EncodeToString(signature))
	txHash = fmt.Sprintf("sui_%x", crypto.Keccak256([]byte(signedTx)))

	return signedTx, txHash, nil
}