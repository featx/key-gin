package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

// AdaTransactionRequest Cardano交易请求结构
type AdaTransactionRequest struct {
	Inputs   []AdaTxInput             `json:"inputs"`
	Outputs  []AdaTxOutput            `json:"outputs"`
	Fee      uint64                   `json:"fee"`
	TTL      uint64                   `json:"ttl,omitempty"` // Time To Live
	Metadata map[string]interface{}   `json:"metadata,omitempty"`
}

// AdaTxInput Cardano交易输入
type AdaTxInput struct {
	TxID   string `json:"txid"`
	Index  uint32 `json:"index"`
	Amount uint64 `json:"amount"`
}

// AdaTxOutput Cardano交易输出
type AdaTxOutput struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"` // 单位是lovelace
}

// AdaTransactionSigner Cardano交易签名器
type AdaTransactionSigner struct{}

// SignTransaction 签名Cardano交易
func (s *AdaTransactionSigner) SignTransaction(rawTx, privateKeyHex string) (signedTx string, txHash string, err error) {
	// 解码私钥
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key format: %w", err)
	}

	// 验证私钥长度是否符合要求
	if len(privateKeyBytes) != 32 {
		return "", "", fmt.Errorf("invalid private key length: expected 32 bytes, got %d bytes", len(privateKeyBytes))
	}

	// 解析交易参数
	var txReq AdaTransactionRequest
	if err := json.Unmarshal([]byte(rawTx), &txReq); err != nil {
		return "", "", fmt.Errorf("invalid transaction data format: %w", err)
	}

	// 准备交易数据进行哈希计算
	txData, err := prepareTransactionDataForSigning(txReq)
	if err != nil {
		return "", "", err
	}

	// 计算交易哈希
	txHashBytes := sha256.Sum256(txData)
	txHash = hex.EncodeToString(txHashBytes[:])

	// 使用Ed25519算法进行签名
	// 在实际的Cardano实现中，这里会使用Cardano特定的签名格式
	// 但我们使用标准的Ed25519签名作为模拟
	privateKey := ed25519.NewKeyFromSeed(privateKeyBytes)
	signature := ed25519.Sign(privateKey, txData)

	// 构建签名的交易
	// 在实际实现中，这会遵循Cardano的CBOR编码格式
	signedTx = fmt.Sprintf("{\"type\":\"WitnessSet\",\"signatures\":{\"%s\":\"%s\"},\"transaction_body_hash\":\"%s\"}",
		txHash,
		hex.EncodeToString(signature),
		txHash,
	)

	return signedTx, txHash, nil
}

// prepareTransactionDataForSigning 准备交易数据用于签名
// 这是一个简化的实现，实际的Cardano实现会更复杂
func prepareTransactionDataForSigning(txReq AdaTransactionRequest) ([]byte, error) {
	// 将交易数据转换为JSON字节
	txBytes, err := json.Marshal(txReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction data: %w", err)
	}

	// 对交易数据进行哈希处理，准备签名
	hash := sha256.New()
	hash.Write(txBytes)
	hashBytes := hash.Sum(nil)

	return hashBytes, nil
}