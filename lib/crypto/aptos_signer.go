package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// AptosTransactionRequest Aptos交易请求结构
// 包含Aptos交易所需的基本字段
// 参考Aptos官方规范

type AptosTransactionRequest struct {
	Type          string          `json:"type"`
	Sender        string          `json:"sender"`
	SequenceNumber uint64         `json:"sequence_number"`
	MaxGasAmount  uint64          `json:"max_gas_amount"`
	GasUnitPrice  uint64          `json:"gas_unit_price"`
	ExpirationTimestamp uint64     `json:"expiration_timestamp_secs"`
	Payload       json.RawMessage `json:"payload"`
}

// AptosTransactionSigner Aptos交易签名器
// 使用Ed25519算法，符合Aptos规范
// 支持对Aptos交易进行签名

type AptosTransactionSigner struct{}

// SignTransaction 签名Aptos交易
func (s *AptosTransactionSigner) SignTransaction(rawTx, privateKeyHex string) (signedTx string, txHash string, err error) {
	// 解码私钥
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key format: %w", err)
	}

	// 验证私钥长度是否符合Ed25519要求
	if len(privateKeyBytes) != 64 {
		// 检查是否是32字节的种子，如果是则转换为64字节的私钥
		if len(privateKeyBytes) == 32 {
			// 创建一个临时密钥对来获取正确格式的私钥
			_, fullPrivateKey, err := ed25519.GenerateKey(nil) // 使用nil Reader不会真正随机生成密钥
			if err != nil {
				return "", "", fmt.Errorf("failed to create full private key: %w", err)
			}
			// 复制种子部分
			copy(fullPrivateKey[:32], privateKeyBytes)
			privateKeyBytes = fullPrivateKey
		} else {
			return "", "", fmt.Errorf("invalid private key length: expected 64 bytes (full private key) or 32 bytes (seed), got %d bytes", len(privateKeyBytes))
		}
	}

	// 将字节切片转换为ed25519.PrivateKey类型
	privateKey := ed25519.PrivateKey(privateKeyBytes)

	// 解析交易参数
	var txReq AptosTransactionRequest
	if err := json.Unmarshal([]byte(rawTx), &txReq); err != nil {
		return "", "", fmt.Errorf("invalid transaction data format: %w", err)
	}

	// 准备要签名的数据
	// 在真实的Aptos交易中，签名的数据包括：
	// 1. 交易类型
	// 2. 发送者地址
	// 3. 序列号码
	// 4. Gas参数
	// 5. 过期时间
	// 6. 交易负载
	// 这里为了简化，我们使用交易的哈希作为要签名的数据
	txDataHash := sha256.Sum256([]byte(rawTx))
	txHash = hex.EncodeToString(txDataHash[:])

	// 使用Ed25519私钥对数据进行签名，符合Aptos要求
	signature := ed25519.Sign(privateKey, txDataHash[:])

	// 构建签名后的交易
	// 在真实的Aptos实现中，签名会被添加到交易中并进行序列化
	// 这里我们返回签名的十六进制表示作为简化实现
	signedTx = "aptos_signed_" + hex.EncodeToString(signature)

	// 添加前缀到交易哈希
	txHash = "aptos_" + txHash

	return signedTx, txHash, nil
}

// VerifyTransaction 验证Aptos交易签名
// 此方法用于验证签名是否有效
func (s *AptosTransactionSigner) VerifyTransaction(rawTx, signatureHex, publicKeyHex string) (bool, error) {
	// 解码公钥
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key format: %w", err)
	}

	// 验证公钥长度是否符合Ed25519要求
	if len(publicKeyBytes) != 32 {
		return false, fmt.Errorf("invalid public key length: expected 32 bytes, got %d bytes", len(publicKeyBytes))
	}

	// 将字节切片转换为ed25519.PublicKey类型
	publicKey := ed25519.PublicKey(publicKeyBytes)

	// 解码签名
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature format: %w", err)
	}

	// 计算交易数据的哈希
	txDataHash := sha256.Sum256([]byte(rawTx))

	// 使用Ed25519验证签名
	isValid := ed25519.Verify(publicKey, txDataHash[:], signature)

	return isValid, nil
}