package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SolanaTransactionRequest Solana交易请求结构
type SolanaTransactionRequest struct {
	RecentBlockhash string             `json:"recentBlockhash"`
	Signatures      []string           `json:"signatures"`
	Instructions    []SolanaInstruction `json:"instructions"`
}

// SolanaInstruction Solana交易指令
type SolanaInstruction struct {
	ProgramID string   `json:"programId"`
	Accounts  []string `json:"accounts"`
	Data      string   `json:"data"` // Base64编码的指令数据
}

// SolanaTransactionSigner Solana交易签名器
type SolanaTransactionSigner struct{}

// SignTransaction 签名Solana交易
// 使用Ed25519算法进行签名，符合Solana的要求
func (s *SolanaTransactionSigner) SignTransaction(rawTx, privateKeyHex string) (signedTx string, txHash string, err error) {
	// 解码私钥
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key format: %w", err)
	}

	// 验证私钥长度是否符合Ed25519要求
	if len(privateKeyBytes) != 64 {
		return "", "", fmt.Errorf("invalid private key length: expected 64 bytes, got %d bytes", len(privateKeyBytes))
	}

	// 将字节切片转换为ed25519.PrivateKey类型
	privateKey := ed25519.PrivateKey(privateKeyBytes)

	// 解析交易参数
	var txReq SolanaTransactionRequest
	if err := json.Unmarshal([]byte(rawTx), &txReq); err != nil {
		return "", "", fmt.Errorf("invalid transaction data format: %w", err)
	}

	// 准备要签名的数据
	// 在真实的Solana交易中，签名的数据包括：
	// 1. 交易消息头
	// 2. 账户公钥
	// 3. RecentBlockhash
	// 4. 指令数据
	// 这里为了简化，我们使用交易的哈希作为要签名的数据
	txDataHash := sha256.Sum256([]byte(rawTx))

	// 使用Ed25519私钥对数据进行签名
	signature := ed25519.Sign(privateKey, txDataHash[:])

	// 交易哈希是交易数据的SHA-256哈希
	txHash = hex.EncodeToString(txDataHash[:])

	// 构建签名后的交易
	// 在真实的Solana实现中，签名会被添加到交易中并进行序列化
	// 这里我们返回签名的十六进制表示作为简化实现
	signedTx = hex.EncodeToString(signature)

	return signedTx, txHash, nil
}

// VerifyTransaction 验证Solana交易签名
// 这个方法用于验证交易签名是否有效
func (s *SolanaTransactionSigner) VerifyTransaction(rawTx, signatureHex, publicKeyHex string) (bool, error) {
	// 解码公钥
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key format: %w", err)
	}

	// 验证公钥长度
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

	// 准备要验证的数据（与签名时相同）
	txDataHash := sha256.Sum256([]byte(rawTx))

	// 使用Ed25519公钥验证签名
	valid := ed25519.Verify(publicKey, txDataHash[:], signature)

	return valid, nil
}

// CreateSolanaTransaction 创建一个标准的Solana交易请求
// 这是一个辅助方法，用于生成测试交易或简化交易创建流程
func (s *SolanaTransactionSigner) CreateSolanaTransaction(
	recentBlockhash string,
	instructions []SolanaInstruction,
) (string, error) {
	// 创建交易请求
	txReq := SolanaTransactionRequest{
		RecentBlockhash: recentBlockhash,
		Signatures:      []string{}, // 签名将在之后添加
		Instructions:    instructions,
	}

	// 序列化为JSON
	txJson, err := json.Marshal(txReq)
	if err != nil {
		return "", fmt.Errorf("failed to serialize transaction: %w", err)
	}

	return string(txJson), nil
}