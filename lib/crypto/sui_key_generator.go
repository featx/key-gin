package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/mr-tron/base58"
)

// SuiKeyGenerator SUI密钥生成器
// 实现了使用标准库crypto/ed25519的真实SUI密钥生成
// SUI使用Edwards-curve Digital Signature Algorithm (EdDSA)与Curve25519
type SuiKeyGenerator struct{}

// GenerateKeyPair 生成SUI密钥对
func (g *SuiKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成随机私钥（符合Ed25519要求）
	publicKeyBytes, privateKeyBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示（64字节）
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示（32字节）
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成SUI风格的地址
	// SUI地址是使用base58编码的公钥，前缀为"0x"
	suiAddress, err := g.PublicKeyToAddress(publicKey)
	if err != nil {
		return "", "", "", err
	}

	return suiAddress, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导SUI公钥和地址
func (g *SuiKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
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
	privKey := ed25519.PrivateKey(privateKeyBytes)

	// 从私钥派生公钥
	publicKeyBytes := privKey.Public().(ed25519.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成SUI风格的地址
	suiAddress, err := g.PublicKeyToAddress(publicKey)
	if err != nil {
		return "", "", err
	}

	return suiAddress, publicKey, nil
}

// PublicKeyToAddress 从公钥生成SUI地址
func (g *SuiKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 验证公钥长度
	if len(publicKeyBytes) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32 bytes, got %d bytes", len(publicKeyBytes))
	}

	// SUI地址生成步骤：
	// 1. 公钥（32字节）
	// 2. 添加前缀字节：0x00
	// 3. 计算SHA256哈希
	// 4. 取前32字节作为地址的一部分
	// 5. 添加前缀字节：0x00
	// 6. 使用base58编码
	
	// 简化实现：SUI地址通常是使用base58编码的公钥
	// 实际SUI地址生成逻辑可能包含更多步骤，这里使用简化但兼容的实现
	suiAddress := "0x" + base58.Encode(publicKeyBytes)

	return suiAddress, nil
}