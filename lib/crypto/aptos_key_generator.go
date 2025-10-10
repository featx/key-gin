package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// AptosKeyGenerator Aptos密钥生成器
// 实现了使用标准库crypto/ed25519的真实Aptos密钥生成
// Aptos使用Edwards-curve Digital Signature Algorithm (EdDSA)与Curve25519
// 参考Aptos官方规范，地址生成符合Aptos Mainnet要求

type AptosKeyGenerator struct{}

// GenerateKeyPair 生成Aptos密钥对
func (g *AptosKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成随机私钥（符合Ed25519要求）
	publicKeyBytes, privateKeyBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示（64字节）
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示（32字节）
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成Aptos风格的地址
	aptosAddress, err := g.PublicKeyToAddress(publicKey)
	if err != nil {
		return "", "", "", err
	}

	return aptosAddress, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导Aptos公钥和地址
func (g *AptosKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
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

	// 生成Aptos风格的地址
	aptosAddress, err := g.PublicKeyToAddress(publicKey)
	if err != nil {
		return "", "", err
	}

	return aptosAddress, publicKey, nil
}

// PublicKeyToAddress 从公钥生成Aptos地址
// 根据Aptos规范，地址生成步骤如下：
// 1. 公钥（32字节）
// 2. 计算SHA3-256哈希（32字节）
// 3. 使用Hex编码，并添加前缀"0x"
func (g *AptosKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 验证公钥长度
	if len(publicKeyBytes) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32 bytes, got %d bytes", len(publicKeyBytes))
	}

	// 正确实现Aptos地址生成：
	// 1. 计算公钥的SHA3-256哈希
	hash := sha3.Sum256(publicKeyBytes)

	// 2. 将哈希结果转换为十六进制字符串
	hashHex := hex.EncodeToString(hash[:])

	// 3. 添加前缀"0x"，确保符合Aptos地址格式
	aptosAddress := "0x" + hashHex

	return aptosAddress, nil
}