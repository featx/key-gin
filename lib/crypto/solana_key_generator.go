package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/mr-tron/base58"
)

// SolanaKeyGenerator Solana密钥生成器
// 实现了使用标准库crypto/ed25519的真实Solana密钥生成
// Solana使用Edwards-curve Digital Signature Algorithm (EdDSA)与Curve25519

type SolanaKeyGenerator struct{}

// GenerateKeyPair 生成Solana密钥对
func (g *SolanaKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成Ed25519密钥对，符合Solana要求
	publicKeyBytes, privateKeyBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	// Solana私钥是64字节，包含私钥种子(32字节)和公钥(32字节)
	// 将标准库的64字节私钥直接用作Solana私钥
	solanaPrivateKey := privateKeyBytes

	// 获取私钥的十六进制表示
	privateKey = hex.EncodeToString(solanaPrivateKey)

	// 公钥是32字节
	publicKey = hex.EncodeToString(publicKeyBytes)

	// Solana地址是公钥的Base58编码
	address = base58.Encode(publicKeyBytes)

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导Solana公钥和地址
func (g *SolanaKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 验证私钥长度是否符合Solana要求
	if len(privateKeyBytes) != 64 {
		return "", "", fmt.Errorf("invalid private key length: expected 64 bytes, got %d bytes", len(privateKeyBytes))
	}

	// 从私钥中提取公钥
	// Solana私钥的后32字节是公钥
	publicKeyBytes := privateKeyBytes[32:]
	publicKey = hex.EncodeToString(publicKeyBytes)

	// Solana地址是公钥的Base58编码
	address = base58.Encode(publicKeyBytes)

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成Solana地址
func (g *SolanaKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 验证公钥长度
	if len(publicKeyBytes) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32 bytes, got %d bytes", len(publicKeyBytes))
	}

	// Solana地址是公钥的Base58编码
	address = base58.Encode(publicKeyBytes)

	return address, nil
}

// AddressToPublicKey 将Solana地址转换回公钥
func (g *SolanaKeyGenerator) AddressToPublicKey(address string) (publicKey string, err error) {
	// 检查地址格式
	if len(address) == 0 {
		return "", fmt.Errorf("empty address")
	}

	// 将Base58编码的地址解码为公钥
	publicKeyBytes, err := base58.Decode(address)
	if err != nil {
		return "", fmt.Errorf("invalid address format: %w", err)
	}

	// 验证公钥长度
	if len(publicKeyBytes) != 32 {
		return "", fmt.Errorf("invalid decoded public key length: expected 32 bytes, got %d bytes", len(publicKeyBytes))
	}

	// 返回公钥的十六进制表示
	publicKey = hex.EncodeToString(publicKeyBytes)

	return publicKey, nil
}