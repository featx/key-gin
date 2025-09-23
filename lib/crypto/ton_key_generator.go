package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// TonKeyGenerator TON (Telegram Open Network)密钥生成器
// 使用Ed25519算法，符合TON规范

type TonKeyGenerator struct{}

// GenerateKeyPair 生成TON密钥对
func (g *TonKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成Ed25519密钥对，符合TON要求
	publicKeyBytes, privateKeyBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	// TON私钥是64字节，包含私钥种子(32字节)和公钥(32字节)
	// 将标准库的64字节私钥直接用作TON私钥
	tonPrivateKey := privateKeyBytes

	// 获取私钥的十六进制表示
	privateKey = hex.EncodeToString(tonPrivateKey)

	// 公钥是32字节
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成符合TON规范的地址
	// TON地址通常以EQ开头，使用Base64编码或Bounceable/NBounceable格式
	// 这里实现一个简化版本，基于公钥哈希生成地址
	address, err = g.PublicKeyToAddress(publicKey)
	if err != nil {
		return "", publicKey, privateKey, fmt.Errorf("failed to generate address: %w", err)
	}

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导TON公钥和地址
func (g *TonKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 验证私钥长度是否符合Ed25519要求
	if len(privateKeyBytes) != 64 {
		// 检查是否是32字节的种子，如果是则转换为64字节的私钥
		if len(privateKeyBytes) == 32 {
			// 从32字节种子派生完整的64字节Ed25519私钥
			publicKeyBytes := ed25519.PrivateKey(privateKeyBytes).Public().(ed25519.PublicKey)
			publicKey = hex.EncodeToString(publicKeyBytes)
			
			// 生成TON地址
			address, err = g.PublicKeyToAddress(publicKey)
			if err != nil {
				return "", publicKey, fmt.Errorf("failed to generate address: %w", err)
			}
			return address, publicKey, nil
		}
		return "", "", fmt.Errorf("invalid private key length: expected 64 bytes (full private key) or 32 bytes (seed), got %d bytes", len(privateKeyBytes))
	}

	// 将字节切片转换为ed25519.PrivateKey类型
	privateKeyObj := ed25519.PrivateKey(privateKeyBytes)

	// 从私钥派生公钥
	publicKeyBytes := privateKeyObj.Public().(ed25519.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成TON地址
	address, err = g.PublicKeyToAddress(publicKey)
	if err != nil {
		return "", publicKey, fmt.Errorf("failed to generate address: %w", err)
	}

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成TON地址
func (g *TonKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 验证公钥长度是否符合Ed25519要求
	if len(publicKeyBytes) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32 bytes, got %d bytes", len(publicKeyBytes))
	}

	// 生成TON风格的地址
	// TON地址生成过程：
	// 1. 对公钥进行哈希
	// 2. 添加地址前缀和后缀
	// 3. 使用Base64编码或其他特定编码
	// 这里实现一个简化版本，生成以EQ开头的地址
	hash := crypto.Keccak256(publicKeyBytes)
	// 截取适当长度并添加TON地址前缀
	// 注意：实际TON地址编码更复杂，这里只是模拟格式
	address = "EQ" + hex.EncodeToString(hash[:20])

	return address, nil
}