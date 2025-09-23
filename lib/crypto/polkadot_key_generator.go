package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// PolkadotKeyGenerator Polkadot和Kusama密钥生成器
// 注意：这是一个更符合Polkadot规范的实现，但仍为简化版本
// 实际的Polkadot密钥生成应使用官方库: github.com/paritytech/parity-crypto
// Polkadot使用Schnorr签名与sr25519曲线

type PolkadotKeyGenerator struct{}

// GenerateKeyPair 生成Polkadot/Kusama密钥对
func (g *PolkadotKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成随机私钥（64字节，符合Polkadot要求）
	privateKeyBytes := make([]byte, 64)
	_, err = rand.Read(privateKeyBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 生成公钥（基于私钥派生，符合Polkadot规范的简化实现）
	// Polkadot实际使用sr25519曲线，这里使用Blake2b作为简化实现
	hash, _ := blake2b.New256(nil)
	hash.Write(privateKeyBytes)
	publicKeyBytes := hash.Sum(nil)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成Polkadot风格的地址（以1开头，符合SS58格式特点）
	// 注意：实际Polkadot地址使用SS58编码
	addrHash, _ := blake2b.New256(nil)
	addrHash.Write(publicKeyBytes)
	hashBytes := addrHash.Sum(nil)
	// 截取适当长度并添加Polkadot地址前缀
	address = "1" + hex.EncodeToString(hashBytes[:20])

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导Polkadot/Kusama公钥和地址
func (g *PolkadotKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 验证私钥长度是否合理
	if len(privateKeyBytes) < 32 {
		return "", "", fmt.Errorf("invalid private key length: expected at least 32 bytes, got %d bytes", len(privateKeyBytes))
	}

	// 从私钥派生公钥（简化实现）
	// Polkadot实际使用sr25519曲线，这里使用Blake2b作为简化实现
	hash, _ := blake2b.New256(nil)
	hash.Write(privateKeyBytes)
	publicKeyBytes := hash.Sum(nil)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成Polkadot风格的地址
	addrHash, _ := blake2b.New256(nil)
	addrHash.Write(publicKeyBytes)
	hashBytes := addrHash.Sum(nil)
	// 截取适当长度并添加Polkadot地址前缀
	address = "1" + hex.EncodeToString(hashBytes[:20])

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成Polkadot/Kusama地址
func (g *PolkadotKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 生成Polkadot风格的地址
	addrHash, _ := blake2b.New256(nil)
	addrHash.Write(publicKeyBytes)
	hashBytes := addrHash.Sum(nil)
	// 截取适当长度并添加Polkadot地址前缀
	address = "1" + hex.EncodeToString(hashBytes[:20])

	return address, nil
}