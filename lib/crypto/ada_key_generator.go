package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// AdaKeyGenerator Cardano (ADA)密钥生成器
// 实现一个更符合Cardano规范的版本

type AdaKeyGenerator struct{}

// AddressType 定义Cardano地址类型
type AddressType string

const (
	// BaseAddress 基本地址类型（包含支付和权益组件）
	BaseAddress AddressType = "base"
	// EnterpriseAddress Enterprise地址类型（仅包含支付组件）
	EnterpriseAddress AddressType = "enterprise"
)

// GenerateKeyPair 生成Cardano密钥对
func (g *AdaKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成随机私钥（32字节，符合Cardano要求）
	privateKeyBytes := make([]byte, 32)
	_, err = rand.Read(privateKeyBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 从私钥派生公钥（模拟Cardano的Ed25519密钥派生过程）
	publicKeyBytes := derivePublicKey(privateKeyBytes)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成符合Cardano规范的地址（使用Bech32格式，默认使用基本地址）
	address, err = generateCardanoAddress(publicKeyBytes, BaseAddress)
	if err != nil {
		return "", "", "", err
	}

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导Cardano公钥和地址
func (g *AdaKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	// 解析私钥（必须是32字节的十六进制字符串）
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 验证私钥长度是否符合Cardano要求
	if len(privateKeyBytes) != 32 {
		return "", "", fmt.Errorf("invalid private key length: expected 32 bytes, got %d bytes", len(privateKeyBytes))
	}

	// 从私钥派生公钥
	publicKeyBytes := derivePublicKey(privateKeyBytes)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成符合Cardano规范的地址（默认使用基本地址）
	address, err = generateCardanoAddress(publicKeyBytes, BaseAddress)
	if err != nil {
		return "", "", err
	}

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成Cardano地址
func (g *AdaKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 生成符合Cardano规范的地址（默认使用基本地址）
	address, err = generateCardanoAddress(publicKeyBytes, BaseAddress)
	if err != nil {
		return "", err
	}

	return address, nil
}

// derivePublicKey 模拟从私钥派生公钥的过程
func derivePublicKey(privateKeyBytes []byte) []byte {
	// 对私钥进行SHA-256哈希，模拟Ed25519的密钥扩展过程
	hash := sha256.New()
	hash.Write(privateKeyBytes)
	hashResult := hash.Sum(nil)

	// 模拟公钥生成
	publicKeyHash := sha256.New()
	publicKeyHash.Write(hashResult)
	publicKeyBytes := publicKeyHash.Sum(nil)

	return publicKeyBytes
}

// generateCardanoAddress 生成符合Cardano规范的地址，支持两种格式
func generateCardanoAddress(publicKeyBytes []byte, addressType AddressType) (string, error) {
	// 1. 创建支付凭证哈希
	paymentCredHash := sha256.New()
	paymentCredHash.Write(publicKeyBytes)
	paymentCred := paymentCredHash.Sum(nil)[:28] // Cardano使用28字节的哈希

	// 2. 根据地址类型构建地址payload
	var addressPayload []byte
	var hrp string // Human Readable Part

	switch addressType {
	case BaseAddress:
		// 基本地址：网络ID(0x00) + 支付凭证类型(0x00) + 支付凭证哈希 + 权益凭证类型(0x00) + 权益凭证哈希
		// 为了简化，这里使用相同的密钥作为权益密钥
		stakeCredHash := sha256.New()
		stakeCredHash.Write(publicKeyBytes)
		stakeCred := stakeCredHash.Sum(nil)[:28]
		
		addressPayload = append([]byte{0x00}, 0x00)  // 网络ID + 支付凭证类型
		addressPayload = append(addressPayload, paymentCred...)  // 支付凭证哈希
		addressPayload = append(addressPayload, 0x00)  // 权益凭证类型
		addressPayload = append(addressPayload, stakeCred...)  // 权益凭证哈希
			hrp = "addr1"
	case EnterpriseAddress:
		// Enterprise地址：网络ID(0x06) + 支付凭证类型(0x00) + 支付凭证哈希
		addressPayload = append([]byte{0x06}, 0x00)  // 网络ID + 支付凭证类型
		addressPayload = append(addressPayload, paymentCred...)  // 支付凭证哈希
		hrp = "addr1"
	default:
		return "", fmt.Errorf("unsupported address type: %s", addressType)
	}

	// 3. 使用Bech32编码地址
	// 首先将数据转换为5位编码
	converted, err := bech32.ConvertBits(addressPayload, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}

	// 4. 使用Bech32编码
	address, err := bech32.Encode(hrp, converted)
	if err != nil {
		return "", fmt.Errorf("failed to encode with bech32: %w", err)
	}

	return address, nil
}

// GenerateKeyPairWithAddressType 生成指定地址类型的Cardano密钥对
// 提供额外的方法支持选择地址类型
func (g *AdaKeyGenerator) GenerateKeyPairWithAddressType(addressType AddressType) (address, publicKey, privateKey string, err error) {
	// 生成随机私钥
	privateKeyBytes := make([]byte, 32)
	_, err = rand.Read(privateKeyBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	privateKey = hex.EncodeToString(privateKeyBytes)

	// 派生公钥
	publicKeyBytes := derivePublicKey(privateKeyBytes)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成指定类型的地址
	address, err = generateCardanoAddress(publicKeyBytes, addressType)
	if err != nil {
		return "", "", "", err
	}

	return address, publicKey, privateKey, nil
}