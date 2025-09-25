package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"golang.org/x/crypto/blake2b"
)

// AdaKeyGenerator Cardano (ADA)密钥生成器
// 实现符合Cardano主网规范的密钥和地址生成

type AdaKeyGenerator struct{}

// AddressType 定义Cardano地址类型
type AddressType string

const (
	// BaseAddress 基本地址类型（包含支付和权益组件）
	BaseAddress AddressType = "base"
	// EnterpriseAddress Enterprise地址类型（仅包含支付组件）
	EnterpriseAddress AddressType = "enterprise"
)

// NetworkType 定义Cardano网络类型
type NetworkType string

const (
	// Mainnet 主网
	Mainnet NetworkType = "mainnet"
	// Testnet 测试网
	Testnet NetworkType = "testnet"
)

// GenerateKeyPair 生成Cardano密钥对 - 使用真实的Ed25519算法
func (g *AdaKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	return g.GenerateKeyPairWithOptions(BaseAddress, Mainnet)
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导Cardano公钥和地址
func (g *AdaKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	return g.DeriveKeyPairFromPrivateKeyWithOptions(privateKey, BaseAddress, Mainnet)
}

// PublicKeyToAddress 从公钥生成Cardano地址
func (g *AdaKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	return g.PublicKeyToAddressWithOptions(publicKey, BaseAddress, Mainnet)
}

// GenerateKeyPairWithAddressType 生成指定地址类型的Cardano密钥对
// 提供额外的方法支持选择地址类型
func (g *AdaKeyGenerator) GenerateKeyPairWithAddressType(addressType AddressType) (address, publicKey, privateKey string, err error) {
	return g.GenerateKeyPairWithOptions(addressType, Mainnet)
}

// GenerateKeyPairWithOptions 生成带选项的Cardano密钥对
// 支持选择地址类型和网络类型
func (g *AdaKeyGenerator) GenerateKeyPairWithOptions(addressType AddressType, networkType NetworkType) (address, publicKey, privateKey string, err error) {
	// 生成Ed25519密钥对
	publicKeyBytes, privateKeyBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成符合Cardano规范的地址
	address, err = generateCardanoAddress(publicKeyBytes, addressType, networkType)
	if err != nil {
		return "", "", "", err
	}

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKeyWithOptions 从现有私钥推导Cardano公钥和地址（带选项）
func (g *AdaKeyGenerator) DeriveKeyPairFromPrivateKeyWithOptions(privateKey string, addressType AddressType, networkType NetworkType) (address, publicKey string, err error) {
	// 解析私钥（必须是64字节的十六进制字符串，Ed25519私钥格式）
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 验证私钥长度是否符合Ed25519要求
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		// 如果是32字节，尝试转换为完整的Ed25519私钥格式
		if len(privateKeyBytes) == 32 {
			// 重新生成完整的Ed25519密钥对
			publicKeyBytes := ed25519.NewKeyFromSeed(privateKeyBytes)
			publicKey = hex.EncodeToString(publicKeyBytes)
			
			// 生成符合Cardano规范的地址
			address, err = generateCardanoAddress(publicKeyBytes, addressType, networkType)
			if err != nil {
				return "", "", err
			}
			return address, publicKey, nil
		}
		return "", "", fmt.Errorf("invalid private key length: expected %d bytes (or 32 bytes for seed), got %d bytes", 
				ed25519.PrivateKeySize, len(privateKeyBytes))
	}

	// 从私钥提取公钥
	privateKeyObj := ed25519.PrivateKey(privateKeyBytes)
	publicKeyBytes := privateKeyObj.Public().(ed25519.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成符合Cardano规范的地址
	address, err = generateCardanoAddress(publicKeyBytes, addressType, networkType)
	if err != nil {
		return "", "", err
	}

	return address, publicKey, nil
}

// PublicKeyToAddressWithOptions 从公钥生成Cardano地址（带选项）
func (g *AdaKeyGenerator) PublicKeyToAddressWithOptions(publicKey string, addressType AddressType, networkType NetworkType) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 验证公钥长度是否符合Ed25519要求
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key length: expected %d bytes, got %d bytes", 
				ed25519.PublicKeySize, len(publicKeyBytes))
	}

	// 生成符合Cardano规范的地址
	address, err = generateCardanoAddress(publicKeyBytes, addressType, networkType)
	if err != nil {
		return "", err
	}

	return address, nil
}

// generateCardanoAddress 生成符合Cardano规范的地址，支持两种格式和网络类型
func generateCardanoAddress(publicKeyBytes []byte, addressType AddressType, networkType NetworkType) (string, error) {
	// 转换网络类型和地址类型为对应的ID值
	// 根据CIP-19规范：
	// - 高4位(7-4)是地址类型：0000为Base Address，0110为Enterprise Address
	// - 低4位(3-0)是网络：0000为测试网，0001为主网
	var networkID uint8
	var addrTypeID uint8

	switch networkType {
	case Mainnet:
		networkID = 1 // 主网网络ID (0001)
	case Testnet:
		networkID = 0 // 测试网网络ID (0000)
	default:
		return "", fmt.Errorf("unsupported network type: %s", networkType)
	}

	switch addressType {
	case BaseAddress:
		addrTypeID = 0 // 基本地址类型ID (0000)
	case EnterpriseAddress:
		addrTypeID = 6 // 企业地址类型ID (0110)
	default:
		return "", fmt.Errorf("unsupported address type: %s", addressType)
	}

	// 计算公钥的Blake2b-224哈希作为支付凭证
	paymentCredHash, err := blake2b.New(28, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create blake2b-224 hash: %w", err)
	}
	paymentCredHash.Write(publicKeyBytes)
	paymentCred := paymentCredHash.Sum(nil)

	// 根据网络ID确定地址前缀
	var hrp string
	switch networkID {
	case 1:
		hrp = "addr"       // Mainnet (0001)
	case 0:
		hrp = "addr_test"  // Testnet (0000)
	default:
		return "", fmt.Errorf("unsupported network ID: %d", networkID)
	}

	// 构建地址数据
	var data []byte

	// 构建地址头部（一个字节，根据CIP-19规范：高4位是地址类型，低4位是网络ID）
	addressHeader := (addrTypeID << 4) | networkID
	data = append(data, addressHeader)

	// 根据地址类型构建不同的地址
	switch addrTypeID {
	case 0:
		// 基本地址: type | payment credential type | payment credential hash | stake credential type | stake credential hash
		data = append(data, 0) // 支付凭证类型 (0 = 密钥哈希)
		data = append(data, paymentCred...) // 支付凭证哈希
		
		// 假设权益凭证与支付凭证相同
		data = append(data, 0) // 权益凭证类型 (0 = 密钥哈希)
		data = append(data, paymentCred...) // 权益凭证哈希
	case 6:
		// 企业地址: type | payment credential type | payment credential hash
		data = append(data, 0) // 支付凭证类型 (0 = 密钥哈希)
		data = append(data, paymentCred...) // 支付凭证哈希
	default:
		return "", fmt.Errorf("unsupported address type: %d", addrTypeID)
	}

	// 将数据从8位字节转换为5位字
	expanded, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}

	// 使用原始bech32编码（根据用户要求）	
	address, err := bech32.Encode(hrp, expanded)
	if err != nil {
		return "", fmt.Errorf("failed to encode with bech32: %w", err)
	}

	return address, nil
}