package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// EthKeyGenerator Ethereum密钥生成器
// 支持ETH及类ETH链的密钥生成

type EthKeyGenerator struct {}

// GenerateKeyPair 生成以太坊密钥对
func (g *EthKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成ECDSA私钥
	privateKeyECDSA, err := crypto.GenerateKey()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKeyBytes := crypto.FromECDSA(privateKeyECDSA)
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成以太坊地址
	address = crypto.PubkeyToAddress(privateKeyECDSA.PublicKey).Hex()

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导以太坊公钥和地址
func (g *EthKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 转换为ECDSA私钥
	privateKeyECDSA, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert to ECDSA private key: %w", err)
	}

	// 获取公钥的十六进制表示
	publicKeyBytes := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成以太坊地址
	address = crypto.PubkeyToAddress(privateKeyECDSA.PublicKey).Hex()

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成以太坊地址
func (g *EthKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 尝试将字节转换为ECDSA公钥
	var key *ecdsa.PublicKey
	if len(publicKeyBytes) == 65 {
		// 完整格式公钥
		key, err = crypto.UnmarshalPubkey(publicKeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal public key: %w", err)
		}
	} else if len(publicKeyBytes) == 33 {
		// 压缩格式公钥
		key, err = crypto.DecompressPubkey(publicKeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to decompress public key: %w", err)
		}
	} else {
		return "", fmt.Errorf("invalid public key length: %d", len(publicKeyBytes))
	}

	// 生成以太坊地址
	address = crypto.PubkeyToAddress(*key).Hex()

	return address, nil
}