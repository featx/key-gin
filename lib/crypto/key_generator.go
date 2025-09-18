package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/featx/keys-gin/web/model"
)

// KeyGenerator 密钥生成器接口
type KeyGenerator interface {
	GenerateKeyPair() (address, publicKey, privateKey string, err error)
	// DeriveKeyPairFromPrivateKey 从现有私钥推导公钥和地址
	DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error)
	// PublicKeyToAddress 从公钥生成地址
	PublicKeyToAddress(publicKey string) (address string, err error)
}

// NewKeyGenerator 根据区块链类型创建密钥生成器
func NewKeyGenerator(chainType string) (KeyGenerator, error) {
	switch chainType {
	case model.ChainTypeETH, model.ChainTypeAvalanche:
		return &EthKeyGenerator{}, nil
	case model.ChainTypeBTC:
		return &BtcKeyGenerator{}, nil
	case model.ChainTypeSolana:
		return &SolanaKeyGenerator{}, nil
	case model.ChainTypeTRON:
		return &TronKeyGenerator{}, nil
	case model.ChainTypeSUI:
		return &SuiKeyGenerator{}, nil
	case model.ChainTypeADA:
		return &AdaKeyGenerator{}, nil
	case model.ChainTypePolkadot, model.ChainTypeKusama:
		return &PolkadotKeyGenerator{}, nil
	case model.ChainTypeTON:
		return &TonKeyGenerator{}, nil
	default:
		return nil, errors.New("unsupported chain type")
	}
}

// EthKeyGenerator 以太坊及兼容链的密钥生成器
// 适用于以太坊、币安智能链、Polygon、Avalanche等EVM兼容链
type EthKeyGenerator struct{}

// GenerateKeyPair 生成以太坊密钥对
func (g *EthKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成ECDSA私钥
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
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
	addressBytes := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)
	address = addressBytes.Hex()

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导公钥和地址
func (g *EthKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 从字节创建ECDSA私钥
	privateKeyECDSA, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert to ECDSA private key: %w", err)
	}

	// 获取公钥的十六进制表示
	publicKeyBytes := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成以太坊地址
	addressBytes := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)
	address = addressBytes.Hex()

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成以太坊地址
func (g *EthKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 从字节创建ECDSA公钥
	pubKey, err := crypto.DecompressPubkey(publicKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decompress public key: %w", err)
	}

	// 生成以太坊地址
	addressBytes := crypto.PubkeyToAddress(*pubKey)
	address = addressBytes.Hex()

	return address, nil
}

// BtcKeyGenerator 比特币密钥生成器
type BtcKeyGenerator struct{}

// GenerateKeyPair 生成比特币密钥对
func (g *BtcKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成ECDSA私钥（比特币使用secp256k1曲线）
	privateKeyECDSA, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 转换为btcec私钥
	privKey, _ := btcec.PrivKeyFromBytes(crypto.FromECDSA(privateKeyECDSA))

	// 获取私钥的十六进制表示
	privateKeyBytes := privKey.Serialize()
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := privKey.PubKey().SerializeCompressed()
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 注意：这里简化了比特币地址的生成
	// 完整的比特币地址生成还需要添加网络前缀、进行Base58编码等步骤
	// 此处返回公钥的十六进制表示作为示例
	address = publicKey

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导公钥和地址
func (g *BtcKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 转换为btcec私钥
	privKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	if privKey == nil {
		return "", "", fmt.Errorf("failed to convert to btcec private key: invalid private key bytes")
	}

	// 获取公钥的十六进制表示
	publicKeyBytes := privKey.PubKey().SerializeCompressed()
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 注意：这里简化了比特币地址的生成
	// 完整的比特币地址生成还需要添加网络前缀、进行Base58编码等步骤
	// 此处返回公钥的十六进制表示作为示例
	address = publicKey

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成比特币地址（简化实现）
func (g *BtcKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 注意：这里简化了比特币地址的生成
	// 完整的比特币地址生成还需要添加网络前缀、进行Base58编码等步骤
	// 此处返回公钥的十六进制表示作为示例
	address = publicKey

	return address, nil
}

// SolanaKeyGenerator Solana密钥生成器
// 注意：这是一个占位实现，实际的Solana密钥生成需要使用Solana特定的库
// 参考：https://docs.solana.com/developing/clients/javascript-reference
// 依赖：github.com/mr-tron/base58、github.com/solana-labs/solana-go

type SolanaKeyGenerator struct{}

// GenerateKeyPair 生成Solana密钥对（占位实现）
func (g *SolanaKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 暂时使用以太坊的密钥生成逻辑作为占位符
	// 生成ECDSA私钥
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKeyBytes := crypto.FromECDSA(privateKeyECDSA)
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成模拟的Solana地址
	address = "SOL" + hex.EncodeToString(publicKeyBytes[:20])

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导Solana公钥和地址（占位实现）
func (g *SolanaKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
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

	// 生成模拟的Solana地址
	address = "SOL" + hex.EncodeToString(publicKeyBytes[:20])

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成Solana地址（占位实现）
func (g *SolanaKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 生成模拟的Solana地址
	address = "SOL" + hex.EncodeToString(publicKeyBytes[:20])

	return address, nil
}

// TronKeyGenerator TRON密钥生成器
// 注意：这是一个占位实现，实际的TRON密钥生成需要使用TRON特定的库
// 依赖：github.com/fbsobreira/gotron-sdk/pkg/crypto

type TronKeyGenerator struct{}

// GenerateKeyPair 生成TRON密钥对（占位实现）
func (g *TronKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 暂时使用以太坊的密钥生成逻辑作为占位符
	// 生成ECDSA私钥
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKeyBytes := crypto.FromECDSA(privateKeyECDSA)
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成模拟的TRON地址（TRON地址以T开头）
	addressBytes := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)
	address = "T" + addressBytes.Hex()[1:]

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导TRON公钥和地址（占位实现）
func (g *TronKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
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

	// 生成模拟的TRON地址（TRON地址以T开头）
	addressBytes := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)
	address = "T" + addressBytes.Hex()[1:]

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成TRON地址（占位实现）
func (g *TronKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 从字节创建ECDSA公钥
	pubKey, err := crypto.DecompressPubkey(publicKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decompress public key: %w", err)
	}

	// 生成模拟的TRON地址（TRON地址以T开头）
	addressBytes := crypto.PubkeyToAddress(*pubKey)
	address = "T" + addressBytes.Hex()[1:]

	return address, nil
}

// SuiKeyGenerator SUI密钥生成器
// 注意：这是一个占位实现，实际的SUI密钥生成需要使用SUI特定的库
// 依赖：github.com/MystenLabs/sui/crypto

type SuiKeyGenerator struct{}

// GenerateKeyPair 生成SUI密钥对（占位实现）
func (g *SuiKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 暂时使用以太坊的密钥生成逻辑作为占位符
	// 生成ECDSA私钥
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKeyBytes := crypto.FromECDSA(privateKeyECDSA)
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成模拟的SUI地址
	address = "0x" + hex.EncodeToString(publicKeyBytes[:20])

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导SUI公钥和地址（占位实现）
func (g *SuiKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
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

	// 生成模拟的SUI地址
	address = "0x" + hex.EncodeToString(publicKeyBytes[:20])

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成SUI地址（占位实现）
func (g *SuiKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 生成模拟的SUI地址
	address = "0x" + hex.EncodeToString(publicKeyBytes[:20])

	return address, nil
}

// AdaKeyGenerator Cardano (ADA)密钥生成器
// 注意：这是一个占位实现，实际的Cardano密钥生成需要使用Cardano特定的库
// 依赖：github.com/input-output-hk/cardano-addresses/go

type AdaKeyGenerator struct{}

// GenerateKeyPair 生成Cardano密钥对（占位实现）
func (g *AdaKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 暂时使用以太坊的密钥生成逻辑作为占位符
	// 生成ECDSA私钥
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKeyBytes := crypto.FromECDSA(privateKeyECDSA)
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成模拟的Cardano地址
	address = "addr1" + hex.EncodeToString(publicKeyBytes[:20])

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导Cardano公钥和地址（占位实现）
func (g *AdaKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
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

	// 生成模拟的Cardano地址
	address = "addr1" + hex.EncodeToString(publicKeyBytes[:20])

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成Cardano地址（占位实现）
func (g *AdaKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 生成模拟的Cardano地址
	address = "addr1" + hex.EncodeToString(publicKeyBytes[:20])

	return address, nil
}

// PolkadotKeyGenerator Polkadot和Kusama密钥生成器
// 注意：这是一个占位实现，实际的Polkadot/Kusama密钥生成需要使用特定的库
// 依赖：github.com/paritytech/parity-crypto

type PolkadotKeyGenerator struct{}

// GenerateKeyPair 生成Polkadot/Kusama密钥对（占位实现）
func (g *PolkadotKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 暂时使用以太坊的密钥生成逻辑作为占位符
	// 生成ECDSA私钥
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKeyBytes := crypto.FromECDSA(privateKeyECDSA)
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成模拟的Polkadot地址
	address = "1" + hex.EncodeToString(publicKeyBytes[:20])

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导Polkadot/Kusama公钥和地址（占位实现）
func (g *PolkadotKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
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

	// 生成模拟的Polkadot地址
	address = "1" + hex.EncodeToString(publicKeyBytes[:20])

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成Polkadot/Kusama地址（占位实现）
func (g *PolkadotKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 生成模拟的Polkadot地址
	address = "1" + hex.EncodeToString(publicKeyBytes[:20])

	return address, nil
}

// TonKeyGenerator TON (The Open Network)密钥生成器
// 注意：这是一个占位实现，实际的TON密钥生成需要使用TON特定的库
// 依赖：github.com/xssnick/tonutils-go

type TonKeyGenerator struct{}

// GenerateKeyPair 生成TON密钥对（占位实现）
func (g *TonKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 暂时使用以太坊的密钥生成逻辑作为占位符
	// 生成ECDSA私钥
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKeyBytes := crypto.FromECDSA(privateKeyECDSA)
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成模拟的TON地址
	address = "EQ" + hex.EncodeToString(publicKeyBytes[:32])

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导TON公钥和地址（占位实现）
func (g *TonKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
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

	// 生成模拟的TON地址
	address = "EQ" + hex.EncodeToString(publicKeyBytes[:32])

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成TON地址（占位实现）
func (g *TonKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 生成模拟的TON地址
	address = "EQ" + hex.EncodeToString(publicKeyBytes[:32])

	return address, nil
}