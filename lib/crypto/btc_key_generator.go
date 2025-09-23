package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// BtcKeyGenerator Bitcoin密钥生成器
// 支持比特币及分叉币的密钥生成

type BtcKeyGenerator struct {}

// GenerateKeyPair 生成比特币密钥对
func (g *BtcKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	// 生成ECDSA私钥
	privateKeyECDSA, err := btcec.NewPrivateKey()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// 获取私钥的十六进制表示
	privateKeyBytes := privateKeyECDSA.Serialize()
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := privateKeyECDSA.PubKey().SerializeCompressed()
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成比特币地址
	addressPubKey, err := btcutil.NewAddressPubKey(publicKeyBytes, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create address: %w", err)
	}

	address = addressPubKey.EncodeAddress()

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导比特币公钥和地址
func (g *BtcKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 转换为ECDSA私钥
	privateKeyECDSA, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKeyBytes := privateKeyECDSA.PubKey().SerializeCompressed()
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成比特币地址
	addressPubKey, err := btcutil.NewAddressPubKey(publicKeyBytes, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", fmt.Errorf("failed to create address: %w", err)
	}

	address = addressPubKey.EncodeAddress()

	return address, publicKey, nil
}

// PublicKeyToAddress 从公钥生成比特币地址
func (g *BtcKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 从字节创建ECDSA公钥
	pubKey, err := btcec.ParsePubKey(publicKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	// 生成比特币地址
	addressPubKey, err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(), &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %w", err)
	}

	address = addressPubKey.EncodeAddress()

	return address, nil
}