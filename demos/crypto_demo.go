package main

import (
	"fmt"
	"log"

	"github.com/featx/keys-gin/lib/crypto"
)

func main() {
	fmt.Println("=== 区块链密钥生成器测试程序 ===")
	fmt.Println("这个程序只测试加密库的功能，不依赖数据库")
	fmt.Println("============================")

	// 测试不同区块链的密钥生成器
	testBlockchainKeys("BTC", &crypto.BtcKeyGenerator{})
	testBlockchainKeys("ETH", &crypto.EthKeyGenerator{})
	testBlockchainKeys("ADA", &crypto.AdaKeyGenerator{})
	testBlockchainKeys("SOL", &crypto.SolanaKeyGenerator{})
	testBlockchainKeys("SUI", &crypto.SuiKeyGenerator{})
	testBlockchainKeys("TON", &crypto.TonKeyGenerator{})
	testBlockchainKeys("TRX", &crypto.TronKeyGenerator{})

	fmt.Println("\n=== 测试完成 ===")
}

func testBlockchainKeys(chainName string, generator crypto.KeyGenerator) {
	fmt.Printf("\n测试 %s 密钥生成器:\n", chainName)

	// 生成新的密钥对
	address, publicKey, privateKey, err := generator.GenerateKeyPair()
	if err != nil {
		log.Printf("%s 生成密钥对失败: %v", chainName, err)
		return
	}

	// 打印密钥信息（实际应用中不应打印私钥）
	fmt.Printf("  私钥: %s\n", privateKey)
	fmt.Printf("  公钥: %s\n", publicKey)
	fmt.Printf("  地址: %s\n", address)

	// 测试从私钥推导公钥和地址
	derivedAddress, derivedPublicKey, err := generator.DeriveKeyPairFromPrivateKey(privateKey)
	if err != nil {
		log.Printf("%s 从私钥推导失败: %v", chainName, err)
		return
	}

	// 验证推导结果是否正确
	if derivedPublicKey != publicKey {
		log.Printf("%s 公钥推导不一致！", chainName)
	} else {
		fmt.Printf("  ✓ 公钥推导验证通过\n")
	}

	if derivedAddress != address {
		log.Printf("%s 地址推导不一致！", chainName)
	} else {
		fmt.Printf("  ✓ 地址推导验证通过\n")
	}

	// 测试公钥到地址的转换
	testAddress, err := generator.PublicKeyToAddress(publicKey)
	if err != nil {
		log.Printf("%s 公钥转地址失败: %v", chainName, err)
		return
	}

	if testAddress != address {
		log.Printf("%s 公钥转地址不一致！", chainName)
	} else {
		fmt.Printf("  ✓ 公钥转地址验证通过\n")
	}

	// 测试无效私钥处理
	invalidPrivateKey := "invalid_private_key_1234567890"
	_, _, err = generator.DeriveKeyPairFromPrivateKey(invalidPrivateKey)
	if err != nil {
		fmt.Printf("  ✓ 无效私钥处理验证通过 (返回错误: %v)\n", err)
	} else {
		log.Printf("%s 无效私钥处理失败: 应该返回错误但没有", chainName)
	}
}
