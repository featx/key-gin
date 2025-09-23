package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/featx/keys-gin/lib/crypto"
)

func main() {
	// 创建TRON密钥生成器和交易签名器
	keyGenerator := &crypto.TronKeyGenerator{}
	signer := &crypto.TronTransactionSigner{}

	// 测试计数器
	passedTests := 0
	failedTests := 0
	totalTests := 7

	fmt.Println("=== TRON 密钥和签名验证测试 ===")
	fmt.Println()

	// 测试1：生成密钥对
	fmt.Println("测试1: 生成TRON密钥对")
	address1, publicKey1, privateKey1, err := keyGenerator.GenerateKeyPair()
	if err != nil {
		fmt.Printf("❌ 失败: %v\n", err)
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 生成密钥对\n")
		fmt.Printf("   地址: %s\n", address1)
		fmt.Printf("   公钥: %s\n", publicKey1)
		fmt.Printf("   私钥: %s\n", privateKey1)
		passedTests++
	}
	fmt.Println()

	// 测试2：从公钥生成地址
	fmt.Println("测试2: 从公钥生成TRON地址")
	derivedAddress, err := keyGenerator.PublicKeyToAddress(publicKey1)
	if err != nil {
		fmt.Printf("❌ 失败: %v\n", err)
		failedTests++
	} else if derivedAddress != address1 {
		fmt.Printf("❌ 失败: 生成的地址与原始地址不匹配\n")
		fmt.Printf("   期望: %s\n", address1)
		fmt.Printf("   实际: %s\n", derivedAddress)
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 地址匹配\n")
		fmt.Printf("   地址: %s\n", derivedAddress)
		passedTests++
	}
	fmt.Println()

	// 测试3：从私钥派生密钥对
	fmt.Println("测试3: 从私钥派生密钥对")
	derivedAddress3, derivedPublicKey3, err := keyGenerator.DeriveKeyPairFromPrivateKey(privateKey1)
	if err != nil {
		fmt.Printf("❌ 失败: %v\n", err)
		failedTests++
	} else if derivedPublicKey3 != publicKey1 || derivedAddress3 != address1 {
		fmt.Printf("❌ 失败: 派生的密钥对与原始密钥对不匹配\n")
		fmt.Printf("   期望公钥: %s\n", publicKey1)
		fmt.Printf("   实际公钥: %s\n", derivedPublicKey3)
		fmt.Printf("   期望地址: %s\n", address1)
		fmt.Printf("   实际地址: %s\n", derivedAddress3)
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 派生的密钥对匹配\n")
		fmt.Printf("   派生地址: %s\n", derivedAddress3)
		fmt.Printf("   派生公钥: %s\n", derivedPublicKey3)
		passedTests++
	}
	fmt.Println()

	// 创建一个符合TronTransactionRequest结构的TRX转账交易
	transactionData := map[string]interface{}{
		"ownerAddress": address1,
		"toAddress":    "TTmvTQ5P33kq39gXsSyBzQnP9aJd79cZ8B",
		"amount":       int64(1000000),
		"feeLimit":     int64(100000),
	}

	// 序列化为JSON字符串
	txJSON, err := json.Marshal(transactionData)
	if err != nil {
		fmt.Printf("❌ 序列化交易失败: %v\n", err)
		log.Fatal(err)
	}
	txJSONStr := string(txJSON)

	// 测试4：使用私钥签名交易
	fmt.Println("测试4: 使用私钥签名交易")
	signature, txHash, err := signer.SignTransaction(txJSONStr, privateKey1)
	if err != nil {
		fmt.Printf("❌ 失败: %v\n", err)
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 交易签名生成\n")
		fmt.Printf("   交易哈希: %s\n", txHash)
		fmt.Printf("   签名: %s\n", signature[:60]+"...") // 只显示部分签名以避免过长
		passedTests++
	}
	fmt.Println()

	// 测试5：验证交易签名
	fmt.Println("测试5: 验证交易签名")
	isValid, err := signer.VerifyTransaction(txJSONStr, signature, publicKey1)
	if err != nil {
		fmt.Printf("❌ 失败: %v\n", err)
		failedTests++
	} else if !isValid {
		fmt.Printf("❌ 失败: 签名验证失败\n")
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 签名验证通过\n")
		passedTests++
	}
	fmt.Println()

	// 测试6：使用不同的密钥对验证签名
	fmt.Println("测试6: 使用不同的密钥对验证签名")
	// 生成新的密钥对
	_, publicKey2, _, err := keyGenerator.GenerateKeyPair()
	if err != nil {
		fmt.Printf("❌ 无法生成新的密钥对: %v\n", err)
		failedTests++
	} else {
		isValid, err := signer.VerifyTransaction(txJSONStr, signature, publicKey2)
		if err != nil {
			fmt.Printf("❌ 验证失败: %v\n", err)
			failedTests++
		} else if isValid {
			fmt.Printf("❌ 失败: 不应该通过不匹配的密钥对验证\n")
			failedTests++
		} else {
			fmt.Printf("✅ 成功: 正确拒绝了不匹配的密钥对\n")
			passedTests++
		}
	}
	fmt.Println()

	// 测试7：使用不同的密钥对签名并比较
	fmt.Println("测试7: 使用不同的密钥对签名并比较")
	// 生成新的密钥对
	_, _, privateKey2, err := keyGenerator.GenerateKeyPair()
	if err != nil {
		fmt.Printf("❌ 无法生成新的密钥对: %v\n", err)
		failedTests++
	} else {
		// 使用新的私钥签名
		signature2, txHash2, err := signer.SignTransaction(txJSONStr, privateKey2)
		if err != nil {
			fmt.Printf("❌ 签名生成失败: %v\n", err)
			failedTests++
		} else if signature == signature2 {
			fmt.Printf("❌ 失败: 不同密钥对应该生成不同的签名\n")
			failedTests++
		} else {
			fmt.Printf("✅ 成功: 不同密钥对生成了不同的签名\n")
			fmt.Printf("   新交易哈希: %s\n", txHash2)
			fmt.Printf("   新签名: %s\n", signature2[:60]+"...")
			passedTests++
		}
	}
	fmt.Println()

	// 测试总结
	fmt.Println("=== 测试总结 ===")
	fmt.Printf("通过测试: %d/%d\n", passedTests, totalTests)
	fmt.Printf("失败测试: %d/%d\n", failedTests, totalTests)

	if failedTests > 0 {
		fmt.Println("❌ 测试未通过")
	} else {
		fmt.Println("✅ 所有测试通过!")
	}
}