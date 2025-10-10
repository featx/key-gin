package main

import (
	"encoding/json"
	"fmt"
	"github.com/featx/keys-gin/lib/crypto"
)

func main() {
	fmt.Println("=== Aptos 密钥生成与签名演示 ===")
	fmt.Println()

	// 创建Aptos密钥生成器和交易签名器
	keyGenerator := &crypto.AptosKeyGenerator{}
	signer := &crypto.AptosTransactionSigner{}

	// 测试计数器
	passedTests := 0
	failedTests := 0
	totalTests := 7

	// 定义需要在多个测试间共享的变量
	var privateKey, publicKey, address string
	var err error

	// 测试1：生成Aptos密钥对
	fmt.Println("测试1: 生成Aptos密钥对")
	address, publicKey, privateKey, err = keyGenerator.GenerateKeyPair()
	if err != nil {
		fmt.Printf("❌ 失败: %v\n", err)
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 生成密钥对\n")
		fmt.Printf("   地址: %s\n", address)
		fmt.Printf("   公钥: %s\n", publicKey)
		fmt.Printf("   私钥: %s\n", privateKey)
		passedTests++
	}
	fmt.Println()

	// 测试2：从私钥派生密钥对
	fmt.Println("测试2: 从私钥派生Aptos密钥对")
	derivedAddress, derivedPublicKey, err := keyGenerator.DeriveKeyPairFromPrivateKey(privateKey)
	if err != nil {
		fmt.Printf("❌ 失败: %v\n", err)
		failedTests++
	} else if derivedAddress != address || derivedPublicKey != publicKey {
		fmt.Printf("❌ 失败: 派生的密钥对与原始密钥对不匹配\n")
		fmt.Printf("   期望地址: %s\n", address)
		fmt.Printf("   实际地址: %s\n", derivedAddress)
		fmt.Printf("   期望公钥: %s\n", publicKey)
		fmt.Printf("   实际公钥: %s\n", derivedPublicKey)
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 派生的密钥对与原始密钥对匹配\n")
		fmt.Printf("   地址: %s\n", derivedAddress)
		fmt.Printf("   公钥: %s\n", derivedPublicKey)
		passedTests++
	}
	fmt.Println()

	// 测试3：从公钥生成地址
	fmt.Println("测试3: 从公钥生成Aptos地址")
	addressFromPublicKey, err := keyGenerator.PublicKeyToAddress(publicKey)
	if err != nil {
		fmt.Printf("❌ 失败: %v\n", err)
		failedTests++
	} else if addressFromPublicKey != address {
		fmt.Printf("❌ 失败: 从公钥生成的地址与原始地址不匹配\n")
		fmt.Printf("   期望: %s\n", address)
		fmt.Printf("   实际: %s\n", addressFromPublicKey)
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 从公钥生成的地址与原始地址匹配\n")
		fmt.Printf("   地址: %s\n", addressFromPublicKey)
		passedTests++
	}
	fmt.Println()

	// 测试4：创建并签名Aptos交易
	fmt.Println("测试4: 创建并签名Aptos交易")

	// 创建交易请求
	txReq := crypto.AptosTransactionRequest{
		Type:                 "entry_function_payload",
		Sender:               address,
		SequenceNumber:       1,
		MaxGasAmount:         100000,
		GasUnitPrice:         100,
		ExpirationTimestamp:  1234567890,
		Payload:              json.RawMessage(`{"function":"0x1::coin::transfer","type_arguments":["0x1::aptos_coin::AptosCoin"],"arguments":["0x7c87f561388444f786d522f8bdf08073e578c7a5632a79a446f6f5240df743b9","1000000"]}`),
	}

	// 序列化交易请求
	txBytes, err := json.Marshal(txReq)
	if err != nil {
		fmt.Printf("❌ 序列化交易失败: %v\n", err)
		failedTests++
	} else {
		rawTx := string(txBytes)

		// 签名交易
		signedTx, txHash, err := signer.SignTransaction(rawTx, privateKey)
		if err != nil {
			fmt.Printf("❌ 签名交易失败: %v\n", err)
			failedTests++
		} else {
			fmt.Printf("✅ 成功: 签名交易\n")
			fmt.Printf("   交易哈希: %s\n", txHash)
			fmt.Printf("   签名交易: %s\n", signedTx)
			passedTests++

			// 测试5：验证交易签名
			fmt.Println("\n测试5: 验证Aptos交易签名")

			// 提取签名部分（移除前缀）
			signature := signedTx[len("aptos_signed_"):]

			// 验证签名
			isValid, err := signer.VerifyTransaction(rawTx, signature, publicKey)
			if err != nil {
				fmt.Printf("❌ 验证签名失败: %v\n", err)
				failedTests++
			} else if !isValid {
				fmt.Printf("❌ 失败: 签名无效\n")
				failedTests++
			} else {
				fmt.Printf("✅ 成功: 签名有效\n")
				passedTests++
			}
		}
	}
	fmt.Println()

	// 测试6：处理无效私钥
	fmt.Println("测试6: 处理无效私钥")
	invalidPrivateKey := "invalid_private_key"
	derivedAddress, derivedPublicKey, err = keyGenerator.DeriveKeyPairFromPrivateKey(invalidPrivateKey)
	if err == nil {
		fmt.Printf("❌ 失败: 应该返回错误但没有\n")
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 正确处理了无效私钥\n")
		fmt.Printf("   错误: %v\n", err)
		passedTests++
	}
	fmt.Println()

	// 测试7：处理无效公钥
	fmt.Println("测试7: 处理无效公钥")
	invalidPublicKey := "invalid_public_key"
	_, err = keyGenerator.PublicKeyToAddress(invalidPublicKey)
	if err == nil {
		fmt.Printf("❌ 失败: 应该返回错误但没有\n")
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 正确处理了无效公钥\n")
		fmt.Printf("   错误: %v\n", err)
		passedTests++
	}
	fmt.Println()

	// 输出测试结果摘要
	fmt.Println("=== 测试结果摘要 ===")
	fmt.Printf("总测试数: %d\n", totalTests)
	fmt.Printf("通过测试: %d\n", passedTests)
	fmt.Printf("失败测试: %d\n", failedTests)

	if failedTests == 0 {
		fmt.Println("✅ 所有测试通过！")
	} else {
		fmt.Println("❌ 有测试失败，请检查上面的输出信息。")
	}
}

// 辅助函数：格式化长字符串以便显示
func formatLongString(str string, maxLength int) string {
	if len(str) <= maxLength {
		return str
	}
	return str[:maxLength] + "..."
}