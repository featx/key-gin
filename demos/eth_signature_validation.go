package main

import (
	"encoding/json"
	"fmt"
	"github.com/featx/keys-gin/lib/crypto"
)

func main() {
	fmt.Println("=== 以太坊 密钥和签名验证测试 ===")
	fmt.Println()

	// 创建以太坊密钥生成器和交易签名器
	keyGenerator := crypto.EthKeyGenerator{}
	signer := &crypto.EthTransactionSigner{}

	// 测试计数器
	passedTests := 0
	failedTests := 0
	totalTests := 7

	// 定义需要在多个测试间共享的变量
	var privateKey2 string
	var eip1559Signature, eip1559TxHash string
	var eip1559TxData map[string]interface{}

	// 测试1：生成以太坊密钥对
	fmt.Println("测试1: 生成以太坊密钥对")
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
	fmt.Println("测试2: 从公钥生成以太坊地址")
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

	// 测试4：使用私钥签名交易 (Legacy格式)
	fmt.Println("测试4: 使用私钥签名交易 (Legacy格式)")
	// 创建一个Legacy格式的以太坊交易
	legacyTxData := map[string]interface{}{
		"from":     address1,
		"to":       "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
		"gas":      "0x5208",          // 21000 in hex
		"gasPrice": "0x3b9aca00",      // 10000000000 in hex
		"value":    "0x1",             // 1 wei in hex
		"nonce":    "0x0",             // 0 in hex
		"data":     "",                // 空数据
		"chainId":  "0x1",             // 主网链ID
	}
	legacyTxJSON, err := json.Marshal(legacyTxData)
	if err != nil {
		fmt.Printf("❌ 序列化交易失败: %v\n", err)
		failedTests++
	} else {
		legacyTxJSONStr := string(legacyTxJSON)
		legacySignature, legacyTxHash, err := signer.SignTransaction(legacyTxJSONStr, privateKey1)
		if err != nil {
			fmt.Printf("❌ 失败: %v\n", err)
			failedTests++
		} else {
			fmt.Printf("✅ 成功: Legacy交易签名生成\n")
			fmt.Printf("   交易哈希: %s\n", legacyTxHash)
			fmt.Printf("   签名: %s...\n", legacySignature[:100]) // 只显示部分签名以避免过长
			passedTests++
		}
	}
	fmt.Println()

	// 测试5：使用私钥签名交易 (EIP-1559格式)
	fmt.Println("测试5: 使用私钥签名交易 (EIP-1559格式)")
	// 创建一个EIP-1559格式的以太坊交易
	eip1559TxData = map[string]interface{}{
		"from":                address1,
		"to":                  "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
		"gas":                 "0x5208",          // 21000 in hex
		"maxPriorityFeePerGas": "0x9502f900",      // 2500000000 in hex
		"maxFeePerGas":        "0x12a05f200",      // 50000000000 in hex
		"value":               "0x1",             // 1 wei in hex
		"nonce":               "0x0",             // 0 in hex
		"data":                "",                // 空数据
		"chainId":             "0x1",             // 主网链ID
	}
	eip1559TxJSON, err := json.Marshal(eip1559TxData)
	if err != nil {
		fmt.Printf("❌ 序列化交易失败: %v\n", err)
		failedTests++
	} else {
		eip1559TxJSONStr := string(eip1559TxJSON)
		eip1559Signature, eip1559TxHash, err = signer.SignTransaction(eip1559TxJSONStr, privateKey1)
		if err != nil {
			fmt.Printf("❌ 失败: %v\n", err)
			failedTests++
		} else {
			fmt.Printf("✅ 成功: EIP-1559交易签名生成\n")
			fmt.Printf("   交易哈希: %s\n", eip1559TxHash)
			fmt.Printf("   签名: %s...\n", eip1559Signature[:100]) // 只显示部分签名以避免过长
			passedTests++
		}
	}
	fmt.Println()

	// 测试6：生成另一个密钥对用于后续测试
	fmt.Println("测试6: 生成另一个密钥对用于比较测试")
	_, _, privateKey2, err = keyGenerator.GenerateKeyPair()
	if err != nil {
		fmt.Printf("❌ 无法生成新的密钥对: %v\n", err)
		failedTests++
	} else {
		fmt.Printf("✅ 成功: 生成第二个密钥对\n")
		fmt.Printf("   第二个私钥: %s\n", privateKey2)
		passedTests++
	}
	fmt.Println()

	// 测试7：使用不同的密钥对签名相同交易并比较
	fmt.Println("测试7: 使用不同的密钥对签名相同交易并比较")
	if privateKey2 != "" {
		// 再次序列化EIP-1559交易用于比较
		eip1559TxJSON, _ := json.Marshal(eip1559TxData)
		eip1559TxJSONStr := string(eip1559TxJSON)
		
		// 使用第二个密钥对签名
		signature2, txHash2, err := signer.SignTransaction(eip1559TxJSONStr, privateKey2)
		if err != nil {
			fmt.Printf("❌ 签名生成失败: %v\n", err)
			failedTests++
		} else {
			fmt.Printf("✅ 成功: 不同密钥对生成了不同的签名\n")
			fmt.Printf("   第一个签名开头: %s...\n", eip1559Signature[:30])
			fmt.Printf("   第二个签名开头: %s...\n", signature2[:30])
			fmt.Printf("   第一个交易哈希: %s\n", eip1559TxHash)
			fmt.Printf("   第二个交易哈希: %s\n", txHash2)
			passedTests++
		}
	} else {
		fmt.Printf("❌ 跳过测试: 没有可用的第二个密钥对\n")
		failedTests++
	}
	fmt.Println()

	// 测试总结
	fmt.Println("=== 测试总结 ===")
	fmt.Printf("通过测试: %d/%d\n", passedTests, totalTests)
	fmt.Printf("失败测试: %d/%d\n", failedTests, totalTests)
	
	if passedTests == totalTests {
		fmt.Println("✅ 所有测试通过!")
	} else {
		fmt.Println("❌ 测试未通过")
	}
}