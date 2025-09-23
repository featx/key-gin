package main

import (
	"encoding/json"
	"fmt"
	"github.com/featx/keys-gin/lib/crypto"
)

// TonDemoConfig 演示配置
var TonDemoConfig = struct {
	TestCount int
}{
	TestCount: 5,
}

// TonTestResult 测试结果
type TonTestResult struct {
	TestName      string
	Success       bool
	ErrorMessage  string
	PublicKey     string
	PrivateKey    string
	Address       string
	SignedTx      string
	TxHash        string
}

func main() {
	fmt.Println("==================================")
	fmt.Println("          TON 验证演示              ")
	fmt.Println("==================================")

	testResults := make([]*TonTestResult, 0, TonDemoConfig.TestCount)
	passCount := 0
	failCount := 0

	// 测试1: 生成密钥对并转换为地址
	result := testGenerateKeyPairAndAddress()
	testResults = append(testResults, result)
	if result.Success {
		passCount++
	} else {
		failCount++
	}

	// 测试2: 从私钥派生密钥对
	if len(testResults) > 0 && testResults[0].Success {
		result := testDeriveKeyPairFromPrivateKey(testResults[0].PrivateKey)
		testResults = append(testResults, result)
		if result.Success {
			passCount++
		} else {
			failCount++
		}
	} else {
		// 如果第一个测试失败，跳过此测试
		result := &TonTestResult{
			TestName:     "从私钥派生密钥对",
			Success:      false,
			ErrorMessage: "跳过，因为第一个测试失败",
		}
		testResults = append(testResults, result)
		failCount++
	}

	// 测试3: 签名交易
	if len(testResults) > 0 && testResults[0].Success {
		result := testSignTransaction(testResults[0].PrivateKey)
		testResults = append(testResults, result)
		if result.Success {
			passCount++
		} else {
			failCount++
		}
	} else {
		// 如果第一个测试失败，跳过此测试
		result := &TonTestResult{
			TestName:     "签名交易",
			Success:      false,
			ErrorMessage: "跳过，因为第一个测试失败",
		}
		testResults = append(testResults, result)
		failCount++
	}

	// 测试4: 验证交易签名
	if len(testResults) > 2 && testResults[0].Success && testResults[2].Success {
		result := testVerifyTransaction(
			testResults[2].SignedTx,
			testResults[0].PublicKey,
			testResults[2].TxHash,
		)
		testResults = append(testResults, result)
		if result.Success {
			passCount++
		} else {
			failCount++
		}
	} else {
		// 如果相关测试失败，跳过此测试
		result := &TonTestResult{
			TestName:     "验证交易签名",
			Success:      false,
			ErrorMessage: "跳过，因为相关测试失败",
		}
		testResults = append(testResults, result)
		failCount++
	}

	// 测试5: 错误的私钥格式
	result = testInvalidPrivateKey()
	testResults = append(testResults, result)
	if result.Success {
		passCount++
	} else {
		failCount++
	}

	// 打印测试结果摘要
	fmt.Println("\n==================================")
	fmt.Println("          测试结果摘要              ")
	fmt.Println("==================================")

	for i, result := range testResults {
		status := "通过"
		if !result.Success {
			status = "失败"
		}
		fmt.Printf("测试 %d: %s - %s\n", i+1, result.TestName, status)
		if !result.Success && result.ErrorMessage != "" {
			fmt.Printf("  错误信息: %s\n", result.ErrorMessage)
		}
	}

	fmt.Println("\n==================================")
	fmt.Printf("通过测试: %d/%d\n", passCount, TonDemoConfig.TestCount)
	fmt.Printf("失败测试: %d/%d\n", failCount, TonDemoConfig.TestCount)

	if failCount == 0 {
		fmt.Println("所有测试通过！")
	} else {
		fmt.Println("有测试失败，请检查错误信息。")
	}
	fmt.Println("==================================")
}

// 测试1: 生成密钥对并转换为地址
func testGenerateKeyPairAndAddress() *TonTestResult {
	result := &TonTestResult{
		TestName: "生成密钥对并转换为地址",
		Success:  true,
	}

	keyGenerator := &crypto.TonKeyGenerator{}
	address, publicKey, privateKey, err := keyGenerator.GenerateKeyPair()
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("生成密钥对失败: %v", err)
		return result
	}

	result.PublicKey = publicKey
	result.PrivateKey = privateKey
	result.Address = address

	fmt.Printf("生成的公钥: %s\n", publicKey[:16] + "..." + publicKey[len(publicKey)-16:])
	fmt.Printf("生成的私钥: %s\n", privateKey[:16] + "..." + privateKey[len(privateKey)-16:])
	fmt.Printf("生成的地址: %s\n", address)

	return result
}

// 测试2: 从私钥派生密钥对
func testDeriveKeyPairFromPrivateKey(privateKey string) *TonTestResult {
	result := &TonTestResult{
		TestName: "从私钥派生密钥对",
		Success:  true,
	}

	keyGenerator := &crypto.TonKeyGenerator{}
	address, publicKey, err := keyGenerator.DeriveKeyPairFromPrivateKey(privateKey)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("派生密钥对失败: %v", err)
		return result
	}

	result.PublicKey = publicKey
	result.Address = address

	fmt.Printf("派生的公钥: %s\n", publicKey[:16] + "..." + publicKey[len(publicKey)-16:])
	fmt.Printf("派生的地址: %s\n", address)

	return result
}

// 测试3: 签名交易
func testSignTransaction(privateKey string) *TonTestResult {
	result := &TonTestResult{
		TestName: "签名交易",
		Success:  true,
	}

	// 创建一个测试交易
	txRequest := crypto.TonTransactionRequest{
		Address:     "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
		Destination: "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
		Amount:      1000000000, // 1 TON = 1,000,000,000 nanotons
		Seqno:       1,
	}

	txData, err := json.Marshal(txRequest)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("序列化交易数据失败: %v", err)
		return result
	}

	signer := &crypto.TonTransactionSigner{}
	signedTx, txHash, err := signer.SignTransaction(string(txData), privateKey)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("签名交易失败: %v", err)
		return result
	}

	result.SignedTx = signedTx
	result.TxHash = txHash

	fmt.Printf("交易哈希: %s\n", txHash)
	fmt.Printf("签名: %s\n", signedTx[:16] + "..." + signedTx[len(signedTx)-16:])

	return result
}

// 测试4: 验证交易签名
func testVerifyTransaction(signedTx, publicKey, txHash string) *TonTestResult {
	result := &TonTestResult{
		TestName: "验证交易签名",
		Success:  true,
	}

	// 重新创建测试交易以验证
	txRequest := crypto.TonTransactionRequest{
		Address:     "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
		Destination: "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
		Amount:      1000000000,
		Seqno:       1,
	}

	txData, err := json.Marshal(txRequest)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("序列化交易数据失败: %v", err)
		return result
	}

	signer := &crypto.TonTransactionSigner{}
	valid, err := signer.VerifyTransaction(string(txData), signedTx, publicKey)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("验证签名失败: %v", err)
		return result
	}

	if !valid {
		result.Success = false
		result.ErrorMessage = "签名无效"
		return result
	}

	fmt.Printf("签名验证成功\n")

	return result
}

// 测试5: 错误的私钥格式
func testInvalidPrivateKey() *TonTestResult {
	result := &TonTestResult{
		TestName: "错误的私钥格式",
		Success:  true, // 预期会失败，所以如果失败则测试通过
	}

	invalidPrivateKey := "this_is_not_a_valid_private_key"

	signer := &crypto.TonTransactionSigner{}
	txRequest := crypto.TonTransactionRequest{
		Address:     "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
		Destination: "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
		Amount:      1000000000,
		Seqno:       1,
	}

	txData, err := json.Marshal(txRequest)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("序列化交易数据失败: %v", err)
		return result
	}

	_, _, err = signer.SignTransaction(string(txData), invalidPrivateKey)
	if err == nil {
		result.Success = false
		result.ErrorMessage = "使用无效私钥应该失败，但成功了"
		return result
	}

	fmt.Printf("预期的错误: %v\n", err)

	return result
}