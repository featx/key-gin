package main

import (
	"encoding/json"
	"fmt"

	"github.com/featx/keys-gin/lib/crypto"
)

// SuiTestResult 存储测试结果的结构体
type SuiTestResult struct {
	TestName   string
	IsPassed   bool
	Address    string
	PublicKey  string
	PrivateKey string
	Signature  string
	TxHash     string
	Error      error
}

func main() {
	// 创建测试结果列表
	results := []SuiTestResult{}

	// 运行各个测试
	results = append(results, testGenerateKeyPairAndAddress())
	results = append(results, testDeriveKeyPairFromPrivateKey())
	results = append(results, testSignTransaction())
	results = append(results, testVerifyTransaction())
	results = append(results, testInvalidPrivateKey())

	// 打印测试结果
	passCount := 0
	failCount := 0

	fmt.Println("\n===== SUI 密钥生成与签名功能测试结果 =====")

	for _, result := range results {
		status := "通过"
		if !result.IsPassed {
			status = "失败"
			failCount++
		} else {
			passCount++
		}

		fmt.Printf("\n测试: %s\n状态: %s\n", result.TestName, status)

		if result.Address != "" {
			fmt.Printf("地址: %s\n", result.Address)
		}

		if result.PublicKey != "" {
			fmt.Printf("公钥: %s\n", result.PublicKey)
		}

		if result.PrivateKey != "" {
			// 只显示部分私钥，出于安全考虑
			if len(result.PrivateKey) > 10 {
				fmt.Printf("私钥: %s...\n", result.PrivateKey[:10])
			} else {
				fmt.Printf("私钥: %s\n", result.PrivateKey)
			}
		}

		if result.Signature != "" {
			// 只显示部分签名，减少输出
			if len(result.Signature) > 10 {
				fmt.Printf("签名: %s...\n", result.Signature[:10])
			} else {
				fmt.Printf("签名: %s\n", result.Signature)
			}
		}

		if result.TxHash != "" {
			fmt.Printf("交易哈希: %s\n", result.TxHash)
		}

		if result.Error != nil {
			fmt.Printf("错误: %v\n", result.Error)
		}
	}

	// 打印测试总结
	fmt.Println("\n===== 测试总结 =====")
	fmt.Printf("通过测试: %d/%d\n", passCount, len(results))
	fmt.Printf("失败测试: %d/%d\n", failCount, len(results))

	if failCount == 0 {
		fmt.Println("所有测试通过！SUI密钥生成和签名功能正常工作。")
	} else {
		fmt.Println("有测试失败，请检查错误信息并修复问题。")
	}
}

// 测试生成密钥对并转换地址
func testGenerateKeyPairAndAddress() SuiTestResult {
	result := SuiTestResult{
		TestName: "生成密钥对并转换地址",
		IsPassed: false,
	}

	generator := &crypto.SuiKeyGenerator{}
	address, publicKey, privateKey, err := generator.GenerateKeyPair()

	if err != nil {
		result.Error = err
		return result
	}

	// 验证结果
	if address != "" && publicKey != "" && privateKey != "" {
		result.IsPassed = true
		result.Address = address
		result.PublicKey = publicKey
		result.PrivateKey = privateKey
	}

	return result
}

// 测试从私钥派生密钥对
func testDeriveKeyPairFromPrivateKey() SuiTestResult {
	result := SuiTestResult{
		TestName: "从私钥派生密钥对",
		IsPassed: false,
	}

	// 先生成一个有效的私钥
	generator := &crypto.SuiKeyGenerator{}
	_, _, originalPrivateKey, err := generator.GenerateKeyPair()
	if err != nil {
		result.Error = err
		return result
	}

	// 从私钥派生公钥和地址
	address, publicKey, err := generator.DeriveKeyPairFromPrivateKey(originalPrivateKey)

	if err != nil {
		result.Error = err
		return result
	}

	// 验证结果
	if address != "" && publicKey != "" {
		result.IsPassed = true
		result.Address = address
		result.PublicKey = publicKey
		result.PrivateKey = originalPrivateKey
	}

	return result
}

// 测试签名交易
func testSignTransaction() SuiTestResult {
	result := SuiTestResult{
		TestName: "签名交易",
		IsPassed: false,
	}

	// 生成密钥对
	generator := &crypto.SuiKeyGenerator{}
	address, publicKey, privateKey, err := generator.GenerateKeyPair()
	if err != nil {
		result.Error = err
		return result
	}

	// 构建交易请求
	txReq := crypto.SuiTransactionRequest{
		TransactionKind: "Transfer",
		GasBudget:       100000000,
		GasPrice:        1000,
		GasPayment:      []string{address},
		InputObjects:    []string{"0x0000000000000000000000000000000000000000000000000000000000000002"},
		Data:            json.RawMessage(`{"recipient":"0x0000000000000000000000000000000000000000000000000000000000000003","amount":1000}`),
	}

	rawTx, err := json.Marshal(txReq)
	if err != nil {
		result.Error = err
		return result
	}

	// 签名交易
	signer := &crypto.SuiTransactionSigner{}
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKey)

	if err != nil {
		result.Error = err
		return result
	}

	// 验证结果
	if signedTx != "" && txHash != "" {
		result.IsPassed = true
		result.Address = address
		result.PublicKey = publicKey
		result.PrivateKey = privateKey
		result.Signature = signedTx
		result.TxHash = txHash
	}

	return result
}

// 测试验证交易签名
func testVerifyTransaction() SuiTestResult {
	result := SuiTestResult{
		TestName: "验证交易签名",
		IsPassed: false,
	}

	// 生成密钥对
	generator := &crypto.SuiKeyGenerator{}
	address, publicKey, privateKey, err := generator.GenerateKeyPair()
	if err != nil {
		result.Error = err
		return result
	}

	// 构建交易请求
	txReq := crypto.SuiTransactionRequest{
		TransactionKind: "Transfer",
		GasBudget:       100000000,
		GasPrice:        1000,
		GasPayment:      []string{address},
		InputObjects:    []string{"0x0000000000000000000000000000000000000000000000000000000000000002"},
		Data:            json.RawMessage(`{"recipient":"0x0000000000000000000000000000000000000000000000000000000000000003","amount":1000}`),
	}

	rawTx, err := json.Marshal(txReq)
	if err != nil {
		result.Error = err
		return result
	}

	// 签名交易
	signer := &crypto.SuiTransactionSigner{}
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKey)
	if err != nil {
		result.Error = err
		return result
	}

	// 验证签名
	valid, err := signer.VerifyTransaction(string(rawTx), signedTx, publicKey)
	if err != nil {
		result.Error = err
		return result
	}

	// 验证结果
	if valid {
		result.IsPassed = true
		result.Address = address
		result.PublicKey = publicKey
		result.Signature = signedTx
		result.TxHash = txHash
	} else {
		result.Error = fmt.Errorf("签名验证失败")
	}

	return result
}

// 测试错误的私钥格式
func testInvalidPrivateKey() SuiTestResult {
	result := SuiTestResult{
		TestName: "错误私钥格式测试",
		IsPassed: false,
	}

	// 使用无效的私钥
	invalidPrivateKey := "invalid_private_key_format"

	// 尝试从无效私钥派生公钥和地址
	generator := &crypto.SuiKeyGenerator{}
	address, publicKey, err := generator.DeriveKeyPairFromPrivateKey(invalidPrivateKey)

	// 验证是否正确返回错误
	if err != nil && address == "" && publicKey == "" {
		result.IsPassed = true
		result.Error = err
	}

	return result
}