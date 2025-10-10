package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// AptosTransactionSigner 测试用例
// 验证Aptos交易签名器的各项功能是否正常工作
func TestAptosTransactionSigner_SignTransaction(t *testing.T) {
	signer := &AptosTransactionSigner{}
	generator := &AptosKeyGenerator{}

	// 生成测试用的密钥对
	address, _, privateKey, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 创建测试交易请求
	txReq := AptosTransactionRequest{
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
	assert.NoError(t, err)
	rawTx := string(txBytes)

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(rawTx, privateKey)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, signedTx, "aptos_signed_")
	assert.Contains(t, txHash, "aptos_")
}

func TestAptosTransactionSigner_VerifyTransaction(t *testing.T) {
	signer := &AptosTransactionSigner{}
	generator := &AptosKeyGenerator{}

	// 生成测试用的密钥对
	address, publicKey, privateKey, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 创建测试交易请求
	txReq := AptosTransactionRequest{
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
	assert.NoError(t, err)
	rawTx := string(txBytes)

	// 执行签名
	signedTx, _, err := signer.SignTransaction(rawTx, privateKey)
	assert.NoError(t, err)

	// 提取签名部分（移除前缀）
	signature := signedTx[len("aptos_signed_"):]

	// 验证签名
	isValid, err := signer.VerifyTransaction(rawTx, signature, publicKey)

	// 验证结果
	assert.NoError(t, err)
	assert.True(t, isValid)
}

func TestAptosTransactionSigner_InvalidPrivateKey(t *testing.T) {
	signer := &AptosTransactionSigner{}

	// 无效的私钥
	privateKeyHex := "invalid_private_key"
	rawTx := `{"type":"entry_function_payload","sender":"0x7c87f561388444f786d522f8bdf08073e578c7a5632a79a446f6f5240df743b9","sequence_number":1,"max_gas_amount":100000,"gas_unit_price":100,"expiration_timestamp_secs":1234567890,"payload":{"function":"0x1::coin::transfer","type_arguments":["0x1::aptos_coin::AptosCoin"],"arguments":["0x7c87f561388444f786d522f8bdf08073e578c7a5632a79a446f6f5240df743b9","1000000"]}}`

	// 执行签名
	_, _, err := signer.SignTransaction(rawTx, privateKeyHex)

	// 验证错误
	assert.Error(t, err)
}

func TestAptosTransactionSigner_InvalidTransactionFormat(t *testing.T) {
	signer := &AptosTransactionSigner{}
	generator := &AptosKeyGenerator{}

	// 生成测试用的密钥对
	_, _, privateKey, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 无效格式的交易数据（非JSON）
	invalidRawTx := "not a valid json transaction"

	// 执行签名
	_, _, err = signer.SignTransaction(invalidRawTx, privateKey)

	// 验证错误
	assert.Error(t, err)
}

func TestAptosTransactionSigner_InvalidSignature(t *testing.T) {
	signer := &AptosTransactionSigner{}
	generator := &AptosKeyGenerator{}

	// 生成测试用的密钥对
	_, publicKey, _, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 有效的交易数据
	rawTx := `{"type":"entry_function_payload","sender":"0x7c87f561388444f786d522f8bdf08073e578c7a5632a79a446f6f5240df743b9","sequence_number":1,"max_gas_amount":100000,"gas_unit_price":100,"expiration_timestamp_secs":1234567890,"payload":{"function":"0x1::coin::transfer","type_arguments":["0x1::aptos_coin::AptosCoin"],"arguments":["0x7c87f561388444f786d522f8bdf08073e578c7a5632a79a446f6f5240df743b9","1000000"]}}`

	// 无效的签名
	invalidSignature := "invalid_signature_data"

	// 验证签名
	isValid, err := signer.VerifyTransaction(rawTx, invalidSignature, publicKey)

	// 验证错误
	assert.Error(t, err)
	assert.False(t, isValid)
}

func TestAptosTransactionSigner_MismatchedPublicKey(t *testing.T) {
	signer := &AptosTransactionSigner{}
	generator1 := &AptosKeyGenerator{}
	generator2 := &AptosKeyGenerator{}

	// 生成两对不同的密钥对
	_, _, privateKey1, err := generator1.GenerateKeyPair()
	assert.NoError(t, err)

	_, publicKey2, _, err := generator2.GenerateKeyPair()
	assert.NoError(t, err)

	// 创建测试交易请求
	txReq := AptosTransactionRequest{
		Type:                 "entry_function_payload",
		Sender:               "0x7c87f561388444f786d522f8bdf08073e578c7a5632a79a446f6f5240df743b9",
		SequenceNumber:       1,
		MaxGasAmount:         100000,
		GasUnitPrice:         100,
		ExpirationTimestamp:  1234567890,
		Payload:              json.RawMessage(`{"function":"0x1::coin::transfer","type_arguments":["0x1::aptos_coin::AptosCoin"],"arguments":["0x7c87f561388444f786d522f8bdf08073e578c7a5632a79a446f6f5240df743b9","1000000"]}`),
	}

	// 序列化交易请求
	txBytes, err := json.Marshal(txReq)
	assert.NoError(t, err)
	rawTx := string(txBytes)

	// 使用第一个私钥签名
	signedTx, _, err := signer.SignTransaction(rawTx, privateKey1)
	assert.NoError(t, err)

	// 提取签名部分
	signature := signedTx[len("aptos_signed_"):]

	// 尝试用第二个公钥验证
	isValid, err := signer.VerifyTransaction(rawTx, signature, publicKey2)

	// 验证结果 - 签名应该无效
	assert.NoError(t, err)
	assert.False(t, isValid)
}