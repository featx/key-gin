package crypto

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEthTransactionSigner_SignTransaction(t *testing.T) {
	signer := &EthTransactionSigner{}

	// 测试用的私钥和交易数据
	privateKeyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

	// 创建TextBigInt类型的变量
	gas := TextBigInt(*big.NewInt(21000))
	gasPrice := TextBigInt(*big.NewInt(1000000000))
	valueInt, _ := new(big.Int).SetString("1000000000000000000", 10)
	value := TextBigInt(*valueInt)
	nonce := TextBigInt(*big.NewInt(0))
	chainID := TextBigInt(*big.NewInt(1))

	// 构建以太坊交易请求
	txReq := EthTransactionRequest{
		From:     "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Gas:      &gas,
		GasPrice: &gasPrice,
		Value:    &value,
		Nonce:    &nonce,
		ChainID:  &chainID,
	}

	rawTx, err := json.Marshal(txReq)
	assert.NoError(t, err)

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKeyHex)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, signedTx, "0x")
	assert.Contains(t, txHash, "0x")
}

func TestEthTransactionSigner_InvalidPrivateKey(t *testing.T) {
	signer := &EthTransactionSigner{}

	// 无效的私钥
	privateKeyHex := "invalid_private_key"
	rawTx := `{"from":"0x...","to":"0x...","gas":21000,"gasPrice":1000000000,"value":"1000000000000000000","nonce":0,"chainId":"1"}`

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(rawTx, privateKeyHex)

	// 验证错误
	assert.Error(t, err)
	assert.Empty(t, signedTx)
	assert.Empty(t, txHash)
}

func TestEthTransactionSigner_InvalidTxFormat(t *testing.T) {
	signer := &EthTransactionSigner{}

	privateKeyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	// 无效的交易格式
	rawTx := "invalid_transaction_format"

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(rawTx, privateKeyHex)

	// 验证错误
	assert.Error(t, err)
	assert.Empty(t, signedTx)
	assert.Empty(t, txHash)
}

func TestEthTransactionSigner_SignEIP1559Transaction(t *testing.T) {
	signer := &EthTransactionSigner{}

	// 测试用的私钥
	privateKeyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

	// 创建TextBigInt类型的变量
	gas := TextBigInt(*big.NewInt(21000))
	maxPriorityFeePerGas := TextBigInt(*big.NewInt(1000000000))
	maxFeePerGas := TextBigInt(*big.NewInt(2000000000))
	valueInt, _ := new(big.Int).SetString("1000000000000000000", 10)
	value := TextBigInt(*valueInt)
	nonce := TextBigInt(*big.NewInt(0))
	chainID := TextBigInt(*big.NewInt(1))

	// 构建EIP-1559交易请求
	txReq := EthTransactionRequest{
		From:               "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:                 "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Gas:                &gas,
		MaxPriorityFeePerGas: &maxPriorityFeePerGas,
		MaxFeePerGas:       &maxFeePerGas,
		Value:              &value,
		Nonce:              &nonce,
		ChainID:            &chainID,
	}

	rawTx, err := json.Marshal(txReq)
	assert.NoError(t, err)

	// 执行签名
	signedTx, txHash, err := signer.SignTransaction(string(rawTx), privateKeyHex)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, signedTx)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, signedTx, "0x")
	assert.Contains(t, txHash, "0x")
}