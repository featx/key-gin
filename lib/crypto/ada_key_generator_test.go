package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdaKeyGenerator_GenerateKeyPair(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 生成密钥对
	address, publicKey, privateKey, err := generator.GenerateKeyPair()

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, address)
	assert.NotEmpty(t, publicKey)
	assert.NotEmpty(t, privateKey)
	// 验证地址格式符合Cardano规范
	assert.Contains(t, address, "addr1")
	// 验证私钥长度
	assert.Equal(t, 64, len(privateKey)) // 32字节的十六进制表示
}

func TestAdaKeyGenerator_DeriveKeyPairFromPrivateKey(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 先生成一个有效的私钥用于测试
	_, _, privateKey, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 从私钥派生公钥和地址
	address, publicKey, err := generator.DeriveKeyPairFromPrivateKey(privateKey)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, address)
	assert.NotEmpty(t, publicKey)
	assert.Contains(t, address, "addr1")
}

func TestAdaKeyGenerator_InvalidPrivateKey(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 测试无效长度的私钥
	invalidPrivateKey := "00000000000000000000000000000000000000000000000000000001" // 31字节
	address, publicKey, err := generator.DeriveKeyPairFromPrivateKey(invalidPrivateKey)

	// 验证错误处理
	assert.Error(t, err)
	assert.Empty(t, address)
	assert.Empty(t, publicKey)
	assert.Contains(t, err.Error(), "invalid private key length")

	// 测试非十六进制格式的私钥
	nonHexPrivateKey := "not_a_hex_string"
	address, publicKey, err = generator.DeriveKeyPairFromPrivateKey(nonHexPrivateKey)

	// 验证错误处理
	assert.Error(t, err)
	assert.Empty(t, address)
	assert.Empty(t, publicKey)
}

func TestAdaKeyGenerator_PublicKeyToAddress(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 先生成一个有效的密钥对
	_, publicKey, _, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 从公钥生成地址
	address, err := generator.PublicKeyToAddress(publicKey)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, address)
	assert.Contains(t, address, "addr1")
}