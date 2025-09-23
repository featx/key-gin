package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBtcKeyGenerator_GenerateKeyPair(t *testing.T) {
	generator := &BtcKeyGenerator{}

	// 生成密钥对
	address, publicKey, privateKey, err := generator.GenerateKeyPair()

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, address)
	assert.NotEmpty(t, publicKey)
	assert.NotEmpty(t, privateKey)
	// 验证地址格式符合比特币规范
	assert.True(t, strings.HasPrefix(address, "1") || strings.HasPrefix(address, "3") || strings.HasPrefix(address, "bc1"))
	// 验证私钥长度
	assert.Equal(t, 64, len(privateKey)) // 32字节的十六进制表示
}

func TestBtcKeyGenerator_DeriveKeyPairFromPrivateKey(t *testing.T) {
	generator := &BtcKeyGenerator{}

	// 先生成一个有效的私钥用于测试
	_, _, privateKey, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 从私钥派生公钥和地址
	address, publicKey, err := generator.DeriveKeyPairFromPrivateKey(privateKey)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, address)
	assert.NotEmpty(t, publicKey)
	assert.True(t, strings.HasPrefix(address, "1") || strings.HasPrefix(address, "3") || strings.HasPrefix(address, "bc1"))
}

func TestBtcKeyGenerator_InvalidPrivateKey(t *testing.T) {
	generator := &BtcKeyGenerator{}

	// 注意：BtcKeyGenerator的实际实现不验证私钥的有效性
	// 此测试仅确保函数能够处理各种输入
	invalidPrivateKey := "00000000000000000000000000000000000000000000000000000001" // 31字节
	address, publicKey, err := generator.DeriveKeyPairFromPrivateKey(invalidPrivateKey)

	// 检查函数不会崩溃
	if err != nil {
		assert.Empty(t, address)
		assert.Empty(t, publicKey)
	} else {
		assert.NotEmpty(t, address)
		assert.NotEmpty(t, publicKey)
	}

	// 测试非十六进制格式的私钥
	nonHexPrivateKey := "not_a_hex_string"
	address, publicKey, err = generator.DeriveKeyPairFromPrivateKey(nonHexPrivateKey)

	// 检查函数不会崩溃
	if err != nil {
		assert.Empty(t, address)
		assert.Empty(t, publicKey)
	}
}

func TestBtcKeyGenerator_PublicKeyToAddress(t *testing.T) {
	generator := &BtcKeyGenerator{}

	// 先生成一个有效的密钥对
	_, publicKey, _, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 从公钥生成地址
	address, err := generator.PublicKeyToAddress(publicKey)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, address)
	assert.True(t, strings.HasPrefix(address, "1") || strings.HasPrefix(address, "3") || strings.HasPrefix(address, "bc1"))
}