package crypto

import (
	"crypto/ed25519"
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
	assert.Contains(t, address, "addr")
	// 验证私钥长度 - Ed25519私钥是64字节，十六进制表示为128字符
	assert.Equal(t, ed25519.PrivateKeySize*2, len(privateKey))
	// 验证公钥长度 - Ed25519公钥是32字节，十六进制表示为64字符
	assert.Equal(t, ed25519.PublicKeySize*2, len(publicKey))
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
	assert.Contains(t, address, "addr")
	// 验证公钥长度
	assert.Equal(t, ed25519.PublicKeySize*2, len(publicKey))
}

func TestAdaKeyGenerator_InvalidPrivateKey(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 测试无效长度的私钥
	invalidPrivateKey := "00000000000000000000000000000000000000000000000000000001"
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
	assert.Contains(t, address, "addr")
}

func TestAdaKeyGenerator_SeedToKeyPair(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 测试从32字节种子生成密钥对
	// 创建一个32字节的十六进制字符串作为种子
	seed := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	address, publicKey, err := generator.DeriveKeyPairFromPrivateKey(seed)

	// 验证结果
	assert.NoError(t, err)
	assert.NotEmpty(t, address)
	assert.NotEmpty(t, publicKey)
	assert.Contains(t, address, "addr")
}

func TestAdaKeyGenerator_GenerateKeyPairWithAddressType(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 测试生成基本地址类型的密钥对
	baseAddress, basePublicKey, basePrivateKey, err := generator.GenerateKeyPairWithAddressType(BaseAddress)
	assert.NoError(t, err)
	assert.NotEmpty(t, baseAddress)
	assert.NotEmpty(t, basePublicKey)
	assert.NotEmpty(t, basePrivateKey)
	assert.Contains(t, baseAddress, "addr")

	// 测试生成Enterprise地址类型的密钥对
	enterpriseAddress, enterprisePublicKey, enterprisePrivateKey, err := generator.GenerateKeyPairWithAddressType(EnterpriseAddress)
	assert.NoError(t, err)
	assert.NotEmpty(t, enterpriseAddress)
	assert.NotEmpty(t, enterprisePublicKey)
	assert.NotEmpty(t, enterprisePrivateKey)
	assert.Contains(t, enterpriseAddress, "addr")
}

func TestAdaKeyGenerator_GenerateKeyPairWithNetworkType(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 测试生成主网地址
	mainnetAddress, mainnetPublicKey, mainnetPrivateKey, err := generator.GenerateKeyPairWithOptions(BaseAddress, Mainnet)
	assert.NoError(t, err)
	assert.NotEmpty(t, mainnetAddress)
	assert.NotEmpty(t, mainnetPublicKey)
	assert.NotEmpty(t, mainnetPrivateKey)
	assert.Contains(t, mainnetAddress, "addr")
	assert.NotContains(t, mainnetAddress, "addr_test")

	// 测试生成测试网地址
	testnetAddress, testnetPublicKey, testnetPrivateKey, err := generator.GenerateKeyPairWithOptions(BaseAddress, Testnet)
	assert.NoError(t, err)
	assert.NotEmpty(t, testnetAddress)
	assert.NotEmpty(t, testnetPublicKey)
	assert.NotEmpty(t, testnetPrivateKey)
	assert.Contains(t, testnetAddress, "addr_test")
}

func TestAdaKeyGenerator_RandomNetworkID(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 生成多个地址并验证它们的网络ID部分是随机的
	addresses := make(map[string]bool)
	for i := 0; i < 10; i++ {
		address, _, _, err := generator.GenerateKeyPairWithOptions(BaseAddress, Mainnet)
		assert.NoError(t, err)
		addresses[address] = true
	}

	// 验证生成的地址都是不同的
	assert.GreaterOrEqual(t, len(addresses), 5, "生成的地址应该大部分是不同的，因为网络ID是随机的")
}

func TestAdaKeyGenerator_DeriveKeyPairWithOptions(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 先生成一个密钥对
	_, _, privateKey, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 使用不同的选项派生
	mainnetBaseAddress, mainnetBasePublicKey, err := generator.DeriveKeyPairFromPrivateKeyWithOptions(privateKey, BaseAddress, Mainnet)
	assert.NoError(t, err)
	assert.NotEmpty(t, mainnetBaseAddress)
	assert.NotEmpty(t, mainnetBasePublicKey)
	assert.Contains(t, mainnetBaseAddress, "addr")
	assert.NotContains(t, mainnetBaseAddress, "addr_test")

	testnetEnterpriseAddress, testnetEnterprisePublicKey, err := generator.DeriveKeyPairFromPrivateKeyWithOptions(privateKey, EnterpriseAddress, Testnet)
	assert.NoError(t, err)
	assert.NotEmpty(t, testnetEnterpriseAddress)
	assert.NotEmpty(t, testnetEnterprisePublicKey)
	assert.Contains(t, testnetEnterpriseAddress, "addr_test")
}

func TestAdaKeyGenerator_PublicKeyToAddressWithOptions(t *testing.T) {
	generator := &AdaKeyGenerator{}

	// 先生成一个公钥
	_, publicKey, _, err := generator.GenerateKeyPair()
	assert.NoError(t, err)

	// 使用不同的选项生成地址
	mainnetBaseAddress, err := generator.PublicKeyToAddressWithOptions(publicKey, BaseAddress, Mainnet)
	assert.NoError(t, err)
	assert.NotEmpty(t, mainnetBaseAddress)
	assert.Contains(t, mainnetBaseAddress, "addr")
	assert.NotContains(t, mainnetBaseAddress, "addr_test")

	testnetEnterpriseAddress, err := generator.PublicKeyToAddressWithOptions(publicKey, EnterpriseAddress, Testnet)
	assert.NoError(t, err)
	assert.NotEmpty(t, testnetEnterpriseAddress)
	assert.Contains(t, testnetEnterpriseAddress, "addr_test")
}