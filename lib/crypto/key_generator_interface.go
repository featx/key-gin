package crypto

// KeyGenerator 密钥生成器接口
// 用于生成各区块链的密钥对和地址
// 每种区块链可以有自己的实现

// KeyGenerator 密钥生成器接口
type KeyGenerator interface {
	// GenerateKeyPair 生成新的密钥对
	// 返回：地址、公钥、私钥、错误
	GenerateKeyPair() (address, publicKey, privateKey string, err error)

	// DeriveKeyPairFromPrivateKey 从现有私钥推导公钥和地址
	// 返回：地址、公钥、错误
	DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error)

	// PublicKeyToAddress 从公钥生成地址
	// 返回：地址、错误
	PublicKeyToAddress(publicKey string) (address string, err error)
}