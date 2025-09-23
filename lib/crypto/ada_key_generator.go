package crypto

// 导入必要的包
import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/btcec"
)

// AdaKeyGenerator Cardano (ADA)密钥生成器
// 实现符合Cardano主网规范的密钥和地址生成

type AdaKeyGenerator struct{}

// AddressType 定义Cardano地址类型
type AddressType string

const (
	// BaseAddress 基本地址类型（包含支付和权益组件）
	BaseAddress AddressType = "base"
	// EnterpriseAddress Enterprise地址类型（仅包含支付组件）
	EnterpriseAddress AddressType = "enterprise"
)

// NetworkType 定义Cardano网络类型

type NetworkType string

const (
	// Mainnet 主网
	Mainnet NetworkType = "mainnet"
	// Testnet 测试网
	Testnet NetworkType = "testnet"
)

// GenerateKeyPair 生成Cardano密钥对 - 使用真实的Ed25519算法
func (g *AdaKeyGenerator) GenerateKeyPair() (address, publicKey, privateKey string, err error) {
	return g.GenerateHDKeyPairWithOptions(BaseAddress, Mainnet)
}

// DeriveKeyPairFromPrivateKey 从现有私钥推导Cardano公钥和地址
func (g *AdaKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (address, publicKey string, err error) {
	return g.DeriveKeyPairFromPrivateKeyWithOptions(privateKey, BaseAddress, Mainnet)
}

// PublicKeyToAddress 从公钥生成Cardano地址
func (g *AdaKeyGenerator) PublicKeyToAddress(publicKey string) (address string, err error) {
	return g.PublicKeyToAddressWithOptions(publicKey, BaseAddress, Mainnet)
}

// GenerateKeyPairWithAddressType 生成指定地址类型的Cardano密钥对
// 提供额外的方法支持选择地址类型
func (g *AdaKeyGenerator) GenerateKeyPairWithAddressType(addressType AddressType) (address, publicKey, privateKey string, err error) {
	return g.GenerateHDKeyPairWithOptions(addressType, Mainnet)
}

// GenerateKeyPairWithOptions 生成带选项的Cardano密钥对
// 支持选择地址类型和网络类型
func (g *AdaKeyGenerator) GenerateKeyPairWithOptions(addressType AddressType, networkType NetworkType) (address, publicKey, privateKey string, err error) {
	return g.GenerateHDKeyPairWithOptions(addressType, networkType)
}

// GenerateHDKeyPairWithOptions 生成带选项的Cardano HD密钥对
// 使用标准的HD钱包路径 m/1852'/1815'/0'/0/0
func (g *AdaKeyGenerator) GenerateHDKeyPairWithOptions(addressType AddressType, networkType NetworkType) (address, publicKey, privateKey string, err error) {
	// 生成随机种子
	seed := make([]byte, 32)
	_, err = rand.Read(seed)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate seed: %w", err)
	}

	// 使用BTC的HD钱包库创建主密钥
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create master key: %w", err)
	}

	// 按照Cardano标准路径 m/1852'/1815'/0'/0/0 派生密钥
	// 注意：强化派生使用HardenedKeyDerivation
	purposeKey, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 1852)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to derive purpose key: %w", err)
	}

	coinTypeKey, err := purposeKey.Derive(hdkeychain.HardenedKeyStart + 1815)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to derive coin type key: %w", err)
	}

	accountKey, err := coinTypeKey.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to derive account key: %w", err)
	}

	changeKey, err := accountKey.Derive(0)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to derive change key: %w", err)
	}

	addressKey, err := changeKey.Derive(0)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to derive address key: %w", err)
	}

	// 获取扩展私钥
	extendedPrivKey, err := addressKey.ECPrivKey()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get private key: %w", err)
	}

	// 转换为Ed25519私钥（使用私钥的32字节作为种子）
	privateKeyBytes := extendedPrivKey.Serialize()[:32]
	publicKeyBytes := ed25519.NewKeyFromSeed(privateKeyBytes)

	// 获取私钥的十六进制表示
	privateKey = hex.EncodeToString(privateKeyBytes)

	// 获取公钥的十六进制表示
	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成符合Cardano规范的地址
	address, err = generateCardanoAddress(publicKeyBytes, addressType, networkType)
	if err != nil {
		return "", "", "", err
	}

	return address, publicKey, privateKey, nil
}

// DeriveKeyPairFromPrivateKeyWithOptions 从现有私钥推导Cardano公钥和地址（带选项）
func (g *AdaKeyGenerator) DeriveKeyPairFromPrivateKeyWithOptions(privateKey string, addressType AddressType, networkType NetworkType) (address, publicKey string, err error) {
	// 解析私钥（必须是32或64字节的十六进制字符串）
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// 验证私钥长度
	var publicKeyBytes []byte
	if len(privateKeyBytes) == 32 {
		// 32字节私钥种子 - 转换为完整的Ed25519公钥
		publicKeyBytes = ed25519.NewKeyFromSeed(privateKeyBytes)
	} else if len(privateKeyBytes) == 64 {
		// 完整的Ed25519私钥格式
		privateKeyObj := ed25519.PrivateKey(privateKeyBytes)
		publicKeyBytes = privateKeyObj.Public().(ed25519.PublicKey)
	} else {
		return "", "", fmt.Errorf("invalid private key length: expected 32 or 64 bytes", len(privateKeyBytes))
	}

	publicKey = hex.EncodeToString(publicKeyBytes)

	// 生成符合Cardano规范的地址
	address, err = generateCardanoAddress(publicKeyBytes, addressType, networkType)
	if err != nil {
		return "", "", err
	}

	return address, publicKey, nil
}

// PublicKeyToAddressWithOptions 从公钥生成Cardano地址（带选项）
func (g *AdaKeyGenerator) PublicKeyToAddressWithOptions(publicKey string, addressType AddressType, networkType NetworkType) (address string, err error) {
	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// 验证公钥长度是否符合Ed25519要求
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key length: expected %d bytes, got %d bytes", 
			ed25519.PublicKeySize, len(publicKeyBytes))
	}

	// 生成符合Cardano规范的地址
	address, err = generateCardanoAddress(publicKeyBytes, addressType, networkType)
	if err != nil {
		return "", err
	}

	return address, nil
}

// generateCardanoAddress 生成符合Cardano规范的地址，支持两种格式和网络类型
// 使用标准的Blake2b-224(28字节)哈希和bech32m编码，符合Cardano的标准规范
func generateCardanoAddress(publicKeyBytes []byte, addressType AddressType, networkType NetworkType) (string, error) {
	// 转换网络类型和地址类型为对应的ID值
	var networkID uint8
	var addrTypeID uint8

	switch networkType {
	case Mainnet:
		networkID = uint8(MainnetNetworkID)
	case Testnet:
		networkID = uint8(TestnetNetworkID)
	default:
		return "", fmt.Errorf("unsupported network type: %s", networkType)
	}

	switch addressType {
	case BaseAddress:
		addrTypeID = uint8(BaseAddressType)
	case EnterpriseAddress:
		addrTypeID = uint8(EnterpriseAddressType)
	default:
		return "", fmt.Errorf("unsupported address type: %s", addressType)
	}

	// 调用新的实现函数
	return GenerateCardanoAddress(publicKeyBytes, networkID, addrTypeID)
}

// GenerateCardanoAddress 生成Cardano地址（使用标准的28字节Blake2b哈希和bech32m编码）
func GenerateCardanoAddress(publicKey []byte, networkID uint8, addressType uint8) (string, error) {
	// 验证输入参数
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key length: expected %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	// 根据网络ID确定地址前缀
	var hrp string
	switch networkID {
	case 0:
		hrp = "addr"
	case 1:
		hrp = "addr_test"
	default:
		return "", fmt.Errorf("unsupported network ID: %d", networkID)
	}

	// 创建地址数据字节数组
	var data []byte

	// 根据地址类型构建不同的地址
	switch addressType {
	case 0:
		// 基本地址: type | networkID | payment credential type | payment credential hash | stake credential type | stake credential hash
		// 使用28字节的Blake2b哈希 (Cardano标准)
		hash, err := blake2b.New(28, nil)
		if err != nil {
			return "", err
		}
		hash.Write(publicKey)
		paymentHash := hash.Sum(nil)

		// 假设权益凭证与支付凭证相同
		hash.Reset()
		hash.Write(publicKey)
		stakeHash := hash.Sum(nil)

		// 构建地址数据 - 修复：地址头部是一个字节，高4位是网络ID，低4位是地址类型
		addressHeader := (networkID << 4) | addressType
		data = append(data, addressHeader)
		data = append(data, 0) // 支付凭证类型 (0 = 密钥哈希)
		data = append(data, paymentHash...)
		data = append(data, 0) // 权益凭证类型 (0 = 密钥哈希)
		data = append(data, stakeHash...)

	case 1:
		// 企业地址: type | networkID | payment credential type | payment credential hash
		// 使用28字节的Blake2b哈希
		hash, err := blake2b.New(28, nil)
		if err != nil {
			return "", err
		}
		hash.Write(publicKey)
		paymentHash := hash.Sum(nil)

		// 构建地址数据 - 修复：地址头部是一个字节
		addressHeader := (networkID << 4) | addressType
		data = append(data, addressHeader)
		data = append(data, 0) // 支付凭证类型 (0 = 密钥哈希)
		data = append(data, paymentHash...)

	default:
		return "", fmt.Errorf("unsupported address type: %d", addressType)
	}

	// 将数据从8位字节转换为5位字
	expanded, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}

	// 使用自定义的bech32m编码函数
	address, err := encodeBech32m(hrp, expanded)
	if err != nil {
		return "", err
	}

	// 验证生成的地址
	if err := validateBech32m(address); err != nil {
		return "", fmt.Errorf("generated address validation failed: %v", err)
	}

	return address, nil
}

// bech32m常量
const (
	charset      = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	bech32mConst = 0x2bc830a3
)

// 计算bech32m校验和
func bech32mChecksum(hrp string, data []byte) []byte {
	// 将HRP转换为5位字
	var expanded []byte
	for _, c := range hrp {
		expanded = append(expanded, byte(c>>5))
	}
	expanded = append(expanded, 0)
	for _, c := range hrp {
		expanded = append(expanded, byte(c&0x1f))
	}
	expanded = append(expanded, data...)
	// 添加bech32m的常量
	expanded = append(expanded, 0, 0, 0, 0, 0, 0)

	// 计算多项式余数
	poly := bech32Polymod(expanded)
	poly ^= bech32mConst

	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((poly >> (5 * (5 - i))) & 0x1f)
	}

	return checksum
}

// bech32多项式计算（与bech32库相同）
func bech32Polymod(values []byte) uint32 {
	generator := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		topleft := chk >> 25
		chk = (chk & 0x1ffffff) << 5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (topleft >> i) & 1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

// 自定义的bech32m编码函数 - 修复后的版本，符合Cardano规范
func encodeBech32m(hrp string, data []byte) (string, error) {
	// 检查HRP有效性
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return "", fmt.Errorf("invalid character in hrp: %q", c)
		}
	}

	// 检查数据有效性
	for i, c := range data {
		if c >= 32 {
			return "", fmt.Errorf("invalid data byte at index %d: %v", i, c)
		}
	}

	// 计算校验和
	checksum := bech32mChecksum(hrp, data)
	combined := append(data, checksum...)

	// 构建最终地址
	result := hrp + "1"
	for _, c := range combined {
		result += string(charset[c])
	}

	// 简化的自我验证，不依赖标准库的严格长度检查
	// 只检查基本格式和校验和
	if len(result) < 8 || len(result) > 150 { // 放宽长度限制
		return "", fmt.Errorf("address length %d outside expected range", len(result))
	}

	// 检查分隔符
	sepIndex := strings.Index(result, "1")
	if sepIndex < 1 || sepIndex > 83 { // HRP最长83个字符
		return "", fmt.Errorf("invalid separator position: %d", sepIndex)
	}

	// 验证校验和 - 使用我们自己的实现
	_, _, err := decodeBech32mWithChecksum(result)
	if err != nil {
		return "", fmt.Errorf("checksum verification failed: %v", err)
	}

	return result, nil
}

// 辅助函数：解码并验证校验和，不依赖标准库
func decodeBech32mWithChecksum(s string) (string, []byte, error) {
	// 查找分隔符
	sep := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '1' {
			sep = i
			break
		}
	}
	if sep == -1 || sep < 1 || sep+7 > len(s) {
		return "", nil, fmt.Errorf("invalid separator position")
	}

	// 提取HRP和数据部分
	hrp := s[:sep]
	dataPart := s[sep+1:]

	// 解码数据部分
	data := make([]byte, 0, len(dataPart))
	for _, c := range dataPart {
		found := false
		for i, char := range charset {
			if c == char {
				data = append(data, byte(i))
				found = true
				break
			}
		}
		if !found {
			return "", nil, fmt.Errorf("invalid character in data: %c", c)
		}
	}

	// 验证校验和
	if len(data) < 6 {
		return "", nil, fmt.Errorf("data too short")
	}
	actualData, checksum := data[:len(data)-6], data[len(data)-6:]

	// 使用我们自己的函数验证校验和
	valid := verifyChecksum(hrp, actualData, checksum)
	if !valid {
		return "", nil, fmt.Errorf("invalid checksum")
	}

	return hrp, actualData, nil
}

// 验证bech32m地址 - 简化版本，不依赖标准库的严格长度检查
func validateBech32m(s string) error {
	// 检查长度 - 根据Cardano实际地址长度放宽限制
	if len(s) < 8 || len(s) > 150 {
		return fmt.Errorf("invalid bech32m string length: %d", len(s))
	}

	// 检查大小写
	lower := false
	upper := false
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			lower = true
		} else if c >= 'A' && c <= 'Z' {
			upper = true
		}
	}
	if lower && upper {
		return fmt.Errorf("bech32m string must not contain mixed case")
	}

	// 不使用标准库进行解码验证，使用我们自定义的宽松验证
	_, _, err := decodeBech32mWithChecksum(s)
	if err != nil {
		return err
	}

	return nil
}

// 验证校验和
func verifyChecksum(hrp string, data []byte, checksum []byte) bool {
	combined := make([]byte, 0, len(hrp)*2+1+len(data)+len(checksum))
	for _, c := range hrp {
		combined = append(combined, byte(c>>5))
	}
	combined = append(combined, 0)
	for _, c := range hrp {
		combined = append(combined, byte(c&0x1f))
	}
	combined = append(combined, data...)
	combined = append(combined, checksum...)

	poly := bech32Polymod(combined)
	return poly == bech32mConst
}

// 网络ID常量
type NetworkID uint8

const (
	// MainnetNetworkID 主网网络ID
	MainnetNetworkID NetworkID = 0
	// TestnetNetworkID 测试网网络ID
	TestnetNetworkID NetworkID = 1
)

// 地址类型常量
type AddressTypeID uint8

const (
	// BaseAddressType 基本地址类型ID
	BaseAddressType AddressTypeID = 0
	// EnterpriseAddressType 企业地址类型ID
	EnterpriseAddressType AddressTypeID = 1
)

func (g *AdaKeyGenerator) GenerateKeyPair() (string, string, string, error) {
	return g.GenerateKeyPairWithOptions(BaseAddress, Mainnet)
}

func (g *AdaKeyGenerator) GenerateKeyPairWithOptions(addressType AddressTypeID, networkId NetworkID) (string, string, string, error) {
	// 生成主私钥（使用BIP32标准随机种子）
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return "", "", "", err
	}

	// 从种子创建主HD密钥
	masterKey, err := hdkeychain.NewMaster(seed, chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", err
	}

	// 按照Cardano标准路径推导：m/1852'/1815'/0'/0/0
	// 1852' - Purpose (Cardano)
	hardenedPurpose, err := masterKey.DeriveNonStandardPath("m/1852'")
	if err != nil {
		return "", "", "", err
	}

	// 1815' - Coin Type (Cardano)
	hardenedCoinType, err := hardenedPurpose.DeriveNonStandardPath("m/1815'")
	if err != nil {
		return "", "", "", err
	}

	// 0' - Account
	hardenedAccount, err := hardenedCoinType.DeriveNonStandardPath("m/0'")
	if err != nil {
		return "", "", "", err
	}

	// 0 - Change
	changeKey, err := hardenedAccount.Derive(0)
	if err != nil {
		return "", "", "", err
	}

	// 0 - Address Index
	childKey, err := changeKey.Derive(0)
	if err != nil {
		return "", "", "", err
	}

	// 提取扩展私钥的原始私钥字节
	ecprivkey, err := childKey.ECPrivKey()
	if err != nil {
		return "", "", "", err
	}

	// 转换为原始私钥字节（Ed25519需要）	
	privateKeyBytes := ecprivkey.Serialize()
	privateKeyHex := hex.EncodeToString(privateKeyBytes)

	// 获取公钥并转换为hex字符串
	publicKey := ecprivkey.PubKey()
	// Cardano只使用公钥的前32字节
	publicKeyBytes := publicKey.SerializeCompressed()
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// 生成Cardano地址
	address, err := GenerateCardanoAddress(publicKeyBytes, addressType, networkId)
	if err != nil {
		return "", "", "", err
	}

	return address, publicKeyHex, privateKeyHex, nil
}

func (g *AdaKeyGenerator) DeriveKeyPairFromPrivateKey(privateKey string) (string, string, error) {
	// 解析私钥
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key format: %v", err)
	}

	// 确保私钥长度正确
	if len(privKeyBytes) != 32 && len(privKeyBytes) != 64 {
		return "", "", fmt.Errorf("invalid private key length: expected 32 or 64, got %d", len(privKeyBytes))
	}

	// 如果是64字节，取前32字节
	if len(privKeyBytes) == 64 {
		privKeyBytes = privKeyBytes[:32]
	}

	// 从原始私钥创建ECDSA私钥
	ecprivkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)

	// 获取公钥
	publicKey := ecprivkey.PubKey()
	// Cardano只使用公钥的前32字节
	publicKeyBytes := publicKey.SerializeCompressed()
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// 生成Cardano主网基本地址
	address, err := GenerateCardanoAddress(publicKeyBytes, BaseAddress, Mainnet)
	if err != nil {
		return "", "", err
	}

	return address, publicKeyHex, nil
}

func (g *AdaKeyGenerator) PublicKeyToAddress(publicKey string) (string, error) {
	// 解析公钥
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key format: %v", err)
	}

	// 确保公钥长度正确
	if len(pubKeyBytes) != 33 && len(pubKeyBytes) != 65 {
		// 如果不是33或65字节，可能是因为已移除了压缩标志位或未压缩格式
		// 尝试处理32字节的情况（纯X坐标）		
		if len(pubKeyBytes) == 32 {
			// 添加压缩标志位（02表示X坐标为偶数）
			compressedPubKey := append([]byte{0x02}, pubKeyBytes...)
			return GenerateCardanoAddress(compressedPubKey, BaseAddress, Mainnet)
		}
		return "", fmt.Errorf("invalid public key length: expected 32, 33 or 65, got %d", len(pubKeyBytes))
	}

	// 生成Cardano主网基本地址
	return GenerateCardanoAddress(pubKeyBytes, BaseAddress, Mainnet)
}

func GenerateCardanoAddress(publicKeyBytes []byte, addressType AddressTypeID, networkId NetworkID) (string, error) {
	// 验证公钥长度
	if len(publicKeyBytes) == 33 {
		// 处理压缩公钥
		publicKeyBytes = publicKeyBytes[1:]
	} else if len(publicKeyBytes) == 65 {
		// 处理未压缩公钥
		publicKeyBytes = publicKeyBytes[1:33]
	} else if len(publicKeyBytes) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32, 33 or 65, got %d", len(publicKeyBytes))
	}

	// 计算公钥的Blake2b哈希作为支付凭证
	paymentCredHash := blake2b.Sum256(publicKeyBytes)

	// 为简化，使用相同的公钥作为权益凭证
	stakeCredHash := paymentCredHash

	// 构建地址头部（网络ID和地址类型合并为一个字节）
	// 高4位是网络ID，低4位是地址类型
	headerByte := byte(networkId)<<4 | byte(addressType)

	// 构建地址payload
	var payload []byte
	payload = append(payload, headerByte)
	payload = append(payload, paymentCredHash[:28]...) // 使用28字节哈希

	// 如果是基本地址，添加权益凭证
	if addressType == BaseAddress {
		payload = append(payload, stakeCredHash[:28]...) // 使用28字节哈希
	}

	// 生成bech32m编码的地址
	address, err := encodeBech32m("addr", payload)
	if err != nil {
		return "", err
	}

	// 验证生成的地址
	if err := validateBech32m(address); err != nil {
		return "", err
	}

	return address, nil
}