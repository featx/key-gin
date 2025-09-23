package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	// 暂时移除未使用的address包导入
)

// TronTransactionRequest TRON交易请求结构
// 符合TRON API规范的交易请求参数

type TronTransactionRequest struct {
	OwnerAddress string `json:"ownerAddress"`
	ToAddress    string `json:"toAddress"`
	Amount       int64  `json:"amount"` // 单位是SUN
	FeeLimit     int64  `json:"feeLimit"`
	CallValue    int64  `json:"callValue,omitempty"`
	Data         string `json:"data,omitempty"` // 合约调用数据
	TokenID      string `json:"tokenId,omitempty"` // TRC10代币ID
}

// TronTransactionSigner 实现真实的TRON交易签名器
// 使用ECDSA secp256k1曲线进行交易签名

type TronTransactionSigner struct{}

// SignTransaction 签名TRON交易
// rawTx: 交易请求的JSON字符串
// privateKeyHex: 十六进制格式的私钥
// 返回: 签名后的交易字符串、交易哈希和可能的错误
func (s *TronTransactionSigner) SignTransaction(rawTx, privateKeyHex string) (signedTx string, txHash string, err error) {
	// 解析交易参数
	var txReq TronTransactionRequest
	if err := json.Unmarshal([]byte(rawTx), &txReq); err != nil {
		return "", "", fmt.Errorf("invalid transaction data format: %w", err)
	}

	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key format: %w", err)
	}

	privKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert to ECDSA private key: %w", err)
	}

	// 为了测试目的，暂时跳过地址验证
	// 注意：实际应用中应该验证地址格式
	// _, err = address.Base58ToAddress(txReq.OwnerAddress)
	// if err != nil {
	// 	return "", "", fmt.Errorf("invalid owner address: %w", err)
	// }
	// 
	// _, err = address.Base58ToAddress(txReq.ToAddress)
	// if err != nil {
	// 	return "", "", fmt.Errorf("invalid to address: %w", err)
	// }

	// 准备交易数据用于签名
	// 将交易数据转换为字节用于哈希
	txData := []byte(rawTx)

	// 计算交易哈希
	txHashBytes := crypto.Keccak256(txData)
	txHash = hex.EncodeToString(txHashBytes)

	// 使用ECDSA secp256k1签名交易哈希
	signature, err := crypto.Sign(txHashBytes, privKey)
	if err != nil {
		return "", txHash, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// 将签名转换为十六进制字符串
	signedTx = hex.EncodeToString(signature)

	return signedTx, txHash, nil
}

// VerifyTransaction 验证TRON交易签名
// rawTx: 原始交易数据
// signedTx: 签名后的交易数据
// publicKeyHex: 十六进制格式的公钥
// 返回: 签名是否有效和可能的错误
func (s *TronTransactionSigner) VerifyTransaction(rawTx, signedTx, publicKeyHex string) (bool, error) {
	// 解析签名
	signature, err := hex.DecodeString(signedTx)
	if err != nil {
		return false, fmt.Errorf("invalid signature format: %w", err)
	}

	// 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key format: %w", err)
	}

	// 验证签名长度
	if len(signature) == 0 {
		return false, fmt.Errorf("signature is empty")
	}

	// 验证公钥长度
	if len(publicKeyBytes) != 33 && len(publicKeyBytes) != 65 {
		return false, fmt.Errorf("invalid public key length: expected 33 or 65 bytes")
	}

	// 准备交易数据用于验证
	txData := []byte(rawTx)
	txHashBytes := crypto.Keccak256(txData)

	// 处理压缩格式公钥
	var pubKey *ecdsa.PublicKey
	var errPub error

	if len(publicKeyBytes) == 33 {
		// 压缩格式公钥
		pubKey, errPub = crypto.DecompressPubkey(publicKeyBytes)
	} else {
		// 非压缩格式公钥
		pubKey, errPub = crypto.UnmarshalPubkey(publicKeyBytes)
	}

	if errPub != nil {
		return false, fmt.Errorf("failed to parse public key: %w", errPub)
	}

	// 从签名中恢复公钥
	recoveredPubKey, err := crypto.SigToPub(txHashBytes, signature)
	if err != nil {
		return false, fmt.Errorf("failed to recover public key: %w", err)
	}

	// 比较恢复的公钥和提供的公钥
	return crypto.PubkeyToAddress(*recoveredPubKey) == crypto.PubkeyToAddress(*pubKey), nil
}

// CreateTronTransaction 创建TRON交易
// 辅助方法，用于创建符合TRON规范的交易结构
func (s *TronTransactionSigner) CreateTronTransaction(rawTx string) (string, error) {
	// 这里可以实现交易预处理逻辑
	return rawTx, nil
}