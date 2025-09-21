package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/ethereum/go-ethereum/crypto"
)

// BtcTransactionRequest 比特币交易请求结构
type BtcTransactionRequest struct {
	Inputs  []BtcTxInput  `json:"inputs"`
	Outputs []BtcTxOutput `json:"outputs"`
}

// BtcTxInput 比特币交易输入
type BtcTxInput struct {
	TxID         string `json:"txid"`
	Vout         uint32 `json:"vout"`
	ScriptPubKey string `json:"scriptPubKey"`
	Amount       int64  `json:"amount"`
}

// BtcTxOutput 比特币交易输出
type BtcTxOutput struct {
	Address      string `json:"address"`
	Amount       int64  `json:"amount"` // 单位是satoshi
	ScriptPubKey string `json:"scriptPubKey,omitempty"`
}

// BtcTransactionSigner 比特币交易签名器
type BtcTransactionSigner struct{}

// SignTransaction 签名比特币交易
func (s *BtcTransactionSigner) SignTransaction(rawTx, privateKeyHex string) (signedTx string, txHash string, err error) {
	// 解码私钥
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key format: %w", err)
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	// 解析交易参数
	var txReq BtcTransactionRequest
	if err := json.Unmarshal([]byte(rawTx), &txReq); err != nil {
		return "", "", fmt.Errorf("invalid transaction data format: %w", err)
	}

	// 这里模拟比特币交易签名过程
	// 实际的比特币交易签名需要使用btcd库进行更复杂的处理
	// 包括构建交易、计算签名哈希、应用签名等步骤

	// 使用privateKey变量
	_ = privateKey

	// 生成示例签名
	signatureBytes := crypto.Keccak256(append(privateKeyBytes, []byte(rawTx)...))
	// 模拟序列化后的签名交易
	signedTx = fmt.Sprintf("btc_signed_%s", hex.EncodeToString(signatureBytes))

	// 生成交易哈希
	txHashBytes := chainhash.DoubleHashB([]byte(signedTx))
	txHash = hex.EncodeToString(txHashBytes)

	return signedTx, txHash, nil
}