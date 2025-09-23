package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/ed25519"
)

// AdaTransactionRequest Cardano交易请求结构
type AdaTransactionRequest struct {
	Inputs   []AdaTxInput             `json:"inputs"`
	Outputs  []AdaTxOutput            `json:"outputs"`
	Fee      uint64                   `json:"fee"`
	TTL      uint64                   `json:"ttl,omitempty"` // Time To Live
	Metadata map[string]interface{}   `json:"metadata,omitempty"`
}

// AdaTxInput Cardano交易输入
type AdaTxInput struct {
	TxID   string `json:"txid"`
	Index  uint32 `json:"index"`
	Amount uint64 `json:"amount"`
}

// AdaTxOutput Cardano交易输出
type AdaTxOutput struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"` // 单位是lovelace
}

// AdaTransactionSigner Cardano交易签名器
type AdaTransactionSigner struct {}

// SignTransaction 签名Cardano交易
func (s *AdaTransactionSigner) SignTransaction(rawTx, privateKeyHex string) (signedTx string, txHash string, err error) {
	// 解码私钥
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key format: %w", err)
	}

	// 处理私钥长度 - 支持32字节种子或64字节完整私钥
	var seed []byte
	if len(privateKeyBytes) == 32 {
		// 直接使用32字节作为种子
		seed = privateKeyBytes
	} else if len(privateKeyBytes) == 64 {
		// 从64字节完整私钥中提取前32字节作为种子
		seed = privateKeyBytes[:32]
	} else {
		return "", "", fmt.Errorf("invalid private key length: expected 32 or 64 bytes, got %d bytes", len(privateKeyBytes))
	}

	// 解析交易参数
	var txReq AdaTransactionRequest
	if err := json.Unmarshal([]byte(rawTx), &txReq); err != nil {
		return "", "", fmt.Errorf("invalid transaction data format: %w", err)
	}

	// 准备交易数据进行哈希计算 (使用CBOR编码)
	txBodyData, txBodyHash, err := prepareCardanoTransactionBody(txReq)
	if err != nil {
		return "", "", err
	}

	// 使用Ed25519算法进行签名
	privateKey := ed25519.NewKeyFromSeed(seed)
	signature := ed25519.Sign(privateKey, txBodyHash)

	// 构建签名的交易 - 符合Cardano的WitnessSet格式
	signedTxData, err := buildCardanoSignedTransaction(txBodyData, txBodyHash, signature, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return "", "", err
	}

	// 返回十六进制编码的交易和交易哈希
	txHash = hex.EncodeToString(txBodyHash)
	signedTx = hex.EncodeToString(signedTxData)

	return signedTx, txHash, nil
}

// prepareCardanoTransactionBody 准备Cardano交易体数据并计算哈希
func prepareCardanoTransactionBody(txReq AdaTransactionRequest) ([]byte, []byte, error) {
	// 转换为Cardano交易体结构
	txBody := map[string]interface{}{
		"inputs":   convertInputs(txReq.Inputs),
		"outputs":  convertOutputs(txReq.Outputs),
		"fee":      txReq.Fee,
		"ttl":      txReq.TTL,
		"metadata": txReq.Metadata,
	}

	// 使用CBOR编码交易体
	encoder, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	txBodyData, err := encoder.Marshal(txBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode transaction body: %w", err)
	}

	// 计算交易体哈希 (Cardano使用双SHA256)
	txBodyHash := doubleSHA256(txBodyData)

	return txBodyData, txBodyHash, nil
}

// buildCardanoSignedTransaction 构建符合Cardano规范的签名交易
func buildCardanoSignedTransaction(txBodyData []byte, txBodyHash []byte, signature, publicKey []byte) ([]byte, error) {
	// 创建完整的交易结构
	transaction := map[string]interface{}{
		"body": txBodyData,
		"witness_set": map[string]interface{}{
			"vkeywitnesses": []map[string]interface{}{{
				"vkey":      publicKey,
				"signature": signature,
			}},
		},
	}

	// 使用CBOR编码完整交易
	encoder, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	signedTxData, err := encoder.Marshal(transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signed transaction: %w", err)
	}

	return signedTxData, nil
}

// convertInputs 转换输入格式为Cardano要求的格式
func convertInputs(inputs []AdaTxInput) []map[string]interface{} {
	result := make([]map[string]interface{}, len(inputs))
	for i, input := range inputs {
		txIDBytes, _ := hex.DecodeString(input.TxID)
		result[i] = map[string]interface{}{
			"tx_id": txIDBytes,
			"index": input.Index,
		}
	}
	return result
}

// convertOutputs 转换输出格式为Cardano要求的格式
func convertOutputs(outputs []AdaTxOutput) []map[string]interface{} {
	result := make([]map[string]interface{}, len(outputs))
	for i, output := range outputs {
		// 在实际应用中，应使用完整的bech32解码和地址解析
		result[i] = map[string]interface{}{
			"address": output.Address,
			"amount":  output.Amount,
		}
	}
	return result
}

// doubleSHA256 执行双SHA256哈希计算
func doubleSHA256(data []byte) []byte {
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:]
}