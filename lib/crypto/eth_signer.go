package crypto

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// TextBigInt 是big.Int的自定义类型，支持从多种格式解析JSON
// 可以解析字符串格式的十进制数、16进制数(0x开头)，以及数字类型
type TextBigInt big.Int

// MarshalJSON 实现json.Marshaler接口
func (t *TextBigInt) MarshalJSON() ([]byte, error) {
	if t == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(t.String())
}

// UnmarshalJSON 实现json.Unmarshaler接口
func (t *TextBigInt) UnmarshalJSON(data []byte) error {
	// 尝试作为字符串解析
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		// 检查是否是0x开头的16进制格式
		if len(str) > 2 && str[:2] == "0x" {
			val, ok := new(big.Int).SetString(str[2:], 16)
			if !ok {
				return errors.New("invalid hex number format")
			}
			*t = TextBigInt(*val)
			return nil
		}
		// 尝试作为十进制字符串解析
		val, ok := new(big.Int).SetString(str, 10)
		if !ok {
			return errors.New("invalid decimal number format")
		}
		*t = TextBigInt(*val)
		return nil
	}

	// 尝试作为数字解析
	var num float64
	if err := json.Unmarshal(data, &num); err == nil {
		// 检查数字是否为整数
		if num == float64(int64(num)) {
			val := big.NewInt(int64(num))
			*t = TextBigInt(*val)
			return nil
		}
		return errors.New("number must be integer")
	}

	// 尝试作为嵌套对象解析，如{"_hex": "0x1"}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		if hexStr, ok := obj["_hex"].(string); ok {
			val, ok := new(big.Int).SetString(hexStr[2:], 16)
			if !ok {
				return errors.New("invalid hex number format in object")
			}
			*t = TextBigInt(*val)
			return nil
		}
	}

	return errors.New("cannot parse value to big.Int")
}

// ToBigInt 将TextBigInt转换为*big.Int
func (t *TextBigInt) ToBigInt() *big.Int {
	if t == nil {
		return nil
	}
	return (*big.Int)(t)
}

// String 返回TextBigInt的十进制字符串表示
func (t *TextBigInt) String() string {
	return t.ToBigInt().String()
}

// EthTransactionRequest 以太坊交易请求结构
// 使用TextBigInt替代所有数值类型，支持多种格式解析
// 例如：字符串格式的十进制数、16进制数(0x开头)，以及数字类型
// 也支持嵌套对象格式如{"_hex": "0x1"}
type EthTransactionRequest struct {
	From               string      `json:"from"`
	To                 string      `json:"to"`
	Gas                *TextBigInt `json:"gas"`
	GasPrice           *TextBigInt `json:"gasPrice"` // Legacy交易参数
	MaxPriorityFeePerGas *TextBigInt `json:"maxPriorityFeePerGas"` // EIP-1559交易参数
	MaxFeePerGas       *TextBigInt `json:"maxFeePerGas"` // EIP-1559交易参数
	Value              *TextBigInt `json:"value"`
	Data               string      `json:"data"`
	Nonce              *TextBigInt `json:"nonce"`
	ChainID            *TextBigInt `json:"chainId"` // 使用TextBigInt支持多种格式解析
}
// EthTransactionSigner 以太坊交易签名器
type EthTransactionSigner struct{}

// SignTransaction 签名以太坊交易
func (s *EthTransactionSigner) SignTransaction(rawTx, privateKeyHex string) (signedTx string, txHash string, err error) {
	// 解码私钥
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key format: %w", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key: %w", err)
	}

	// 解析交易参数，TextBigInt类型会自动处理多种格式的数值
	var txReq EthTransactionRequest
	if err = json.Unmarshal([]byte(rawTx), &txReq); err != nil {
		return "", "", fmt.Errorf("invalid transaction data format: %w", err)
	}

	// 验证必要的数值参数
	if txReq.Nonce == nil {
		return "", "", errors.New("nonce is required")
	}
	if txReq.Gas == nil {
		return "", "", errors.New("gas is required")
	}
	if txReq.ChainID == nil {
		return "", "", errors.New("chainId is required")
	}

	// 验证交易费用参数：要么使用Legacy的GasPrice，要么使用EIP-1559的MaxPriorityFeePerGas和MaxFeePerGas
	useEIP1559 := txReq.MaxPriorityFeePerGas != nil && txReq.MaxFeePerGas != nil
	useLegacy := txReq.GasPrice != nil

	if !useEIP1559 && !useLegacy {
		return "", "", errors.New("either gasPrice (for legacy tx) or maxPriorityFeePerGas and maxFeePerGas (for EIP-1559 tx) is required")
	}

	// 将TextBigInt转换为big.Int
	nonce := txReq.Nonce.ToBigInt()
	gas := txReq.Gas.ToBigInt()
	value := big.NewInt(0)
	if txReq.Value != nil {
		value = txReq.Value.ToBigInt()
	}
	chainID := txReq.ChainID.ToBigInt()

	// 根据接收地址创建相应的交易对象
	var tx *types.Transaction

	if useEIP1559 {
		// 使用EIP-1559交易格式
		maxPriorityFeePerGas := txReq.MaxPriorityFeePerGas.ToBigInt()
		maxFeePerGas := txReq.MaxFeePerGas.ToBigInt()

		if txReq.To != "" {
			toAddress := common.HexToAddress(txReq.To)
			tx = types.NewTx(&types.DynamicFeeTx{
				ChainID:   chainID,
				Nonce:     nonce.Uint64(),
				GasTipCap: maxPriorityFeePerGas,
				GasFeeCap: maxFeePerGas,
				Gas:       gas.Uint64(),
				To:        &toAddress,
				Value:     value,
				Data:      common.FromHex(txReq.Data),
			})
		} else {
			// 合约创建交易
			tx = types.NewTx(&types.DynamicFeeTx{
				ChainID:   chainID,
				Nonce:     nonce.Uint64(),
				GasTipCap: maxPriorityFeePerGas,
				GasFeeCap: maxFeePerGas,
				Gas:       gas.Uint64(),
				To:        nil,
				Value:     value,
				Data:      common.FromHex(txReq.Data),
			})
		}
	} else {
		// 使用Legacy交易格式
		gasPrice := txReq.GasPrice.ToBigInt()
		if txReq.To != "" {
			toAddress := common.HexToAddress(txReq.To)
			tx = types.NewTx(&types.LegacyTx{
				Nonce:    nonce.Uint64(),
				GasPrice: gasPrice,
				Gas:      gas.Uint64(),
				To:       &toAddress,
				Value:    value,
				Data:     common.FromHex(txReq.Data),
			})
		} else {
			// 合约创建交易
			tx = types.NewTx(&types.LegacyTx{
				Nonce:    nonce.Uint64(),
				GasPrice: gasPrice,
				Gas:      gas.Uint64(),
				To:       nil,
				Value:    value,
				Data:     common.FromHex(txReq.Data),
			})
		}
	}

	// 签名交易
	var signer types.Signer
	if tx.Type() == types.DynamicFeeTxType {
		signer = types.NewLondonSigner(chainID)
	} else {
		signer = types.NewEIP155Signer(chainID)
	}
	signedTxObj, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// 序列化签名后的交易
	txBytes, err := signedTxObj.MarshalBinary()
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal transaction: %w", err)
	}

	// 生成交易哈希
	txHash = signedTxObj.Hash().Hex()
	signedTx = "0x" + hex.EncodeToString(txBytes)

	return signedTx, txHash, nil
}
