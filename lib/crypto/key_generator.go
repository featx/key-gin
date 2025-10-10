package crypto

import (
	"errors"

	"github.com/featx/keys-gin/web/model"
)

// 注意：这个文件已被重构为模块化结构
// 所有密钥生成器的具体实现已移至单独的文件中
// 本文件保留兼容性层，确保现有代码能无缝工作

// 声明需要的结构体以避免编译错误
var (
	// 这些变量用于确保编译器不会报错
	_ = &EthKeyGenerator{}
	_ = &BtcKeyGenerator{}
	_ = &SolanaKeyGenerator{}
	_ = &TronKeyGenerator{}
	_ = &SuiKeyGenerator{}
	_ = &AdaKeyGenerator{}
	_ = &PolkadotKeyGenerator{}
	_ = &TonKeyGenerator{}
)

// NewKeyGenerator 根据区块链类型创建密钥生成器
// 这是一个兼容性包装函数
func NewKeyGenerator(chainType string) (KeyGenerator, error) {
	switch chainType {
	case model.ChainTypeETH, model.ChainTypeBSC, model.ChainTypePolygon, model.ChainTypeAvalanche:
		return &EthKeyGenerator{}, nil
	case model.ChainTypeBTC:
		return &BtcKeyGenerator{}, nil
	case model.ChainTypeSolana:
		return &SolanaKeyGenerator{}, nil
	case model.ChainTypeTRON:
		return &TronKeyGenerator{}, nil
	case model.ChainTypeSUI:
		return &SuiKeyGenerator{}, nil
	case model.ChainTypeADA:
		return &AdaKeyGenerator{}, nil
	case model.ChainTypePolkadot, model.ChainTypeKusama:
		return &PolkadotKeyGenerator{}, nil
	case model.ChainTypeTON:
		return &TonKeyGenerator{}, nil
	case model.ChainTypeAPTOS:
		return &AptosKeyGenerator{}, nil
	default:
		return nil, errors.New("unsupported chain type")
	}
}