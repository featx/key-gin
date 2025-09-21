package crypto

import (
	"errors"

	"github.com/featx/keys-gin/web/model"
)

// NewTransactionSigner 根据区块链类型创建交易签名器
// 类ETH的链共用一个签名器，chainId从交易参数中获取
func NewTransactionSigner(chainType string) (TransactionSigner, error) {
	switch chainType {
	case model.ChainTypeETH, model.ChainTypeBSC, model.ChainTypePolygon, model.ChainTypeAvalanche:
		return &EthTransactionSigner{}, nil
	case model.ChainTypeBTC:
		return &BtcTransactionSigner{}, nil
	case model.ChainTypeSolana:
		return &SolanaTransactionSigner{}, nil
	case model.ChainTypeTRON:
		return &TronTransactionSigner{}, nil
	case model.ChainTypeSUI:
		return &SuiTransactionSigner{}, nil
	case model.ChainTypeADA:
		return &AdaTransactionSigner{}, nil
	case model.ChainTypePolkadot:
		return &PolkadotTransactionSigner{IsKusama: false}, nil
	case model.ChainTypeKusama:
		return &PolkadotTransactionSigner{IsKusama: true}, nil
	case model.ChainTypeTON:
		return &TonTransactionSigner{}, nil
	default:
		return nil, errors.New("unsupported chain type")
	}
}