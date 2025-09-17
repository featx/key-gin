package util

import "github.com/featx/keys-gin/internal/model"

// GetCurveAndEncoding 根据链类型获取对应的曲线类型和编码方式
func GetCurveAndEncoding(chainType string) (string, string) {
	switch chainType {
	case model.ChainTypeETH, model.ChainTypeAvalanche:
		return "secp256k1", "ethereum_address"
	case model.ChainTypeBTC:
		return "secp256k1", "bitcoin_public_key"
	case model.ChainTypeSolana:
		return "ed25519", "solana_address"
	case model.ChainTypeTRON:
		return "secp256k1", "tron_address"
	case model.ChainTypeSUI:
		return "ed25519", "sui_address"
	case model.ChainTypeADA:
		return "ed25519", "cardano_address"
	case model.ChainTypePolkadot, model.ChainTypeKusama:
		return "sr25519", "ss58_address"
	case model.ChainTypeTON:
		return "ed25519", "ton_address"
	default:
		return "unknown", "unknown"
	}
}