package model

import (
	"time"
)

// ChainType 区块链类型枚举
const (
	ChainTypeETH  = "ethereum"
	ChainTypeBTC  = "bitcoin"
	ChainTypeAvalanche = "avalanche"
	ChainTypeSolana = "solana"
	ChainTypeTRON = "tron"
	ChainTypeSUI = "sui"
	ChainTypeADA = "ada"
	ChainTypePolkadot = "polkadot"
	ChainTypeKusama = "kusama"
	ChainTypeTON = "ton"
)

// PublicKey 公钥模型
// 存储公钥信息及相关元数据

type PublicKey struct {
	ID          int64     `xorm:"pk autoincr" json:"id"`
	UserID      string    `xorm:"varchar(50) notnull index" json:"user_id"`
	ChainType   string    `xorm:"varchar(30) notnull index" json:"chain_type"`
	PublicKey   string    `xorm:"text notnull unique" json:"public_key"`
	Curve       string    `xorm:"varchar(50) notnull" json:"curve"` // 推导椭圆曲线方式
	CreatedAt   time.Time `xorm:"created" json:"created_at"`
	UpdatedAt   time.Time `xorm:"updated" json:"updated_at"`
}

// Address 地址模型
// 存储地址信息及相关元数据

type Address struct {
	ID          int64     `xorm:"pk autoincr" json:"id"`
	PublicKey   string    `xorm:"text notnull index" json:"public_key"` // 直接使用公钥作为关联字段
	UserID      string    `xorm:"varchar(50) notnull index" json:"user_id"`
	ChainType   string    `xorm:"varchar(30) notnull index" json:"chain_type"`
	Address     string    `xorm:"varchar(100) notnull unique" json:"address"`
	Encoding    string    `xorm:"varchar(50) notnull" json:"encoding"` // 从公钥转换的编码方式
	CreatedAt   time.Time `xorm:"created" json:"created_at"`
	UpdatedAt   time.Time `xorm:"updated" json:"updated_at"`
}

// KeyPair 密钥对模型
// 注意：这是一个组合结构，不会被同步为数据库表

type KeyPair struct {
	PublicKey *PublicKey `xorm:"-" json:"public_key"`
	Address   *Address   `xorm:"-" json:"address"`
}

// Transaction 交易模型
type Transaction struct {
	ID          int64     `xorm:"pk autoincr" json:"id"`
	UserID      string    `xorm:"varchar(50) notnull index" json:"user_id"`
	KeyPairID   int64     `xorm:"notnull index" json:"key_pair_id"`
	ChainType   string    `xorm:"varchar(30) notnull index" json:"chain_type"`
	TxHash      string    `xorm:"varchar(100) notnull unique" json:"tx_hash"`
	RawTx       string    `xorm:"text notnull" json:"raw_tx"`
	SignedTx    string    `xorm:"text notnull" json:"signed_tx"`
	Status      string    `xorm:"varchar(20) notnull default 'pending'" json:"status"`
	CreatedAt   time.Time `xorm:"created" json:"created_at"`
	UpdatedAt   time.Time `xorm:"updated" json:"updated_at"`
}