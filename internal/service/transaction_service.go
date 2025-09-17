package service

import (
	"errors"
	"fmt"
	"time"

	xormio "xorm.io/xorm"
	"github.com/katuyo/goals/internal/crypto"
	"github.com/katuyo/goals/internal/db"
	"github.com/katuyo/goals/internal/model"
)

// TransactionService 交易服务
type TransactionService struct {
	db         *xormio.Engine
	keyService *KeyService
}

// NewTransactionService 创建交易服务
func NewTransactionService(dbEngine *xormio.Engine, keyService *KeyService) (*TransactionService, error) {
	return &TransactionService{
		db:         dbEngine,
		keyService: keyService,
	},
	nil
}

// SignTransaction 为交易签名
func (s *TransactionService) SignTransaction(keyPairID int64, rawTx string) (*model.Transaction, error) {
	// 验证参数
	if keyPairID <= 0 || rawTx == "" {
		return nil, errors.New("keyPairID and rawTx are required")
	}

	// 获取密钥对
	keyPair, err := s.keyService.GetKeyPairByID(keyPairID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key pair: %w", err)
	}
	if keyPair == nil {
		return nil, errors.New("key pair not found")
	}

	// 获取私钥（从文件系统）
	privateKey, err := s.keyService.GetPrivateKey(keyPair.Address.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	// 创建交易签名器
	signer, err := crypto.NewTransactionSigner(keyPair.Address.ChainType)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction signer: %w", err)
	}

	// 签名交易
	signedTx, txHash, err := signer.SignTransaction(rawTx, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// 创建交易记录
	transaction := &model.Transaction{
		UserID:    keyPair.Address.UserID,
		KeyPairID: keyPair.Address.ID, // 使用地址ID作为KeyPairID
		ChainType: keyPair.Address.ChainType,
		TxHash:    txHash,
		RawTx:     rawTx,
		SignedTx:  signedTx,
		Status:    "signed",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// 保存到数据库
	_, err = s.db.Insert(transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to save transaction: %w", err)
	}

	return transaction, nil
}

// GetUserTransactions 获取用户的所有交易
func (s *TransactionService) GetUserTransactions(userID string) ([]*model.Transaction, error) {
	if userID == "" {
		return nil, errors.New("userID is required")
	}

	var transactions []*model.Transaction
	err := s.db.Where("user_id = ?", userID).OrderBy("created_at DESC").Find(&transactions)
	if err != nil {
		return nil, fmt.Errorf("failed to get user transactions: %w", err)
	}

	return transactions, nil
}

// GetTransactionByHash 获取指定哈希的交易
func (s *TransactionService) GetTransactionByHash(txHash string) (*model.Transaction, error) {
	if txHash == "" {
		return nil, errors.New("txHash is required")
	}

	transaction := &model.Transaction{}
	has, err := s.db.Where("tx_hash = ?", txHash).Get(transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}
	if !has {
		return nil, errors.New("transaction not found")
	}

	return transaction, nil
}

// UpdateTransactionStatus 更新交易状态
func (s *TransactionService) UpdateTransactionStatus(txHash, status string) error {
	if txHash == "" || status == "" {
		return errors.New("txHash and status are required")
	}

	affected, err := s.db.Where("tx_hash = ?", txHash).Update(&model.Transaction{
		Status:    status,
		UpdatedAt: time.Now(),
	})
	if err != nil {
		return fmt.Errorf("failed to update transaction status: %w", err)
	}
	if affected == 0 {
		return errors.New("transaction not found")
	}

	return nil
}