package service

import (
	"errors"
	"fmt"

	"github.com/featx/keys-gin/lib/crypto"
	"github.com/featx/keys-gin/lib/keystore"
	"github.com/featx/keys-gin/web/model"
	"github.com/featx/keys-gin/web/util"
	"xorm.io/xorm"
)

// KeyService 密钥对服务
type KeyService struct {
	db       *xorm.Engine
	keyStore *keystore.Keystore
}

// NewKeyService 创建密钥服务
func NewKeyService(dbEngine *xorm.Engine) (*KeyService, error) {
	// 创建私钥存储管理器
	keyStore, err := keystore.NewKeystore("./data/keystore")
	if err != nil {
		return nil, fmt.Errorf("failed to create keystore: %w", err)
	}

	return &KeyService{
			db:       dbEngine,
			keyStore: keyStore,
		},
		nil
}

// GenerateKeyPair 为用户生成指定链的密钥对
// 实现逻辑：
// 1. 检查用户是否已有该链类型的地址，如有则直接返回
// 2. 如果没有，检查用户是否有使用相同曲线的其他链类型的密钥对
// 3. 如果有，从已有私钥推导出新链类型的公钥和地址
// 4. 如果都没有，生成新的密钥对
func (s *KeyService) GenerateKeyPair(userID, chainType string) (*model.KeyPair, error) {
	// 验证参数
	if userID == "" || chainType == "" {
		return nil, errors.New("userID and chainType are required")
	}

	// 步骤1: 检查用户是否已有该链类型的地址
	if existingKeyPair, err := s.checkExistingAddress(userID, chainType); err != nil {
		return nil, err
	} else if existingKeyPair != nil {
		return existingKeyPair, nil
	}

	// 获取曲线类型和编码方式
	curve, encoding := util.GetCurveAndEncoding(chainType)

	// 步骤2: 检查用户是否有使用相同曲线的其他链类型的密钥对
	var existingPublicKeys []model.PublicKey
	err := s.db.Where("user_id = ? AND curve = ?", userID, curve).Find(&existingPublicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing public keys with same curve: %w", err)
	}

	// 步骤3: 如果有相同曲线的密钥对，尝试从已有密钥推导
	if len(existingPublicKeys) > 0 {
		return s.deriveKeyPairFromExisting(existingPublicKeys, userID, chainType, curve, encoding)
	}

	// 步骤4: 生成新的密钥对
	return s.generateNewKeyPair(userID, chainType, curve, encoding)
}

// checkExistingAddress 检查用户是否已有该链类型的地址，有则返回对应的密钥对
func (s *KeyService) checkExistingAddress(userID, chainType string) (*model.KeyPair, error) {
	var existingAddress model.Address
	has, err := s.db.Where("user_id = ? AND chain_type = ?", userID, chainType).Get(&existingAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing address: %w", err)
	}

	// 如果地址已存在，返回对应的密钥对
	if has {
		var existingPublicKey model.PublicKey
		has, err := s.db.Where("public_key = ?", existingAddress.PublicKey).Get(&existingPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get existing public key: %w", err)
		}
		if has {
			return &model.KeyPair{
					PublicKey: &existingPublicKey,
					Address:   &existingAddress,
				},
				nil
		}
	}

	return nil, nil
}

// deriveKeyPairFromExisting 从已有密钥对推导新链类型的密钥对
func (s *KeyService) deriveKeyPairFromExisting(existingPublicKeys []model.PublicKey, userID, chainType, curve, encoding string) (*model.KeyPair, error) {
	// 创建密钥生成器
	generator, err := crypto.NewKeyGenerator(chainType)
	if err != nil {
		return nil, fmt.Errorf("failed to create key generator: %w", err)
	}

	// 选择第一个使用相同曲线的公钥
	publicKey := existingPublicKeys[0].PublicKey
	benchmarkChainType := existingPublicKeys[0].ChainType

	// 优先尝试直接从公钥生成新链类型的地址
	addressValue, err := generator.PublicKeyToAddress(publicKey)
	if err == nil {
		// 获取基准链类型的私钥（用于保存）
		var privateKey string
		if privateKey, err = s.keyStore.GetUserPrivateKey(userID, benchmarkChainType); err != nil {
			// 如果获取私钥失败，回退到生成新密钥对
			return s.generateNewKeyPair(userID, chainType, curve, encoding)
		}

		// 保存新的公钥和地址到数据库
		return s.saveDerivedKeyPair(userID, chainType, curve, encoding, publicKey, addressValue, privateKey)
	}

	// 如果从公钥生成地址失败，回退到从私钥推导
	privateKey, err := s.keyStore.GetUserPrivateKey(userID, benchmarkChainType)
	if err != nil {
		// 如果获取私钥失败，回退到生成新密钥对
		return s.generateNewKeyPair(userID, chainType, curve, encoding)
	}

	// 从现有私钥推导公钥和地址
	addressValue, publicKeyValue, err := generator.DeriveKeyPairFromPrivateKey(privateKey)
	if err != nil {
		// 如果推导失败，回退到生成新密钥对
		return s.generateNewKeyPair(userID, chainType, curve, encoding)
	}

	// 保存新的公钥和地址到数据库
	return s.saveDerivedKeyPair(userID, chainType, curve, encoding, publicKeyValue, addressValue, privateKey)
}

// GetUserKeyPairs 获取用户的所有密钥对
func (s *KeyService) GetUserKeyPairs(userID string) ([]*model.KeyPair, error) {
	if userID == "" {
		return nil, errors.New("userID is required")
	}

	// 查询公钥
	var publicKeys []*model.PublicKey
	err := s.db.Where("user_id = ?", userID).Find(&publicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}

	// 查询对应的地址
	keyPairs := make([]*model.KeyPair, 0, len(publicKeys))
	for _, pk := range publicKeys {
		address := &model.Address{}
		has, err := s.db.Where("public_key = ?", pk.PublicKey).Get(address)
		if err != nil {
			return nil, fmt.Errorf("failed to get address for public key: %w", err)
		}
		if has {
			keyPairs = append(keyPairs, &model.KeyPair{
				PublicKey: pk,
				Address:   address,
			})
		}
	}

	return keyPairs, nil
}

// GetKeyPairByID 获取指定ID的密钥对
// 注意：此方法不返回私钥，私钥需要通过GetPrivateKey方法单独获取
func (s *KeyService) GetKeyPairByID(id int64) (*model.KeyPair, error) {
	// 首先通过地址ID查找
	address := &model.Address{}
	has, err := s.db.ID(id).Get(address)
	if err != nil {
		return nil, fmt.Errorf("failed to get address: %w", err)
	}
	if !has {
		return nil, nil
	}

	// 然后查找对应的公钥
	publicKey := &model.PublicKey{}
	has, err = s.db.Where("public_key = ?", address.PublicKey).Get(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	if !has {
		return nil, nil
	}

	keyPair := &model.KeyPair{
		PublicKey: publicKey,
		Address:   address,
	}

	return keyPair, nil
}

// GetKeyPairByAddress 获取指定地址的密钥对
// 注意：此方法不返回私钥，私钥需要通过GetPrivateKey方法单独获取
func (s *KeyService) GetKeyPairByAddress(addressValue string) (*model.KeyPair, error) {
	if addressValue == "" {
		return nil, errors.New("address is required")
	}

	// 先查找地址
	address := &model.Address{}
	has, err := s.db.Where("address = ?", addressValue).Get(address)
	if err != nil {
		return nil, fmt.Errorf("failed to get address: %w", err)
	}
	if !has {
		return nil, nil
	}

	// 然后查找对应的公钥
	publicKey := &model.PublicKey{}
	has, err = s.db.Where("public_key = ?", address.PublicKey).Get(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	if !has {
		return nil, nil
	}

	keyPair := &model.KeyPair{
		PublicKey: publicKey,
		Address:   address,
	}

	return keyPair, nil
}

// GetPrivateKey 获取指定地址的私钥
func (s *KeyService) GetPrivateKey(addressValue string) (string, error) {
	if addressValue == "" {
		return "", errors.New("address is required")
	}

	// 验证该地址是否存在
	address := &model.Address{}
	has, err := s.db.Where("address = ?", addressValue).Get(address)
	if err != nil {
		return "", fmt.Errorf("failed to verify address: %w", err)
	}
	if !has {
		return "", errors.New("address not found")
	}

	// 从文件系统获取私钥
	privateKey, err := s.keyStore.GetPrivateKey(addressValue)
	if err != nil {
		return "", fmt.Errorf("failed to get private key: %w", err)
	}

	return privateKey, nil
}

// DeleteKeyPair 删除指定ID的密钥对
func (s *KeyService) DeleteKeyPair(id int64) error {
	// 获取密钥对
	keyPair, err := s.GetKeyPairByID(id)
	if err != nil {
		return fmt.Errorf("failed to get key pair: %w", err)
	}
	if keyPair == nil {
		return nil
	}

	// 删除私钥文件
	if err = s.keyStore.DeletePrivateKey(keyPair.Address.Address); err != nil {
		return fmt.Errorf("failed to delete private key: %w", err)
	}

	// 从数据库删除地址
	_, err = s.db.ID(keyPair.Address.ID).Delete(&model.Address{})
	if err != nil {
		return fmt.Errorf("failed to delete address from database: %w", err)
	}

	// 从数据库删除公钥
	_, err = s.db.ID(keyPair.PublicKey.ID).Delete(&model.PublicKey{})
	if err != nil {
		return fmt.Errorf("failed to delete public key from database: %w", err)
	}

	return nil
}

// GetUserPrivateKey 获取指定用户ID和链类型的私钥
func (s *KeyService) GetUserPrivateKey(userID, chainType string) (string, error) {
	return s.keyStore.GetUserPrivateKey(userID, chainType)
}

// generateNewKeyPair 生成新的密钥对并保存
func (s *KeyService) generateNewKeyPair(userID, chainType, curve, encoding string) (*model.KeyPair, error) {
	// 创建密钥生成器
	generator, err := crypto.NewKeyGenerator(chainType)
	if err != nil {
		return nil, fmt.Errorf("failed to create key generator: %w", err)
	}

	// 生成密钥对
	addressValue, publicKeyValue, privateKey, err := generator.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 同时保存私钥到两个位置：按地址索引和按用户ID索引
	if err := s.keyStore.SavePrivateKey(addressValue, privateKey); err != nil {
		return nil, fmt.Errorf("failed to save private key by address: %w", err)
	}

	if err := s.keyStore.SaveUserPrivateKey(userID, chainType, privateKey); err != nil {
		// 如果按用户ID保存失败，删除已保存的按地址索引的私钥
		s.keyStore.DeletePrivateKey(addressValue)
		return nil, fmt.Errorf("failed to save private key by user ID: %w", err)
	}

	// 保存公钥和地址到数据库
	return s.saveKeyPairToDatabase(userID, chainType, curve, encoding, publicKeyValue, addressValue)
}

// saveDerivedKeyPair 保存从现有私钥推导的公钥和地址
func (s *KeyService) saveDerivedKeyPair(userID, chainType, curve, encoding, publicKeyValue, addressValue, privateKey string) (*model.KeyPair, error) {
	// 保存私钥按用户ID索引（如果还没有保存的话）
	if err := s.keyStore.SaveUserPrivateKey(userID, chainType, privateKey); err != nil {
		return nil, fmt.Errorf("failed to save private key by user ID: %w", err)
	}

	// 保存公钥和地址到数据库
	return s.saveKeyPairToDatabase(userID, chainType, curve, encoding, publicKeyValue, addressValue)
}

// saveKeyPairToDatabase 将公钥和地址保存到数据库
func (s *KeyService) saveKeyPairToDatabase(userID, chainType, curve, encoding, publicKeyValue, addressValue string) (*model.KeyPair, error) {
	// 创建公钥记录
	publicKey := &model.PublicKey{
		PublicKey: publicKeyValue,
		UserID:    userID,
		Curve:     curve,
	}

	// 创建地址记录
	address := &model.Address{
		PublicKey: publicKeyValue,
		UserID:    userID,
		ChainType: chainType,
		Address:   addressValue,
		Encoding:  encoding,
	}

	// 保存公钥到数据库
	_, err := s.db.Insert(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to save public key: %w", err)
	}

	// 保存地址到数据库
	_, err = s.db.Insert(address)
	if err != nil {
		// 如果地址保存失败，删除已保存的公钥
		s.db.Delete(publicKey)
		return nil, fmt.Errorf("failed to save address: %w", err)
	}

	// 返回组合的密钥对
	keyPair := &model.KeyPair{
		PublicKey: publicKey,
		Address:   address,
	}

	return keyPair, nil
}
