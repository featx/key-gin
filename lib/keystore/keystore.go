package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Keystore 私钥存储管理器
type Keystore struct {
	baseDir string
}

// UserPrivateKeys 存储用户所有私钥的结构
type UserPrivateKeys struct {
	PrivateKeys map[string]string `json:"private_keys"` // 链类型 -> 私钥映射
}

// NewKeystore 创建私钥存储管理器
func NewKeystore(baseDir string) (*Keystore, error) {
	// 确保基础目录存在
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keystore directory: %w", err)
	}
	
	return &Keystore{baseDir: baseDir},
		 nil
}

// getKeyFilePath 根据地址获取私钥文件路径
func (ks *Keystore) getKeyFilePath(address string) string {
	// 为了安全，我们可以对地址进行哈希处理作为文件名
	// 这里简化处理，直接使用地址作为文件名的一部分
	return filepath.Join(ks.baseDir, fmt.Sprintf("key_%s.txt", address))
}

// getUserKeyFilePath 根据用户ID获取私钥文件路径
func (ks *Keystore) getUserKeyFilePath(userID string) string {
	// 使用用户ID作为文件名的一部分
	return filepath.Join(ks.baseDir, fmt.Sprintf("user_%s_private_keys.json", userID))
}

// SavePrivateKey 保存私钥到文件
// 注意：在实际生产环境中，应该对私钥进行加密存储
func (ks *Keystore) SavePrivateKey(address, privateKey string) error {
	filePath := ks.getKeyFilePath(address)
	
	// 写入文件（简化版本，实际应该加密）
	if err := os.WriteFile(filePath, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	
	return nil
}

// SaveUserPrivateKey 按用户ID保存私钥
func (ks *Keystore) SaveUserPrivateKey(userID, chainType, privateKey string) error {
	filePath := ks.getUserKeyFilePath(userID)
	
	// 读取现有私钥
	userKeys := &UserPrivateKeys{
		PrivateKeys: make(map[string]string),
	}
	
	// 如果文件已存在，读取现有内容
	if exists, err := fileExists(filePath); err == nil && exists {
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read existing user private keys: %w", err)
		}
		
		// 解析JSON
		if err := json.Unmarshal(fileData, userKeys); err != nil {
			return fmt.Errorf("failed to parse user private keys: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check user private keys file: %w", err)
	}
	
	// 更新或添加私钥
	userKeys.PrivateKeys[chainType] = privateKey
	
	// 序列化并保存
	jsonData, err := json.MarshalIndent(userKeys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal user private keys: %w", err)
	}
	
	if err := os.WriteFile(filePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to save user private keys: %w", err)
	}
	
	return nil
}

// GetPrivateKey 从文件中获取私钥
func (ks *Keystore) GetPrivateKey(address string) (string, error) {
	filePath := ks.getKeyFilePath(address)
	
	// 检查文件是否存在
	exists, err := fileExists(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to check private key file: %w", err)
	}
	
	if !exists {
		return "", errors.New("private key not found for address")
	}
	
	// 读取文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}
	
	return string(data), nil
}

// GetUserPrivateKey 按用户ID和链类型获取私钥
func (ks *Keystore) GetUserPrivateKey(userID, chainType string) (string, error) {
	filePath := ks.getUserKeyFilePath(userID)
	
	// 检查文件是否存在
	exists, err := fileExists(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to check user private keys file: %w", err)
	}
	
	if !exists {
		return "", errors.New("private key not found for user")
	}
	
	// 读取文件内容
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read user private keys: %w", err)
	}
	
	// 解析JSON
	userKeys := &UserPrivateKeys{}
	if err := json.Unmarshal(fileData, userKeys); err != nil {
		return "", fmt.Errorf("failed to parse user private keys: %w", err)
	}
	
	// 获取指定链类型的私钥
	privateKey, exists := userKeys.PrivateKeys[chainType]
	if !exists {
		return "", errors.New("private key not found for chain type")
	}
	
	return privateKey, nil
}

// DeletePrivateKey 删除私钥文件
func (ks *Keystore) DeletePrivateKey(address string) error {
	filePath := ks.getKeyFilePath(address)
	
	// 检查文件是否存在
	exists, err := fileExists(filePath)
	if err != nil {
		return fmt.Errorf("failed to check private key file: %w", err)
	}
	
	if !exists {
		return errors.New("private key file not found")
	}
	
	// 删除文件
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete private key: %w", err)
	}
	
	return nil
}

// fileExists 检查文件是否存在
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// EncryptPrivateKey 加密私钥（可选功能）
// 在实际生产环境中，应该使用这个方法加密私钥后再存储
func EncryptPrivateKey(privateKey, password string) (string, error) {
	// 创建AES加密块
	block, err := aes.NewCipher([]byte(password)[:32])
	if err != nil {
		return "", err
	}
	
	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	// 创建随机数作为nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	
	// 加密数据
	ciphertext := gcm.Seal(nonce, nonce, []byte(privateKey), nil)
	
	// 转换为十六进制字符串
	return hex.EncodeToString(ciphertext), nil
}

// DecryptPrivateKey 解密私钥（可选功能）
func DecryptPrivateKey(encryptedData, password string) (string, error) {
	// 解码十六进制字符串
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	
	// 创建AES加密块
	block, err := aes.NewCipher([]byte(password)[:32])
	if err != nil {
		return "", err
	}
	
	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	// 提取nonce
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	
	// 解密数据
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	
	return string(plaintext), nil
}