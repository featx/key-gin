package crypto

import (
	"crypto/sha256"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ripemd160"
)

// GetHashFunction 根据区块链类型返回适当的哈希函数
func GetHashFunction(chainType string) hash.Hash {
	// 注意：这里是简化实现，实际应用应根据各区块链官方规范选择哈希函数
	// 对于没有特定要求的，可以默认使用SHA-256
	return sha256.New()
}

// Blake2b256 计算输入数据的Blake2b-256哈希值
func Blake2b256(data []byte) []byte {
	hash, _ := blake2b.New256(nil)
	hash.Write(data)
	return hash.Sum(nil)
}

// Ripemd160 计算输入数据的RIPEMD-160哈希值
func Ripemd160(data []byte) []byte {
	hash := ripemd160.New()
	hash.Write(data)
	return hash.Sum(nil)
}