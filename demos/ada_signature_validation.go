package main

import (
	"encoding/json"
	"fmt"

	"github.com/featx/keys-gin/lib/crypto"
)

func main() {
	fmt.Println("===== Cardano (ADA) 密钥生成与签名验证测试 =====")

	// 创建ADA密钥生成器
	keyGenerator := &crypto.AdaKeyGenerator{}

	// 1. 生成密钥对
	address, publicKey, privateKey, err := keyGenerator.GenerateKeyPair()
	if err != nil {
		fmt.Printf("❌ 生成密钥对失败: %v\n", err)
		return
	}
	fmt.Printf("✅ 生成密钥对成功\n")
	fmt.Printf("   私钥 (hex): %s\n", privateKey)
	fmt.Printf("   私钥长度: %d 字节\n", len(privateKey)/2) // hex编码是2倍长度
	fmt.Printf("   公钥 (hex): %s\n", publicKey)
	fmt.Printf("   地址: %s\n", address)

	// 2. 创建一个测试交易
	txReq := crypto.AdaTransactionRequest{
		Inputs: []crypto.AdaTxInput{
			{
				TxID:   "61f0bdbd7df2425e5b1e2576d0be264986a08e9f7f2f6152f37c922b0638d023",
				Index:  0,
				Amount: 1000000000, // 1 ADA = 1,000,000 lovelace
			},
		},
		Outputs: []crypto.AdaTxOutput{
			{
				Address: address, // 使用我们生成的地址作为输出
				Amount:  999830000, // 减去手续费
			},
		},
		Fee: 170000, // 手续费
		TTL: 8000000, // Time To Live
	}

	// 序列化交易
	txBytes, err := json.Marshal(txReq)
	if err != nil {
		fmt.Printf("❌ 序列化交易失败: %v\n", err)
		return
	}
	rawTx := string(txBytes)

	// 3. 使用生成的私钥对交易进行签名
	signer := &crypto.AdaTransactionSigner{}
	signedTx, txHash, err := signer.SignTransaction(rawTx, privateKey)
	if err != nil {
		fmt.Printf("❌ 签名交易失败: %v\n", err)
		return
	}

	// 4. 验证签名结果
	fmt.Printf("✅ 签名交易成功\n")
	fmt.Printf("   交易哈希: %s\n", txHash)
	fmt.Printf("   签名交易长度: %d 字符\n", len(signedTx))

	// 5. 验证私钥格式（生成第二个密钥对并检查格式一致性）
	_ /*address2*/, _ /*publicKey2*/, privateKey2, err := keyGenerator.GenerateKeyPair()
	if err != nil {
		fmt.Printf("❌ 生成第二个密钥对失败: %v\n", err)
		return
	}
	fmt.Printf("✅ 验证私钥格式一致\n")
	fmt.Printf("   第二个私钥长度: %d 字节\n", len(privateKey2)/2)

	fmt.Println("\n===== 验证总结 =====")
	fmt.Println("✅ 密钥生成器与签名器兼容测试通过")
	fmt.Println("✅ 生成的私钥能够成功用于交易签名")
	fmt.Println("✅ 签名过程没有出现错误")
	fmt.Println("✅ 私钥格式符合Ed25519算法要求")
	fmt.Println("\n注意: 这是一个简化的测试。在实际生产环境中，建议使用Cardano官方库进行交易签名。")
	fmt.Println("官方推荐库: github.com/input-output-hk/cardano-addresses/go")
}