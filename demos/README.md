# 演示和验证文件目录

本目录包含项目中所有的演示和验证文件，用于展示和测试不同加密货币的功能。将这些文件集中存放在此处，以保持项目根目录的整洁。

## 目录内容

### 加密货币验证文件

这些文件用于验证不同加密货币的密钥生成和交易签名功能：

- **ada_signature_validation.go** - Cardano (ADA) 签名验证
- **btc_signature_validation.go** - Bitcoin (BTC) 签名验证
- **eth_signature_validation.go** - Ethereum (ETH) 签名验证
- **solana_signature_validation.go** - Solana (SOL) 签名验证
- **sui_signature_validation.go** - SUI 签名验证
- **ton_signature_validation.go** - TON 签名验证
- **tron_signature_validation.go** - TRON (TRX) 签名验证

### 演示文件

这些文件提供了特定功能的演示：

- **ada_address_demo.go** - Cardano 地址生成演示
- **crypto_demo.go** - 通用加密功能演示

## 使用方法

您可以使用以下命令运行这些验证和演示文件：

```bash
# 先进入demos目录
cd demos

# 运行特定的验证文件，例如以太坊验证
go run eth_signature_validation.go
```

或者从项目根目录直接运行：

```bash
go run demos/eth_signature_validation.go
```

## 注意事项

- 这些文件主要用于测试和演示目的，确保加密货币相关功能正常工作
- 每个文件都是独立的，不需要依赖其他文件即可运行
- 所有验证文件都包含多个测试用例，全面验证各加密货币的密钥生成和签名功能
- 运行后会显示详细的测试结果，包括通过/失败状态和关键信息
- 文件中的私钥和地址仅用于测试目的，生产环境中请使用安全的密钥管理方式