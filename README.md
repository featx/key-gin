# 区块链签名机 (Blockchain Signing Machine)

一个用于生成各种区块链密钥对和签名交易的服务。

## 功能特性

- 支持多种区块链：以太坊、比特币、币安智能链、Polygon、Avalanche等
- 生成区块链密钥对
- 为交易提供签名服务
- 保存密钥对和交易记录
- RESTful API接口
- 使用SQLite数据库存储数据

## 技术栈

- **Go**: 主要开发语言
- **Gin**: Web框架
- **XORM**: ORM框架 (已迁移至 xorm.io/xorm)
- **MySQL**: 主数据库
- **Viper**: 配置管理
- **Wire**: 依赖注入工具
- **BTCD**: 比特币相关功能支持
- **go-ethereum**: 以太坊相关功能支持
- **Keystore**: 文件系统私钥存储系统 (安全存储私钥)

## 项目结构

```

├── internal/             # 内部包
│   ├── config/           # 配置管理
│   ├── crypto/           # 密码学相关功能
│   ├── db/               # 数据库操作
│   ├── handler/          # HTTP请求处理
│   ├── model/            # 数据模型
│   └── service/          # 业务逻辑
├── config/               # 配置文件
├── data/                 # 数据库文件（运行时生成）
├── logs/                 # 日志文件（运行时生成）
├── go.mod                # Go模块定义
├── main.go               # 签名机主程序
└── README.md             # 项目说明
```

## 依赖注入架构

本项目使用Google Wire作为编译时依赖注入工具，实现了组件间的解耦。依赖注入架构如下：

1. **数据库引擎**：由`internal/db`包提供，作为底层依赖
2. **服务层**：
   - `KeyService`依赖于数据库引擎
   - `TransactionService`依赖于数据库引擎和`KeyService`
3. **处理器层**：
   - `KeyHandler`依赖于`KeyService`
   - `TransactionHandler`依赖于`TransactionService`
4. **路由器**：依赖于所有处理器

所有依赖关系在`internal/pkg/injector`包中定义和管理，通过`injector.InitializeApp()`方法统一初始化整个应用。

## 快速开始

### 环境要求

- Go 1.24或更高版本
- SQLite

### 安装步骤

### 1. 安装依赖

```bash
# 确保在项目根目录下
cd ~\github.com\featx\keys-gin
# 安装依赖
go mod tidy
```

### 2. 运行应用

```bash
# 在项目根目录下运行
go run main.go
```

### 3. API接口

#### 密钥对相关接口

- **生成密钥对**
  - POST `/api/v1/keys`
  - 参数: `{"user_id": "user123", "chain_type": "ethereum"}`

- **获取用户密钥对列表**
  - GET `/api/v1/keys/user/{userID}`

- **根据ID获取密钥对**
  - GET `/api/v1/keys/{id}`

- **根据地址获取密钥对**
  - GET `/api/v1/keys/address/{address}`

#### 交易相关接口

- **签名交易**
  - POST `/api/v1/transactions/sign`
  - 参数: `{"key_pair_id": 1, "raw_tx": "{...}"}`

- **获取用户交易列表**
  - GET `/api/v1/transactions/user/{userID}`

- **根据哈希获取交易**
  - GET `/api/v1/transactions/{hash}`

- **更新交易状态**
  - PUT `/api/v1/transactions/{hash}/status`
  - 参数: `{"status": "completed"}`

## 配置说明

配置文件位于 `config/config.yaml`，包含以下主要配置项：

- `server`: 服务器配置（端口、主机）
- `database`: 数据库配置（驱动、连接字符串等）
- `crypto`: 加密配置（密钥派生、迭代次数等）
- `logging`: 日志配置（级别、格式、文件路径等）

## 注意事项

- 本项目中的私钥存储在数据库中，仅用于演示目的
- 在生产环境中，应考虑使用更安全的方式存储私钥，如硬件安全模块(HSM)或密钥管理服务(KMS)
- 建议启用HTTPS以保护API通信安全
- 比特币地址生成和交易签名逻辑进行了简化，在实际应用中需要使用完整的比特币SDK

## License

MIT