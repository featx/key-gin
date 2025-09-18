package config

import (
	"github.com/spf13/viper"
)

// Config 全局配置结构
var Config *Configuration

// Configuration 配置结构体
type Configuration struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Crypto   CryptoConfig   `mapstructure:"crypto"`
	Logging  LoggingConfig  `mapstructure:"logging"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port int    `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Driver          string `mapstructure:"driver"`
	Source          string `mapstructure:"source"`
	ShowSQL         bool   `mapstructure:"show_sql"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetime string `mapstructure:"conn_max_lifetime"`
}

// CryptoConfig 加密配置
type CryptoConfig struct {
	KeyDerivation    string `mapstructure:"key_derivation"`
	Iterations       int    `mapstructure:"iterations"`
	SaltLength       int    `mapstructure:"salt_length"`
	KeyLength        int    `mapstructure:"key_length"`
	AESGCMNonceLength int   `mapstructure:"aes_gcm_nonce_length"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"`
}

// Init 初始化配置
func Init(configPath string) error {
	viper.SetConfigFile(configPath)
	viper.AutomaticEnv()

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	// 解析配置到结构体
	var config Configuration
	if err := viper.Unmarshal(&config); err != nil {
		return err
	}

	Config = &config
	return nil
}