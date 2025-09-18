package db

import (
	"errors"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"xorm.io/xorm"
	"github.com/featx/keys-gin/web/model"
)

var (
	db *xorm.Engine
	// ErrDBNotInitialized 数据库未初始化错误
	ErrDBNotInitialized = errors.New("database not initialized")
)

// DatabaseConfig 数据库配置结构
// 这个结构需要和 web/config 包中的 DatabaseConfig 结构保持一致
// 用于打破循环导入

type DatabaseConfig struct {
	Driver          string `mapstructure:"driver"`
	Source          string `mapstructure:"source"`
	ShowSQL         bool   `mapstructure:"show_sql"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetime string `mapstructure:"conn_max_lifetime"`
}

// Init 初始化数据库连接
func Init(dbConfig DatabaseConfig) error {
	// 创建数据库引擎
	engine, err := xorm.NewEngine(dbConfig.Driver, dbConfig.Source)
	if err != nil {
		return fmt.Errorf("failed to create database engine: %w", err)
	}

	// 设置数据库参数
	engine.ShowSQL(dbConfig.ShowSQL)
	engine.SetMaxOpenConns(dbConfig.MaxOpenConns)
	engine.SetMaxIdleConns(dbConfig.MaxIdleConns)

	// 设置连接最大生命周期
	lifetime, err := time.ParseDuration(dbConfig.ConnMaxLifetime)
	if err != nil {
		// 如果解析失败，使用默认值
		lifetime = 30 * time.Minute
	}
	engine.SetConnMaxLifetime(lifetime)

	// 测试连接
	err = engine.Ping()
	if err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// 自动同步数据库表结构
	if err := syncTables(engine); err != nil {
		return fmt.Errorf("failed to sync database tables: %w", err)
	}
	db = engine
	return nil
}

// GetEngine 获取数据库引擎
func GetEngine() (*xorm.Engine, error) {
	if db == nil {
		return nil, ErrDBNotInitialized
	}
	return db, nil
}

// Close 关闭数据库连接
func Close() error {
	if db != nil {
		return db.Close()
	}
	return nil
}

// syncTables 同步数据库表结构
func syncTables(engine *xorm.Engine) error {
	tables := []interface{}{
		&model.PublicKey{},
		&model.Address{},
		&model.Transaction{},
	}

	for _, table := range tables {
		if err := engine.Sync(table); err != nil {
			return fmt.Errorf("failed to sync table %T: %w", table, err)
		}
	}

	return nil
}