//go:build wireinject
// +build wireinject

package injector

import (
	github.com/google/wire
	github.com/gin-gonic/gin
	github.com/featx/keys-gin/internal/db
	github.com/featx/keys-gin/internal/handler
	github.com/featx/keys-gin/internal/service
)

// InitializeApp 初始化应用程序，提供依赖注入
func InitializeApp() (*gin.Engine, error) {
	wire.Build(
		db.GetEngine,
		service.NewKeyService,
		service.NewTransactionService,
		handler.NewKeyHandler,
		handler.NewTransactionHandler,
		ProvideRouter,
	)
	return nil, nil
}

// ProvideRouter 创建并配置Gin路由器
func ProvideRouter(
	keyHandler *handler.KeyHandler,
	transactionHandler *handler.TransactionHandler,
) *gin.Engine {
	router := gin.Default()
	
	// 注册路由
	keyHandler.RegisterRoutes(router)
	transactionHandler.RegisterRoutes(router)
	
	// 添加健康检查端点
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	
	return router
}