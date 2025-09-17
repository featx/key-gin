package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/featx/keys-gin/internal/service"
)

// KeyHandler 密钥处理器
type KeyHandler struct {
	keyService *service.KeyService
}

// NewKeyHandler 创建密钥处理器
func NewKeyHandler(keyService *service.KeyService) (*KeyHandler, error) {
	return &KeyHandler{
		keyService: keyService,
	},
	nil
}

// RegisterRoutes 注册路由
func (h *KeyHandler) RegisterRoutes(router *gin.Engine) {
	keys := router.Group("/api/v1/keys")
	{
		keys.POST("", h.GenerateKeyPair)
		keys.GET("/user/:userID", h.GetUserKeyPairs)
		keys.GET("/:id", h.GetKeyPairByID)
		keys.GET("/address/:address", h.GetKeyPairByAddress)
	}
}

// GenerateKeyPairRequest 生成密钥对请求参数

type GenerateKeyPairRequest struct {
	UserID    string `json:"user_id" binding:"required"`
	ChainType string `json:"chain_type" binding:"required"`
}

// GenerateKeyPair 处理生成密钥对请求
func (h *KeyHandler) GenerateKeyPair(c *gin.Context) {
	var req GenerateKeyPairRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	keyPair, err := h.keyService.GenerateKeyPair(req.UserID, req.ChainType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, keyPair)
}

// GetUserKeyPairs 处理获取用户密钥对列表请求
func (h *KeyHandler) GetUserKeyPairs(c *gin.Context) {
	userID := c.Param("userID")

	keyPairs, err := h.keyService.GetUserKeyPairs(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, keyPairs)
}

// GetKeyPairByID 处理根据ID获取密钥对请求
func (h *KeyHandler) GetKeyPairByID(c *gin.Context) {
	id := c.Param("id")

	// 转换ID为int64
	var keyPairID int64
	if _, err := fmt.Sscanf(id, "%d", &keyPairID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key pair ID"})
		return
	}

	keyPair, err := h.keyService.GetKeyPairByID(keyPairID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, keyPair)
}

// GetKeyPairByAddress 处理根据地址获取密钥对请求
func (h *KeyHandler) GetKeyPairByAddress(c *gin.Context) {
	address := c.Param("address")

	keyPair, err := h.keyService.GetKeyPairByAddress(address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, keyPair)
}