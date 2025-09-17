package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/katuyo/goals/internal/service"
)

// TransactionHandler 交易处理器
type TransactionHandler struct {
	transactionService *service.TransactionService
}

// NewTransactionHandler 创建交易处理器
func NewTransactionHandler(transactionService *service.TransactionService) (*TransactionHandler, error) {
	return &TransactionHandler{
		transactionService: transactionService,
	},
	nil
}

// RegisterRoutes 注册路由
func (h *TransactionHandler) RegisterRoutes(router *gin.Engine) {
	txs := router.Group("/api/v1/transactions")
	{
		txs.POST("/sign", h.SignTransaction)
		txs.GET("/user/:userID", h.GetUserTransactions)
		txs.GET("/:hash", h.GetTransactionByHash)
		txs.PUT("/:hash/status", h.UpdateTransactionStatus)
	}
}

// SignTransactionRequest 签名交易请求参数
type SignTransactionRequest struct {
	KeyPairID int64  `json:"key_pair_id" binding:"required"`
	RawTx     string `json:"raw_tx" binding:"required"`
}

// SignTransaction 处理交易签名请求
func (h *TransactionHandler) SignTransaction(c *gin.Context) {
	var req SignTransactionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	transaction, err := h.transactionService.SignTransaction(req.KeyPairID, req.RawTx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, transaction)
}

// GetUserTransactions 处理获取用户交易列表请求
func (h *TransactionHandler) GetUserTransactions(c *gin.Context) {
	userID := c.Param("userID")

	transactions, err := h.transactionService.GetUserTransactions(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, transactions)
}

// GetTransactionByHash 处理根据哈希获取交易请求
func (h *TransactionHandler) GetTransactionByHash(c *gin.Context) {
	txHash := c.Param("hash")

	transaction, err := h.transactionService.GetTransactionByHash(txHash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, transaction)
}

// UpdateTransactionStatusRequest 更新交易状态请求参数
type UpdateTransactionStatusRequest struct {
	Status string `json:"status" binding:"required"`
}

// UpdateTransactionStatus 处理更新交易状态请求
func (h *TransactionHandler) UpdateTransactionStatus(c *gin.Context) {
	txHash := c.Param("hash")

	var req UpdateTransactionStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.transactionService.UpdateTransactionStatus(txHash, req.Status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Transaction status updated"})
}