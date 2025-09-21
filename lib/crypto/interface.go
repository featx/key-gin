package crypto

// TransactionSigner 交易签名器接口
type TransactionSigner interface {
	SignTransaction(rawTx, privateKey string) (signedTx string, txHash string, err error)
}