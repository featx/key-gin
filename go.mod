module github.com/featx/keys-gin

go 1.24

require (
	github.com/btcsuite/btcd v0.24.0
	github.com/ethereum/go-ethereum v1.13.5
	github.com/gin-gonic/gin v1.10.0
	github.com/google/wire v0.5.0
	github.com/spf13/viper v1.18.2
	golang.org/x/crypto v0.23.0
	golang.org/x/net v0.25.0
	golang.org/x/text v0.15.0
	xorm.io/xorm v1.3.3
)

// SQLite3依赖已被注释掉，因为我们现在使用MySQL
// replace github.com/mattn/go-sqlite3 => github.com/mattn/go-sqlite3 v1.14.16
