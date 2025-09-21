package crypto

import (
	"testing"

	"github.com/featx/keys-gin/web/model"
	"github.com/stretchr/testify/assert"
)

func TestNewTransactionSigner(t *testing.T) {
	// 测试各种链类型的签名器创建
	testCases := []struct {
		chainType      string
		expectedType   interface{}
		expectError    bool
	}{{
		chainType:      model.ChainTypeETH,
		expectedType:   &EthTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypeBSC,
		expectedType:   &EthTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypePolygon,
		expectedType:   &EthTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypeAvalanche,
		expectedType:   &EthTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypeBTC,
		expectedType:   &BtcTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypeSolana,
		expectedType:   &SolanaTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypeTRON,
		expectedType:   &TronTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypeSUI,
		expectedType:   &SuiTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypeADA,
		expectedType:   &AdaTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypePolkadot,
		expectedType:   &PolkadotTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypeKusama,
		expectedType:   &PolkadotTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      model.ChainTypeTON,
		expectedType:   &TonTransactionSigner{},
		expectError:    false,
	}, {
		chainType:      "unsupported_chain",
		expectedType:   nil,
		expectError:    true,
	}}

	for _, tc := range testCases {
		signer, err := NewTransactionSigner(tc.chainType)
		
		if tc.expectError {
			assert.Error(t, err)
			assert.Nil(t, signer)
		} else {
			assert.NoError(t, err)
			assert.NotNil(t, signer)
			assert.IsType(t, tc.expectedType, signer)
			
			// 特别检查Polkadot和Kusama的IsKusama字段
			if tc.chainType == model.ChainTypePolkadot {
				polkadotSigner := signer.(*PolkadotTransactionSigner)
				assert.False(t, polkadotSigner.IsKusama)
			} else if tc.chainType == model.ChainTypeKusama {
				kusamaSigner := signer.(*PolkadotTransactionSigner)
				assert.True(t, kusamaSigner.IsKusama)
			}
		}
	}
}