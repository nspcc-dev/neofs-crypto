// +build !go1.15

package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_decompressPoints(t *testing.T) {
	t.Run("prepared public keys: decompressPoints", func(t *testing.T) {
		for i := range testKeys {
			bytes, err := hex.DecodeString(testKeys[i])
			require.NoErrorf(t, err, testKeys[i])

			x, y := decompressPoints(new(big.Int).SetBytes(bytes[1:]), uint(bytes[0]))
			require.NotNil(t, x)
			require.NotNil(t, y)

			res := MarshalPublicKey(&ecdsa.PublicKey{Curve: curve, X: x, Y: y})
			require.Equal(t, testKeys[i], hex.EncodeToString(res))
		}
	})
}
