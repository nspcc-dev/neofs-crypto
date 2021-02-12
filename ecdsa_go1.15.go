// +build go1.15

package crypto

import (
	"crypto/elliptic"
	"math/big"
)

func encodePoint(x, y *big.Int) []byte {
	return elliptic.MarshalCompressed(curve, x, y)
}

func decodePoint(data []byte) (x *big.Int, y *big.Int) {
	// empty data
	if len(data) == 0 {
		return
	}

	// tries to unmarshal compressed form
	// returns (nil, nil) when:
	// - wrong len(data)
	// - data[0] != 2 && data[0] != 3
	if x, y = elliptic.UnmarshalCompressed(curve, data); x != nil && y != nil {
		return x, y
	}

	// tries to unmarshal uncompressed form and check that points on curve
	if x, y = unmarshalXY(data); x == nil || y == nil || !curve.IsOnCurve(x, y) {
		x, y = nil, nil
	}

	return x, y
}
