// +build !go1.15

package crypto

import "math/big"

// decompressPoints using formula y² = x³ - 3x + b
// crypto/elliptic/elliptic.go:55
func decompressPoints(x *big.Int, yBit uint) (*big.Int, *big.Int) {
	params := curve.Params()

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, params.B)
	x3.Mod(x3, params.P)

	// y = √(x³ - 3x + b) mod p
	y := new(big.Int).ModSqrt(x3, params.P)

	// big.Int.Jacobi(a, b) can return nil
	if y == nil {
		return nil, nil
	}

	if y.Bit(0) != (yBit & 0x1) {
		y.Neg(y)
		y.Mod(y, params.P)
	}

	return x, y
}

func encodePoint(x, y *big.Int) []byte {
	data := make([]byte, PublicKeyCompressedSize)
	i := PublicKeyCompressedSize - len(x.Bytes())
	copy(data[i:], x.Bytes())

	if y.Bit(0) == 0x1 {
		data[0] = 0x3
	} else {
		data[0] = 0x2
	}

	return data
}

func decodePoint(data []byte) (x *big.Int, y *big.Int) {
	// empty data
	if len(data) == 0 {
		return
	}

	switch prefix := data[0]; prefix {
	case 0x02, 0x03: // compressed key
		// Incorrect length for compressed encoding
		if len(data) != PublicKeyCompressedSize {
			return nil, nil
		}

		x, y = decompressPoints(new(big.Int).SetBytes(data[1:]), uint(prefix))
	case 0x04: // uncompressed key
		// To get the public key, besides getting it from the data and checking,
		// we also must to check that the points are on an elliptic curve
		x, y = unmarshalXY(data)
	default: // unknown type
		return
	}

	if x == nil || y == nil || !curve.IsOnCurve(x, y) {
		x, y = nil, nil
	}

	return
}
