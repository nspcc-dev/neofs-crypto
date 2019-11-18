package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"math/big"

	"github.com/nspcc-dev/neofs-crypto/internal"
	"github.com/pkg/errors"
)

const (
	// ErrEmptyPublicKey when PK passed to Verify method is nil.
	ErrEmptyPublicKey = internal.Error("empty public key")

	// ErrInvalidSignature when signature passed to Verify method is mismatch.
	ErrInvalidSignature = internal.Error("invalid signature")

	// ErrCannotUnmarshal when signature ([]byte) passed to Verify method has wrong format
	// and cannot be parsed.
	ErrCannotUnmarshal = internal.Error("could not unmarshal signature")

	// PrivateKeyCompressedSize is constant with compressed size of private key (SK).
	// D coordinate stored, recover PK by formula x, y = curve.ScalarBaseMul(d,bytes).
	PrivateKeyCompressedSize = 32

	// PublicKeyCompressedSize is constant with compressed size of public key (PK).
	PublicKeyCompressedSize = 33

	// PublicKeyUncompressedSize is constant with uncompressed size of public key (PK).
	// First byte always should be 0x4 other 64 bytes is X and Y (32 bytes per coordinate).
	// 2 * 32 + 1
	PublicKeyUncompressedSize = 65
)

// P256 is base elliptic curve.
var curve = elliptic.P256()

// Marshal converts a points into the uncompressed form specified in section 4.3.6 of ANSI X9.62.
func marshalXY(x, y *big.Int) []byte {
	return elliptic.Marshal(curve, x, y)
}

// unmarshalXY converts a point, serialized by Marshal, into an x, y pair.
// It is an error if the point is not in uncompressed form.
// On error, x,y = nil.
// Unlike the original version of the code, we ignore that x or y not on the curve
// --------------
// It's copy-paste elliptic.Unmarshal(curve, data) stdlib function, without last line
// of code.
// Link - https://golang.org/pkg/crypto/elliptic/#Unmarshal
func unmarshalXY(data []byte) (x *big.Int, y *big.Int) {
	if len(data) != PublicKeyUncompressedSize {
		return
	} else if data[0] != 4 { // uncompressed form
		return
	}

	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1:PublicKeyCompressedSize])
	y = new(big.Int).SetBytes(data[PublicKeyCompressedSize:])

	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		x, y = nil, nil
	}

	return
}

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

func decodePoint(data []byte) (*big.Int, *big.Int) {
	// empty data
	if len(data) == 0 {
		return nil, nil
	}

	switch prefix := data[0]; prefix {
	case 0x02, 0x03: // compressed key
		// Incorrect length for compressed encoding
		if len(data) != PublicKeyCompressedSize {
			return nil, nil
		}

		return decompressPoints(new(big.Int).SetBytes(data[1:]), uint(prefix))
	case 0x04: // uncompressed key
		// To get the public key, besides getting it from the data and checking,
		// we also must to check that the points are on an elliptic curve
		return unmarshalXY(data)
	}

	// unknown type
	return nil, nil
}

// MarshalPublicKey to bytes.
func MarshalPublicKey(key *ecdsa.PublicKey) []byte {
	if key == nil || key.X == nil || key.Y == nil {
		return nil
	}

	return encodePoint(key.X, key.Y)
}

// UnmarshalPublicKey from bytes.
func UnmarshalPublicKey(data []byte) *ecdsa.PublicKey {
	if x, y := decodePoint(data); x != nil && y != nil && curve.IsOnCurve(x, y) {
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}
	}

	return nil
}

// UnmarshalPrivateKey from bytes.
// It is similar to `ecdsa.Generate()` but uses pre-defined big.Int and
// curve for NEO Blockchain (elliptic.P256)
// Link - https://golang.org/pkg/crypto/ecdsa/#GenerateKey
func UnmarshalPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	if len(data) == PrivateKeyCompressedSize { // todo: consider using only NEO blockchain private keys
		d := new(big.Int).SetBytes(data)
		priv := new(ecdsa.PrivateKey)
		priv.PublicKey.Curve = curve
		priv.D = d
		priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(data)

		return priv, nil
	}

	return x509.ParseECPrivateKey(data)
}

// MarshalPrivateKey to bytes.
func MarshalPrivateKey(key *ecdsa.PrivateKey) []byte {
	return key.D.Bytes()
}

// hashBytes returns the sha512 sum.
func hashBytes(data []byte) []byte {
	buf := sha512.Sum512(data)
	return buf[:]
}

// Verify verifies the signature of msg using the public key pub. It returns
// nil only if signature is valid.
func Verify(pub *ecdsa.PublicKey, msg, sig []byte) error {
	if r, s := unmarshalXY(sig); r == nil || s == nil {
		return ErrCannotUnmarshal
	} else if pub == nil {
		return ErrEmptyPublicKey
	} else if !ecdsa.Verify(pub, hashBytes(msg), r, s) {
		return errors.Wrapf(ErrInvalidSignature, "%0x : %0x", r, s)
	}

	return nil
}

// Sign signs a message using the private key. If the sha512 hash of msg
// is longer than the bit-length of the private key's curve order, the hash
// will be truncated to that length. It returns the signature as slice bytes.
// The security of the private key depends on the entropy of rand.
func Sign(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	x, y, err := ecdsa.Sign(rand.Reader, key, hashBytes(msg))
	if err != nil {
		return nil, err
	}

	return marshalXY(x, y), nil
}
