package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"

	"github.com/nspcc-dev/neofs-crypto/internal"
	"github.com/nspcc-dev/rfc6979"
	"github.com/pkg/errors"
)

const (
	// RFC6979SignatureSize contains r and s coordinates (32 bytes)
	RFC6979SignatureSize = 64

	// ErrWrongHashSize when passed signature to VerifyRFC6979 has wrong size.
	ErrWrongHashSize = internal.Error("wrong hash size")

	// ErrWrongSignature when passed signature to VerifyRFC6979 isn't valid.
	ErrWrongSignature = internal.Error("wrong signature")
)

// hashBytesRFC6979 returns the sha256 sum.
func hashBytesRFC6979(data []byte) []byte {
	sign := sha256.Sum256(data)
	return sign[:]
}

// SignRFC6979 signs an arbitrary length hash (which should be the result of
// hashing a larger message) using the private key. It returns the
// signature as a pair of integers.
//
// Note that FIPS 186-3 section 4.6 specifies that the hash should be truncated
// to the byte-length of the subgroup. This function does not perform that.
func SignRFC6979(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	r, s, err := rfc6979.SignECDSA(key, hashBytesRFC6979(msg), sha256.New)
	if err != nil {
		return nil, err
	}

	return append(r.Bytes(), s.Bytes()...), nil
}

func decodeSignature(sig []byte) (*big.Int, *big.Int, error) {
	if ln := len(sig); ln != RFC6979SignatureSize {
		return nil, nil, errors.Wrapf(ErrWrongHashSize, "actual=%d, expect=%d", ln, RFC6979SignatureSize)
	}

	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]), nil
}

// VerifyRFC6979 verifies the signature of msg using the public key. It
// return nil only if signature is valid.
func VerifyRFC6979(key *ecdsa.PublicKey, msg, sig []byte) error {
	if r, s, err := decodeSignature(sig); err != nil {
		return err
	} else if !ecdsa.Verify(key, hashBytesRFC6979(msg), r, s) {
		return ErrWrongSignature
	}

	return nil
}
