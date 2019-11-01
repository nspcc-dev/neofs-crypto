package multisig

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
)

type (
	// PrivateKey is a generic type for private key.
	PrivateKey = kyber.Scalar
	// PublicKey is a generic type for public key.
	PublicKey = kyber.Point
)

var suite = bn256.NewSuite()

// GenerateKey returns random key pair.
func GenerateKey() (PrivateKey, PublicKey) {
	return bls.NewKeyPair(suite, random.New())
}

// Sign returns message signature.
func Sign(key PrivateKey, msg []byte) ([]byte, error) {
	return bls.Sign(suite, key, msg)
}

// Verify checks if sig is msg signature.
func Verify(pub PublicKey, msg, sig []byte) error {
	return bls.Verify(suite, pub, msg, sig)
}

// AggregateSignatures returns aggregated signature
// which can be checked with aggregated public key.
func AggregateSignatures(sigs ...[]byte) ([]byte, error) {
	return bls.AggregateSignatures(suite, sigs...)
}

// AggregatePublicKeys returns aggregated public key.
func AggregatePublicKeys(pubs ...PublicKey) PublicKey {
	return bls.AggregatePublicKeys(suite, pubs...)
}
