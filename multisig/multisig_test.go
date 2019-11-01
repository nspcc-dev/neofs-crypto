package multisig

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	priv, pub := GenerateKey()
	msg := randBuffer(t, 100)

	sig, err := Sign(priv, msg)
	require.NoError(t, err)
	require.NotNil(t, sig)

	err = Verify(pub, msg, sig)
	require.NoError(t, err)

	sig[0] = ^sig[0]
	err = Verify(pub, msg, sig)
	require.Error(t, err)
}

func TestAggregateSignatures(t *testing.T) {
	priv1, pub1 := GenerateKey()
	priv2, pub2 := GenerateKey()

	require.NotEqual(t, pub1, pub2)

	msg := randBuffer(t, 100)

	sig1, err := Sign(priv1, msg)
	require.NoError(t, err)
	require.NotNil(t, sig1)

	sig2, err := Sign(priv2, msg)
	require.NoError(t, err)
	require.NotNil(t, sig2)

	sig, err := AggregateSignatures(sig1, sig2)
	require.NoError(t, err)
	require.NotNil(t, sig)

	pub := AggregatePublicKeys(pub1, pub2)
	err = Verify(pub, msg, sig)
	require.NoError(t, err)

	sig[0] = ^sig[0]
	err = Verify(pub, msg, sig)
	require.Error(t, err)
}

func randBuffer(t *testing.T, n int) []byte {
	data := make([]byte, n)
	_, err := rand.Read(data)
	require.NoError(t, err)

	return data
}
