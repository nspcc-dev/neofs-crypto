package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/nspcc-dev/neofs-crypto/test"
	"github.com/stretchr/testify/require"
)

var (
	rfc6979Data = "1f2155c0e513a7dab93d8b468809cd30a03c62326ec051deed031a6c6fbbdf" +
		"02ca351745fa86b9ba5a9452d785ac4f7fc2b7548ca2a46c4fcf4a0000000053724e000000000000001e61"

	rfc6979Signatures = "03012d47e76210aec73be39ab3d186e0a40fe8d86bfa3d4fabfda57ba13b88f96a" +
		"e6e87810285bdcba714b5c7a38ca32a3759f3b6d10b3ae69a3e33a444dd7a0f5025a730e07a81170e89124a8115d10bf29446b4a09280e567fca4f27a6d0fcd8" +
		"e6e87810285bdcba714b5c7a38ca32a3759f3b6d10b3ae69a3e33a444dd7a0f5025a730e07a81170e89124a8115d10bf29446b4a09280e567fca4f27a6d0fcd8" +
		"02f7528ce97c9a93558efe7d4f62577aabdf771c931f54a71be6ad21e7d9cc1777" +
		"63efa21e48c3f56f9c8b1c7b24fa8141a4dd33cc12ae5d0bc2c885c628b2eb5b96aa1d7514e343c2221a49a8664415f1944452560bab13ff14ff3c6549da0665" +
		"63efa21e48c3f56f9c8b1c7b24fa8141a4dd33cc12ae5d0bc2c885c628b2eb5b6955e289eb1cbc3edde5b65799bbea0e28a2a8579b6c8a85deba8e5db2891eec" +
		"023e00f03a16e8707ce045eb42ee80d392451541ee510dc18e1c8befbac54d7426" +
		"314e2f2adaaf67908aba6cb1183376574f27c1cafad5d8d852169f5adb26a6ac52641096d9051cdcd91e02420a0643827af535f25d8a9dafe4c5a00554a412ed" +
		"314e2f2adaaf67908aba6cb1183376574f27c1cafad5d8d852169f5adb26a6ac52641096d9051cdcd91e02420a0643827af535f25d8a9dafe4c5a00554a412ed" +
		"0340750b92789821683283bcb98e32b7e032b94f267b6964613fc31a7ce5813fdd" +
		"9e155d31ba033d0637b03d9820c9312709376ab5d7f0a3b08392e47a5807bb76182f7add86b60723e120b25677626f3ab78fe04ed00ae0bb86503d8312c6d0bd" +
		"9e155d31ba033d0637b03d9820c9312709376ab5d7f0a3b08392e47a5807bb76182f7add86b60723e120b25677626f3ab78fe04ed00ae0bb86503d8312c6d0bd" +
		"03fef27f744e829131d0ec980829fafa51db1714c2761d9f78762c008c323e9d66" +
		"f2de56e0777506fa52c19166706856794152a65e75a29dc6fc8a011d2abe1233c8e5e807a3d6b932e92ff91338755136446c57c9ec27df7eec04165e8ae38536" +
		"f2de56e0777506fa52c19166706856794152a65e75a29dc6fc8a011d2abe1233371a17f75c2946ce16d006ecc78aaec9787aa2e3baefbf0607b5b464717fa01b" +
		"0368a6f5829fb2a34fa03d0308ae6b05f433f2904d9a852fed1f5d2eb598ca7947" +
		"9595d09ad84355e2c19ca5f08c19b9492816add735c7e01e549902f04b2c9d1ad7ea131a5e19ae325fffe5a4027383ff2132815c633abf318c2dc170890afc52" +
		"9595d09ad84355e2c19ca5f08c19b9492816add735c7e01e549902f04b2c9d1a2815ece4a1e651cea0001a5bfd8c7c009bb4795143dcdf53678c0952735828ff"

	keys = []string{
		"L3o221BojgcCPYgdbXsm6jn7ayTZ72xwREvBHXKknR8VJ3G4WmjB",
		"KxLBJgapF8FucHptTm49BaW7wMmQGq97mdeYSnyDmVd39SCFxjBc",
		"Kyf6PExBaDHbYwmV7HAwaiqJM2x7wBqLHZrZqdKvF2RQsmDRfXgG",
		"KwMWwRYN72vFFV2pjTv9XrWz3tKCvANZQ5BHSKkGCBS5UdKeGTEG",
		"L4b9sjSbxfwJPUX9ESPV3LAU9PwLwrAuthVEpGc43Pm9ELtpky3b",
		"KyCQQ1LHNYsUQ2ZkD6yQry3hnMUWMvrbk9dHKBwq9ogGXippznKs",
	}
)

func TestRFC6979(t *testing.T) {
	body, err := hex.DecodeString(rfc6979Data)
	require.NoError(t, err)

	data, err := hex.DecodeString(rfc6979Signatures)
	require.NoError(t, err)

	var offset int

	for i := 0; i < 6; i++ {
		key, err := WIFDecode(keys[i])
		require.NoError(t, err)

		pub := UnmarshalPublicKey(data[offset : offset+PublicKeyCompressedSize])
		offset += PublicKeyCompressedSize

		require.NotNilf(t, pub, "step: %d", i)
		require.Equal(t, &key.PublicKey, pub)

		{ // Generated by Go
			sig := data[offset : offset+RFC6979SignatureSize]

			{ // SignRFC6979
				res, err := SignRFC6979(key, body)
				require.NoError(t, err)

				require.Equal(t, sig, res, "step: %d, %02x", i, res)

				require.NoErrorf(t, VerifyRFC6979(pub, body, sig), "step: %d", i)
			}
			{ // SignRFC6979Hash
				sum := sha256.Sum256(body)
				res, err := SignRFC6979Hash(key, sum[:])
				require.NoError(t, err)

				require.Equal(t, sig, res, "step: %d, %02x", i, res)

				require.NoErrorf(t, VerifyRFC6979Hash(pub, sum[:], sig), "step: %d", i)
			}
			offset += RFC6979SignatureSize
		}

		{ // Generated by Python
			sig := data[offset : offset+RFC6979SignatureSize]

			// It's not equals in Python and Go:
			// require.Equal(t, sig, res, "step: %d, %02x", i, res)

			require.NoErrorf(t, VerifyRFC6979(pub, body, sig), "step: %d", i)

			offset += RFC6979SignatureSize
		}
	}
}

func TestRFC6979_ShortDecodePoints(t *testing.T) {
	key := test.DecodeKey(1)

	msgs := []string{
		"6341922933e156ea5a53b8ea3fa4a80c", // this msg has 31 byte `s` point
		"61b863d81f72e0e0d0353b1cb90d62ce", // this msg has 31 byte 'r' point
	}

	for i := range msgs {
		msg, err := hex.DecodeString(msgs[i])
		require.NoError(t, err)

		signature, err := SignRFC6979(key, msg)
		require.NoError(t, err, msgs[i])

		err = VerifyRFC6979(&key.PublicKey, msg, signature)
		require.NoError(t, err, msgs[i])
	}
}
