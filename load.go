package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"os"

	"github.com/pkg/errors"
)

// LoadPrivateKey allows to load private key from various formats:
// - wif string
// - hex string
// - file path (D-bytes or SEC 1 / ASN.1 DER form)
func LoadPrivateKey(val string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(val); err == nil {
		return UnmarshalPrivateKey(data)
	} else if data, err = hex.DecodeString(val); err == nil {
		return UnmarshalPrivateKey(data)
	} else if key, err := WIFDecode(val); err == nil {
		return key, nil
	}

	return nil, errors.Errorf("unknown key format (%q), expect: hex-string, wif or file-path", val)
}
