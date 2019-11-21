package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"io/ioutil"

	"github.com/pkg/errors"
)

func LoadPrivateKey(val string) (*ecdsa.PrivateKey, error) {
	if data, err := ioutil.ReadFile(val); err == nil {
		return UnmarshalPrivateKey(data)
	} else if data, err = hex.DecodeString(val); err == nil {
		return UnmarshalPrivateKey(data)
	} else if key, err := WIFDecode(val); err == nil {
		return key, nil
	}

	return nil, errors.Errorf("unknown key format (%q), expect: hex-string, wif or file-path", val)
}
