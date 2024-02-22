# NeoFS Crypto library

**¡Atención! This library is deprecated and no longer supported.**

For WIF, key management and RFC6979 signatures please refer to
[github.com/nspcc-dev/neo-go/pkg/crypto/keys](https://pkg.go.dev/github.com/nspcc-dev/neo-go/pkg/crypto/keys)
and [github.com/nspcc-dev/rfc6979](https://pkg.go.dev/github.com/nspcc-dev/rfc6979).
For NeoFS-specific signatures with SHA-512 hashes use
[github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa](https://pkg.go.dev/github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa).

This package contained useful methods to work with crypto-primitives used in NeoFS/Neo.

## Examples

### Simple Marshal / Unmarshal ECDSA public key (PK):

```
// returns slice of 33 bytes marshaled public key
data := crypto.MarshalPublicKey(&sk.PublicKey)

// returns public key decoded from 33 bytes    
pk := crypto.UnmarshalPublicKey(data)
```

### Simple Marshal / Unmarshal ECDSA private key (SK):

```
// returns slice of 32 bytes marshaled private key
data := crypto.MarshalPrivateKey(&sk)

// returns private key decoded from 32 bytes or error,
// if something whet wrong    
newSk, err := crypto.UnmarshalPrivateKey(data)
```

### ECDSA Sign / Verify bytes using PK / SK

```
// Sign returns signature (slice of 65 bytes) of SK for passed message (slice of bytes),
// or error, if something went wrong:
signature, err := crypto.Sign(sk, message)

// Verify returns error message if PK is empty or
// passed wrong signature (slice of 65 bytes) for message (slice of bytes),
err := crypto.Verify(&sk.PublicKey, signature, message)  
```

### RFC6979 Sign / Verify bytes using PK / SK

```
// Sign returns signature (slice of 64 bytes) of SK for passed message (slice of bytes),
// or error, if something went wrong:
signature, err := crypto.SignRFC6979(sk, message)

// Verify returns error message if PK is empty or
// passed wrong signature (slice of 64 bytes) for message (slice of bytes),
err := crypto.VerifyRFC6979(&sk.PublicKey, signature, message)  
```

### WIF Encode / Decode private key (SK)

```
// WIFEncode encodes the given private key into a WIF string.
// if sk or sk.D is empty, returns error
wif, err := crypto.WIFEncode(sk)

// WIFDecode decoded the given WIF string into a private key.
// if something went wrong, returns error:
skFromWIF, err := crypto.WIFDecode(wif)
```

### LoadPrivateKey

```
// Load private key from wif format
sk, err := crypto.LoadPrivateKey(wif_string)

// Load private key from hex string
sk, err := crypto.LoadPrivateKey(hex_string)

// Load private key from file
sk, err := crypto.LoadPrivateKey(file_path)
```
