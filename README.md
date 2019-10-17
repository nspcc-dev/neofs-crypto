# NeoFS Crypto library

**This package contains useful methods to work with crypto-primitives, that used in NeoFS / NeoBlockchain.**

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
// Sign returns signature (slice of 65 bytes) of SK for passed message (slice of bytes),
// or error, if something went wrong:
signature, err := crypto.SignRFC6979(sk, message)

// Verify returns error message if PK is empty or
// passed wrong signature (slice of 65 bytes) for message (slice of bytes),
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
