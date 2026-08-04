# ``Crypto``

Swift Crypto is the CryptoKit-shaped public facade for the Pure Swift
implementations in ``swift-ssl/SSLCrypto``.

The dependency direction is intentionally one-way:

```text
Consumer -> Crypto facade -> SSLCrypto -> Pure Swift algorithms
```

The facade owns API compatibility, representation validation, and typed errors.
SSLCrypto owns byte-level algorithms, scoped borrows, secret zeroization, and
target-independent storage. No alternate implementation is selected by this
package; all supported operations use the same Pure Swift path on every target.

## Topics

### Cryptographically secure hashes

- ``HashFunction``
- ``SHA512``
- ``SHA384``
- ``SHA256``

### Message authentication codes

- ``HMAC``
- ``SymmetricKey``
- ``SymmetricKeySize``

### Ciphers

- ``AES``
- ``ChaChaPoly``

### Public key cryptography

- ``Curve25519``
- ``P521``
- ``P384``
- ``P256``
- ``SharedSecret``
- ``HPKE``

### Key derivation functions

- ``HKDF``

### Errors

- ``CryptoKitError``
- ``CryptoKitASN1Error``

### Legacy algorithms

- ``Insecure``
