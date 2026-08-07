//===----------------------------------------------------------------------===//
//
// Pure Swift Curve25519 adapters for the CryptoKit-compatible facade.
//
// The facade keeps only validated key bytes. SSLCrypto's noncopyable key
// owner is constructed inside a synchronous borrow and never escapes it.
// This keeps key lifetime and secret wiping in the SSLCrypto layer while
// preserving CryptoKit's value-oriented API.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

@_spi(PureSwiftCrypto) import SSLCrypto

private func withOwnedByteSpan<Result: ~Copyable>(
    _ bytes: [UInt8],
    _ body: (Span<UInt8>) throws -> Result
) rethrows -> Result {
    // Unsafe boundary invariants:
    // - The allocation owns exactly bytes.count initialized UInt8 values.
    // - The span is borrowed only for the synchronous body call.
    // - The pointer never escapes and is erased before deallocation.
    let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: bytes.count)
    pointer.initialize(from: bytes, count: bytes.count)
    defer {
        UnsafeMutableRawBufferPointer(start: pointer, count: bytes.count).zeroize()
        pointer.deinitialize(count: bytes.count)
        pointer.deallocate()
    }
    let span = Span(_unsafeStart: pointer, count: bytes.count)
    return try body(span)
}

extension Curve25519.KeyAgreement {
    @usableFromInline
    static let keySizeBytes = 32

    @usableFromInline
    struct SSLCryptoCurve25519PublicKeyImpl: Sendable {
        @usableFromInline var keyBytes: [UInt8]

        @inlinable
        init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitError) {
            let bytes = rawRepresentation.withUnsafeBytes { Array($0) }
            guard bytes.count == Curve25519.KeyAgreement.keySizeBytes else { throw .incorrectKeySize }
            keyBytes = bytes
        }

        @usableFromInline init(_ keyBytes: [UInt8]) {
            precondition(keyBytes.count == Curve25519.KeyAgreement.keySizeBytes)
            self.keyBytes = keyBytes
        }

        @usableFromInline var rawRepresentation: Data { Data(keyBytes) }
    }

    @usableFromInline
    struct SSLCryptoCurve25519PrivateKeyImpl: Sendable {
        var key: SecureBytes
        @usableFromInline var publicKey: SSLCryptoCurve25519PublicKeyImpl

        init() {
            do {
                let generated = try SSLCrypto.X25519PrivateKey.generate()
                let privateBytes = generated.withBorrowedBytes { bytes in
                    bytes.withUnsafeBytes { rawBytes in
                        SecureBytes(bytes: rawBytes.bytes)
                    }
                }
                let generatedPublicKey = generated.publicKey()
                let publicBytes = generatedPublicKey.withBorrowedBytes { bytes in
                    bytes.withUnsafeBytes { Array($0) }
                }
                key = privateBytes
                publicKey = SSLCryptoCurve25519PublicKeyImpl(publicBytes)
            } catch {
                preconditionFailure("Unable to generate an X25519 private key: \(error)")
            }
        }

        init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitError) {
            let bytes = rawRepresentation.withUnsafeBytes { Array($0) }
            guard bytes.count == Curve25519.KeyAgreement.keySizeBytes else { throw .incorrectKeySize }
            do {
                let generated = try withOwnedByteSpan(bytes) { span in
                    try SSLCrypto.X25519PrivateKey(bytes: span)
                }
                key = SecureBytes(bytes: bytes)
                let generatedPublicKey = generated.publicKey()
                publicKey = SSLCryptoCurve25519PublicKeyImpl(
                    generatedPublicKey.withBorrowedBytes { Array(copying: $0.bytes) }
                )
            } catch {
                throw .incorrectKeySize
            }
        }

        func sharedSecretFromKeyAgreement(
            with publicKeyShare: SSLCryptoCurve25519PublicKeyImpl
        ) throws(CryptoKitMetaError) -> SharedSecret {
            do {
                return try key.withUnsafeBytes { privateBytes in
                    let privateKey = try SSLCrypto.X25519PrivateKey(
                        bytes: Span(_unsafeElements: privateBytes.bindMemory(to: UInt8.self))
                    )
                    let publicKey = try withOwnedByteSpan(publicKeyShare.keyBytes) { span in
                        try SSLCrypto.X25519PublicKey(bytes: span)
                    }
                    let secret = try SSLCrypto.X25519.sharedSecret(
                        privateKey: privateKey,
                        peerPublicKey: publicKey
                    )
                    let copiedSecret = secret.withBorrowedBytes { bytes in
                        bytes.withUnsafeBytes { rawBytes in
                            SecureBytes(bytes: rawBytes.bytes)
                        }
                    }
                    return SharedSecret(ss: copiedSecret)
                }
            } catch let error as CryptoInputError {
                switch error {
                case .invalidLength: throw CryptoKitError.incorrectParameterSize
                case .invalidPeerKey: throw CryptoKitError.invalidParameter
                default: throw CryptoKitError.invalidParameter
                }
            } catch {
                throw error
            }
        }

        @usableFromInline var rawRepresentation: Data { Data(key) }

        static func validateX25519PrivateKeyData(rawRepresentation: UnsafeRawBufferPointer) throws(CryptoKitError) {
            guard rawRepresentation.count == Curve25519.KeyAgreement.keySizeBytes else { throw .incorrectKeySize }
        }
    }
}

extension Curve25519.Signing {
    @usableFromInline
    struct SSLCryptoCurve25519SigningPrivateKeyImpl: Sendable {
        var _privateKey: SecureBytes
        @usableFromInline var _publicKey: [UInt8]

        @usableFromInline
        init() {
            do {
                let seed = SecureBytes(count: 32)
                // The generated key owns a copied seed; the facade retains the
                // original SecureBytes as its exactly-once wiping owner.
                let seedCopy = Array(seed)
                let key = try withOwnedByteSpan(seedCopy) { span in
                    try SSLCrypto.Ed25519PrivateKey(seed: span)
                }
                _privateKey = seed
                _publicKey = Array(try key.publicKey())
            } catch {
                preconditionFailure("Unable to generate an Ed25519 private key")
            }
        }

        @usableFromInline
        init<D: ContiguousBytes>(rawRepresentation data: D) throws(CryptoKitError) {
            let seed = data.withUnsafeBytes { Array($0) }
            guard seed.count == 32 else { throw .incorrectKeySize }
            do {
                let key = try withOwnedByteSpan(seed) { span in
                    try SSLCrypto.Ed25519PrivateKey(seed: span)
                }
                _privateKey = SecureBytes(bytes: seed)
                _publicKey = Array(try key.publicKey())
            } catch {
                throw .incorrectKeySize
            }
        }

        @usableFromInline
        var publicKey: SSLCryptoCurve25519SigningPublicKeyImpl {
            SSLCryptoCurve25519SigningPublicKeyImpl(_publicKey)
        }

        var key: SecureBytes { _privateKey }
        @usableFromInline var rawRepresentation: Data { Data(_privateKey.prefix(32)) }

        func sign(message: Span<UInt8>) throws(CryptoKitMetaError) -> Data {
            do {
                assert(message.count == 0 || message.count > 0)
                return try _privateKey.withUnsafeBytes { seed in
                    let privateKey = try SSLCrypto.Ed25519PrivateKey(
                        seed: Span(_unsafeElements: seed.bindMemory(to: UInt8.self))
                    )
                    return try withOwnedByteSpan(_publicKey) { publicKey in
                        Data(try privateKey.sign(
                            message: message,
                            precomputedPublicKey: publicKey
                        ))
                    }
                }
            } catch is CryptoInputError {
                throw CryptoKitError.invalidParameter
            } catch {
                throw error
            }
        }
    }

    @usableFromInline
    struct SSLCryptoCurve25519SigningPublicKeyImpl: Sendable {
        @usableFromInline var keyBytes: [UInt8]
        @usableFromInline var validatedKey: SSLCrypto.Ed25519PublicKey?

        init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitError) {
            let bytes = rawRepresentation.withUnsafeBytes { Array($0) }
            guard bytes.count == 32 else { throw .incorrectKeySize }
            keyBytes = bytes
            do {
                validatedKey = try withOwnedByteSpan(bytes) { span in
                    try SSLCrypto.Ed25519PublicKey(bytes: span)
                }
            } catch {
                // CryptoKit accepts any correctly sized Ed25519 public-key
                // representation. Invalid point encodings fail verification.
                validatedKey = nil
            }
        }

        @usableFromInline init(_ keyBytes: [UInt8]) {
            precondition(keyBytes.count == 32)
            self.keyBytes = keyBytes
            do {
                validatedKey = try withOwnedByteSpan(keyBytes) { span in
                    try SSLCrypto.Ed25519PublicKey(bytes: span)
                }
            } catch {
                preconditionFailure("Derived Ed25519 public key is invalid")
            }
        }

        var rawRepresentation: Data { Data(keyBytes) }

        func isValidSignature(signature: Span<UInt8>, message: Span<UInt8>) -> Bool {
            guard let validatedKey else { return false }
            do {
                return try SSLCrypto.Ed25519.verify(
                    signature: signature,
                    message: message,
                    using: validatedKey
                )
            } catch {
                return false
            }
        }
    }
}

private func withSSLCryptoDataSpan<D: DataProtocol, Result>(
    _ data: D,
    _ body: (Span<UInt8>) throws -> Result
) rethrows -> Result {
    if data.regions.count == 1, let region = data.regions.first {
        return try region.withUnsafeBytes { raw in
            try body(Span(_unsafeElements: raw.bindMemory(to: UInt8.self)))
        }
    }
    var contiguous = Data()
    contiguous.reserveCapacity(data.count)
    for region in data.regions { region.withUnsafeBytes { contiguous.append(contentsOf: $0) } }
    return try contiguous.withUnsafeBytes { raw in
        try body(Span(_unsafeElements: raw.bindMemory(to: UInt8.self)))
    }
}

extension Curve25519.Signing.PublicKey {
    public func isValidSignature<S: DataProtocol, D: DataProtocol>(
        _ signature: S,
        for data: D
    ) -> Bool {
        guard signature.count == 64 else { return false }
        return withSSLCryptoDataSpan(signature) { signatureSpan in
            withSSLCryptoDataSpan(data) { dataSpan in
                self.baseKey.isValidSignature(signature: signatureSpan, message: dataSpan)
            }
        }
    }
}

extension Curve25519.Signing.PublicKey: DataValidator {
    typealias Signature = Data
}

extension Curve25519.Signing.PrivateKey: Signer {}

extension Curve25519.Signing.PrivateKey {
    public func signature<D: DataProtocol>(for data: D) throws(CryptoKitMetaError) -> Data {
        do {
            return try withSSLCryptoDataSpan(data) { message in
                try self.baseKey.sign(message: message)
            }
        } catch {
            throw error
        }
    }
}

#endif
