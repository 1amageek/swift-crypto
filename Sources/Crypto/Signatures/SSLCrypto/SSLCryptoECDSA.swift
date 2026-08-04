//===----------------------------------------------------------------------===//
//
// Pure Swift ECDSA adapters for the CryptoKit-compatible facade.
//
// Digest and key bytes are borrowed only inside the SSLCrypto operation. The
// facade materializes a signature because its public API owns `Data` values.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

import SSLCrypto

private func mapSSLCryptoECDSAError(_ error: CryptoInputError) -> CryptoKitError {
    switch error {
    case .invalidLength, .invalidOutputLength:
        return .incorrectParameterSize
    case .nonCanonicalEncoding, .invalidPeerKey, .invalidSignature, .invalidRange,
         .contextTooLong, .inputTooLong:
        return .invalidParameter
    }
}

extension P256.Signing.PrivateKey {
    internal func openSSLSignature<D: Digest>(
        for digest: D
    ) throws(CryptoKitMetaError) -> P256.Signing.ECDSASignature {
        do {
            let privateBytes = self.rawRepresentation
            let rawSignature = try privateBytes.withUnsafeBytes { privateRaw in
                let privateKey = try SSLCrypto.P256PrivateKey(
                    bytes: Span(_unsafeElements: privateRaw.bindMemory(to: UInt8.self))
                )
                return try digest.withUnsafeBytes { digestRaw in
                    try SSLCrypto.P256ECDSA.sign(
                        messageHash: Span(_unsafeElements: digestRaw.bindMemory(to: UInt8.self)),
                        using: privateKey
                    )
                }
            }
            return try P256.Signing.ECDSASignature(rawRepresentation: Data(rawSignature))
        } catch let error as CryptoInputError {
            throw mapSSLCryptoECDSAError(error)
        } catch let error as CryptoKitError {
            throw error
        } catch {
            throw error
        }
    }
}

extension P256.Signing.PublicKey {
    internal func openSSLIsValidSignature<D: Digest>(
        _ signature: P256.Signing.ECDSASignature,
        for digest: D
    ) -> Bool {
        do {
            let publicBytes = self.x963Representation
            return try publicBytes.withUnsafeBytes { publicRaw in
                let publicKey = try SSLCrypto.P256PublicKey(
                    bytes: Span(_unsafeElements: publicRaw.bindMemory(to: UInt8.self))
                )
                return try signature.rawRepresentation.withUnsafeBytes { signatureRaw in
                    try digest.withUnsafeBytes { digestRaw in
                        try SSLCrypto.P256ECDSA.verify(
                            signature: Span(_unsafeElements: signatureRaw.bindMemory(to: UInt8.self)),
                            messageHash: Span(_unsafeElements: digestRaw.bindMemory(to: UInt8.self)),
                            using: publicKey
                        )
                    }
                }
            }
        } catch {
            return false
        }
    }
}

extension P384.Signing.PrivateKey {
    internal func openSSLSignature<D: Digest>(
        for digest: D
    ) throws(CryptoKitMetaError) -> P384.Signing.ECDSASignature {
        do {
            let privateBytes = self.rawRepresentation
            let rawSignature = try privateBytes.withUnsafeBytes { privateRaw in
                let privateKey = try SSLCrypto.P384PrivateKey(
                    bytes: Span(_unsafeElements: privateRaw.bindMemory(to: UInt8.self))
                )
                return try digest.withUnsafeBytes { digestRaw in
                    try SSLCrypto.P384ECDSA.sign(
                        messageHash: Span(_unsafeElements: digestRaw.bindMemory(to: UInt8.self)),
                        using: privateKey
                    )
                }
            }
            return try P384.Signing.ECDSASignature(rawRepresentation: Data(rawSignature))
        } catch let error as CryptoInputError {
            throw mapSSLCryptoECDSAError(error)
        } catch let error as CryptoKitError {
            throw error
        } catch {
            throw CryptoKitError.invalidParameter
        }
    }
}

extension P384.Signing.PublicKey {
    internal func openSSLIsValidSignature<D: Digest>(
        _ signature: P384.Signing.ECDSASignature,
        for digest: D
    ) -> Bool {
        do {
            let publicBytes = self.x963Representation
            return try publicBytes.withUnsafeBytes { publicRaw in
                let publicKey = try SSLCrypto.P384PublicKey(
                    bytes: Span(_unsafeElements: publicRaw.bindMemory(to: UInt8.self))
                )
                return try signature.rawRepresentation.withUnsafeBytes { signatureRaw in
                    try digest.withUnsafeBytes { digestRaw in
                        try SSLCrypto.P384ECDSA.verify(
                            signature: Span(_unsafeElements: signatureRaw.bindMemory(to: UInt8.self)),
                            messageHash: Span(_unsafeElements: digestRaw.bindMemory(to: UInt8.self)),
                            using: publicKey
                        )
                    }
                }
            }
        } catch {
            return false
        }
    }
}

extension P521.Signing.PrivateKey {
    internal func openSSLSignature<D: Digest>(
        for digest: D
    ) throws(CryptoKitMetaError) -> P521.Signing.ECDSASignature {
        do {
            let privateBytes = self.rawRepresentation
            let rawSignature = try privateBytes.withUnsafeBytes { privateRaw in
                let privateKey = try SSLCrypto.P521PrivateKey(
                    bytes: Span(_unsafeElements: privateRaw.bindMemory(to: UInt8.self))
                )
                return try digest.withUnsafeBytes { digestRaw in
                    try SSLCrypto.P521ECDSA.sign(
                        messageHash: Span(_unsafeElements: digestRaw.bindMemory(to: UInt8.self)),
                        using: privateKey
                    )
                }
            }
            return try P521.Signing.ECDSASignature(rawRepresentation: Data(rawSignature))
        } catch let error as CryptoInputError {
            throw mapSSLCryptoECDSAError(error)
        } catch let error as CryptoKitError {
            throw error
        } catch {
            throw CryptoKitError.invalidParameter
        }
    }
}

extension P521.Signing.PublicKey {
    internal func openSSLIsValidSignature<D: Digest>(
        _ signature: P521.Signing.ECDSASignature,
        for digest: D
    ) -> Bool {
        do {
            let publicBytes = self.x963Representation
            return try publicBytes.withUnsafeBytes { publicRaw in
                let publicKey = try SSLCrypto.P521PublicKey(
                    bytes: Span(_unsafeElements: publicRaw.bindMemory(to: UInt8.self))
                )
                return try signature.rawRepresentation.withUnsafeBytes { signatureRaw in
                    try digest.withUnsafeBytes { digestRaw in
                        try SSLCrypto.P521ECDSA.verify(
                            signature: Span(_unsafeElements: signatureRaw.bindMemory(to: UInt8.self)),
                            messageHash: Span(_unsafeElements: digestRaw.bindMemory(to: UInt8.self)),
                            using: publicKey
                        )
                    }
                }
            }
        } catch {
            return false
        }
    }
}

#endif
