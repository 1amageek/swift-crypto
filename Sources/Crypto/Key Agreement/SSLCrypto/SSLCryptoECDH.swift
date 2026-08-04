//===----------------------------------------------------------------------===//
//
// Pure Swift ECDH facade adapter.
//
// The backend performs the scalar multiplication; this file only translates
// the facade's contiguous key boundary and owns the copied shared-secret bytes.
//
//===----------------------------------------------------------------------===//

#if SWIFT_CRYPTO_PURE_SWIFT

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

import SSLCrypto

private func mapSSLCryptoECDHError(_ error: CryptoInputError) -> CryptoKitError {
    switch error {
    case .invalidLength, .invalidOutputLength:
        return .incorrectParameterSize
    case .invalidPeerKey, .nonCanonicalEncoding, .invalidSignature, .invalidRange,
         .contextTooLong, .inputTooLong:
        return .invalidParameter
    }
}

extension P256.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(
        with publicKeyShare: P256.KeyAgreement.PublicKey
    ) throws(CryptoKitError) -> SharedSecret {
        do {
            let privateBytes = self.rawRepresentation
            let publicBytes = publicKeyShare.x963Representation
            return try privateBytes.withUnsafeBytes { privateRaw in
                try publicBytes.withUnsafeBytes { publicRaw in
                    let privateKey = try SSLCrypto.P256PrivateKey(
                        bytes: Span(_unsafeElements: privateRaw.bindMemory(to: UInt8.self))
                    )
                    let publicKey = try SSLCrypto.P256PublicKey(
                        bytes: Span(_unsafeElements: publicRaw.bindMemory(to: UInt8.self))
                    )
                    let secret = try SSLCrypto.P256KeyAgreement.sharedSecret(
                        privateKey: privateKey,
                        peerPublicKey: publicKey
                    )
                    let copied = secret.withBorrowedBytes { bytes in
                        bytes.withUnsafeBytes { raw in SecureBytes(bytes: raw.bytes) }
                    }
                    return SharedSecret(ss: copied)
                }
            }
        } catch let error as CryptoInputError {
            throw mapSSLCryptoECDHError(error)
        } catch let error as CryptoKitError {
            throw error
        } catch {
            throw .invalidParameter
        }
    }
}

extension P384.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(
        with publicKeyShare: P384.KeyAgreement.PublicKey
    ) throws(CryptoKitError) -> SharedSecret {
        do {
            let privateBytes = self.rawRepresentation
            let publicBytes = publicKeyShare.x963Representation
            return try privateBytes.withUnsafeBytes { privateRaw in
                try publicBytes.withUnsafeBytes { publicRaw in
                    let privateKey = try SSLCrypto.P384PrivateKey(
                        bytes: Span(_unsafeElements: privateRaw.bindMemory(to: UInt8.self))
                    )
                    let publicKey = try SSLCrypto.P384PublicKey(
                        bytes: Span(_unsafeElements: publicRaw.bindMemory(to: UInt8.self))
                    )
                    let secret = try SSLCrypto.P384KeyAgreement.sharedSecret(
                        privateKey: privateKey,
                        peerPublicKey: publicKey
                    )
                    let copied = secret.withBorrowedBytes { bytes in
                        bytes.withUnsafeBytes { raw in SecureBytes(bytes: raw.bytes) }
                    }
                    return SharedSecret(ss: copied)
                }
            }
        } catch let error as CryptoInputError {
            throw mapSSLCryptoECDHError(error)
        } catch let error as CryptoKitError {
            throw error
        } catch {
            throw .invalidParameter
        }
    }
}

extension P521.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(
        with publicKeyShare: P521.KeyAgreement.PublicKey
    ) throws(CryptoKitError) -> SharedSecret {
        do {
            let privateBytes = self.rawRepresentation
            let publicBytes = publicKeyShare.x963Representation
            return try privateBytes.withUnsafeBytes { privateRaw in
                try publicBytes.withUnsafeBytes { publicRaw in
                    let privateKey = try SSLCrypto.P521PrivateKey(
                        bytes: Span(_unsafeElements: privateRaw.bindMemory(to: UInt8.self))
                    )
                    let publicKey = try SSLCrypto.P521PublicKey(
                        bytes: Span(_unsafeElements: publicRaw.bindMemory(to: UInt8.self))
                    )
                    let secret = try SSLCrypto.P521KeyAgreement.sharedSecret(
                        privateKey: privateKey,
                        peerPublicKey: publicKey
                    )
                    let copied = secret.withBorrowedBytes { bytes in
                        bytes.withUnsafeBytes { raw in SecureBytes(bytes: raw.bytes) }
                    }
                    return SharedSecret(ss: copied)
                }
            }
        } catch let error as CryptoInputError {
            throw mapSSLCryptoECDHError(error)
        } catch let error as CryptoKitError {
            throw error
        } catch {
            throw .invalidParameter
        }
    }
}

#endif
