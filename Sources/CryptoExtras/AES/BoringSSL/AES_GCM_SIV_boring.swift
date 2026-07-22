//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// This is a copy ChaChaPoly_boring just with a different set aes algos

#if hasFeature(Embedded)
import CCryptoBoringSSL
#else
@_implementationOnly import CCryptoBoringSSL
#endif
#if hasFeature(Embedded)
import CCryptoBoringSSLShims
#else
@_implementationOnly import CCryptoBoringSSLShims
#endif
import Crypto
import CryptoBoringWrapper

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD {
    /// Seal a given message.
    func seal<Plaintext: DataProtocol, Nonce: Crypto.ContiguousBytes, AuthenticatedData: DataProtocol>(
        message: Plaintext,
        key: SymmetricKey,
        nonce: Nonce,
        authenticatedData: AuthenticatedData
    ) throws(CryptoKitMetaError) -> Data {
        #if hasFeature(Embedded)
        var nonceData = Data()
        nonce.withUnsafeBytes { nonceData.append(contentsOf: $0) }
        let authenticatedData = Data(authenticatedData)
        var combined = nonceData
        combined.append(contentsOf: message)
        let plaintextOffset = nonceData.count
        let tagOffset = plaintextOffset + message.count
        combined.append(contentsOf: repeatElement(UInt8(0), count: 16))

        do {
            let context = try AEADContext(cipher: self, key: key.bytes)
            try combined.withUnsafeMutableBytes { (buffer) throws(CryptoBoringWrapperError) in
                let messageBuffer = UnsafeMutableRawBufferPointer(rebasing: buffer[plaintextOffset..<tagOffset])
                let tagBuffer = UnsafeMutableRawBufferPointer(rebasing: buffer[tagOffset..<buffer.count])
                var messageSpan = messageBuffer.mutableBytes
                var tagSpan = OutputRawSpan(buffer: tagBuffer, initializedCount: 0)
                try context.seal(
                    message: &messageSpan,
                    nonce: nonceData.bytes,
                    authenticatedData: authenticatedData.bytes,
                    tag: &tagSpan
                )
            }
            return combined
        } catch {
            throw cryptoExtrasError(error)
        }
        #else
        do {
            let context = try AEADContext(cipher: self, key: key)
            return try context.seal(message: message, nonce: nonce, authenticatedData: authenticatedData)
        } catch CryptoBoringWrapperError.underlyingCoreCryptoError(let errorCode) {
            throw cryptoExtrasError(CryptoKitError.underlyingCoreCryptoError(error: errorCode))
        }
        #endif
    }

    /// Open a given message.
    func open<Nonce: Crypto.ContiguousBytes, AuthenticatedData: DataProtocol>(
        combinedCiphertextAndTag: Data,
        key: SymmetricKey,
        nonce: Nonce,
        authenticatedData: AuthenticatedData
    ) throws(CryptoKitMetaError) -> Data {
        #if hasFeature(Embedded)
        let ciphertext = combinedCiphertextAndTag.dropLast(16)
        let tag = combinedCiphertextAndTag.suffix(16)
        var output = Data(ciphertext)
        var nonceData = Data()
        nonce.withUnsafeBytes { nonceData.append(contentsOf: $0) }
        let authenticatedData = Data(authenticatedData)

        do {
            let context = try AEADContext(cipher: self, key: key.bytes)
            try output.withUnsafeMutableBytes { (buffer) throws(CryptoBoringWrapperError) in
                var messageSpan = buffer.mutableBytes
                try context.open(
                    message: &messageSpan,
                    nonce: nonceData.bytes,
                    tag: tag.bytes,
                    authenticatedData: authenticatedData.bytes
                )
            }
            return output
        } catch {
            throw cryptoExtrasError(error)
        }
        #else
        do {
            let context = try AEADContext(cipher: self, key: key)
            return try context.open(
                combinedCiphertextAndTag: combinedCiphertextAndTag,
                nonce: nonce,
                authenticatedData: authenticatedData
            )
        } catch CryptoBoringWrapperError.underlyingCoreCryptoError(let errorCode) {
            throw cryptoExtrasError(CryptoKitError.underlyingCoreCryptoError(error: errorCode))
        }
        #endif
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum OpenSSLAESGCMSIVImpl {
    @inlinable
    static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>(
        key: SymmetricKey,
        message: Plaintext,
        nonce: AES.GCM._SIV.Nonce?,
        authenticatedData: AuthenticatedData? = nil
    ) throws(CryptoKitMetaError) -> AES.GCM._SIV.SealedBox {
        let nonce = nonce ?? AES.GCM._SIV.Nonce()

        let aead = try Self._backingAEAD(key: key)

        let combined: Data
        if let ad = authenticatedData {
            combined = try aead.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: ad
            )
        } else {
            combined = try aead.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: []
            )
        }

        return AES.GCM._SIV.SealedBox(combined: combined, nonceByteCount: nonce.bytes.count)
    }

    @inlinable
    static func open<AuthenticatedData: DataProtocol>(
        key: SymmetricKey,
        sealedBox: AES.GCM._SIV.SealedBox,
        authenticatedData: AuthenticatedData? = nil
    ) throws(CryptoKitMetaError) -> Data {
        let aead = try Self._backingAEAD(key: key)

        if let ad = authenticatedData {
            return try aead.open(
                combinedCiphertextAndTag: sealedBox.combined.dropFirst(AES.GCM._SIV.nonceByteCount),
                key: key,
                nonce: sealedBox.nonce,
                authenticatedData: ad
            )
        } else {
            return try aead.open(
                combinedCiphertextAndTag: sealedBox.combined.dropFirst(AES.GCM._SIV.nonceByteCount),
                key: key,
                nonce: sealedBox.nonce,
                authenticatedData: []
            )
        }
    }

    @usableFromInline
    static func _backingAEAD(key: SymmetricKey) throws(CryptoKitMetaError) -> BoringSSLAEAD {
        switch key.bitCount {
        case 128:
            return .aes128gcmsiv
        case 256:
            return .aes256gcmsiv
        default:
            throw cryptoExtrasError(CryptoKitError.incorrectKeySize)
        }
    }
}
