//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

#if canImport(CryptoKit)
import CryptoKit
#else
internal import CCryptoBoringSSL
internal import CCryptoBoringSSLShims
import CryptoBoringWrapper

extension BoringSSLAEAD {
    private func convert(_ wrapperError: CryptoBoringWrapperError) -> CryptoKitMetaError {
        switch wrapperError {
        case .incorrectKeySize:
            return error(CryptoKitError.incorrectKeySize)
        case .incorrectParameterSize:
            return error(CryptoKitError.incorrectParameterSize)
        case .authenticationFailure:
            return error(CryptoKitError.authenticationFailure)
        case .underlyingCoreCryptoError(let errorCode):
            return error(CryptoKitError.underlyingCoreCryptoError(error: errorCode))
        case .wrapFailure:
            return error(CryptoKitError.wrapFailure)
        case .unwrapFailure:
            return error(CryptoKitError.unwrapFailure)
        case .invalidParameter:
            return error(CryptoKitError.invalidParameter)
        }
    }

    /// Seal a given message.
    func seal<Plaintext: DataProtocol, Nonce: ContiguousBytes, AuthenticatedData: DataProtocol>(
        message: Plaintext,
        key: SymmetricKey,
        nonce: Nonce,
        authenticatedData: AuthenticatedData
    ) throws(CryptoKitMetaError) -> Data {
        #if hasFeature(Embedded)
        var nonceData = Data()
        nonce.withUnsafeBytes { nonceData.append(contentsOf: $0) }
        let authenticatedDataData = Data(authenticatedData)
        var combined = nonceData
        combined.append(contentsOf: message)
        let plaintextOffset = nonceData.count
        let tagOffset = plaintextOffset + message.count
        combined.append(contentsOf: repeatElement(UInt8(0), count: ChaChaPoly.tagByteCount))

        try combined.withUnsafeMutableBytes { (combinedBuffer) throws(CryptoKitMetaError) in
            let messageBuffer = UnsafeMutableRawBufferPointer(rebasing: combinedBuffer[plaintextOffset..<tagOffset])
            let tagBuffer = UnsafeMutableRawBufferPointer(rebasing: combinedBuffer[tagOffset..<combinedBuffer.count])
            var messageSpan = messageBuffer.mutableBytes
            var tagSpan = OutputRawSpan(buffer: tagBuffer, initializedCount: 0)
            try self.seal(
                message: &messageSpan,
                key: key,
                nonce: nonceData.bytes,
                authenticatedData: authenticatedDataData.bytes,
                tag: &tagSpan
            )
        }

        return combined
        #else
        do {
            let context = try AEADContext(cipher: self, key: key.bytes)
            return try context.seal(
                message: message,
                nonce: nonce,
                authenticatedData: authenticatedData
            )
        } catch CryptoBoringWrapperError.underlyingCoreCryptoError(let errorCode) {
            throw error(CryptoKitError.underlyingCoreCryptoError(error: errorCode))
        }
        #endif
    }

    /// Seal a given message in place
    func seal(
        message: inout MutableRawSpan,
        key: SymmetricKey,
        nonce: RawSpan,
        authenticatedData: RawSpan,
        tag: inout OutputRawSpan
    ) throws(CryptoKitMetaError) {
        do {
            let context = try AEADContext(cipher: self, key: key.bytes)
            return try context.seal(
                message: &message,
                nonce: nonce,
                authenticatedData: authenticatedData,
                tag: &tag,
            )
        } catch {
            throw self.convert(error)
        }
    }

    /// Open a given message.
    func open<Nonce: ContiguousBytes, AuthenticatedData: DataProtocol>(
        ciphertext: Data,
        key: SymmetricKey,
        nonce: Nonce,
        tag: Data,
        authenticatedData: AuthenticatedData
    ) throws(CryptoKitMetaError) -> Data {
        #if hasFeature(Embedded)
        var output = Data(ciphertext)
        var nonceData = Data()
        nonce.withUnsafeBytes { nonceData.append(contentsOf: $0) }
        let authenticatedDataData = Data(authenticatedData)

        try output.withUnsafeMutableBytes { (outputBuffer) throws(CryptoKitMetaError) in
            var messageSpan = outputBuffer.mutableBytes
            try self.open(
                message: &messageSpan,
                key: key,
                nonce: nonceData.bytes,
                tag: tag.bytes,
                authenticatedData: authenticatedDataData.bytes
            )
        }

        return output
        #else
        do {
            let context = try AEADContext(cipher: self, key: key.bytes)
            return try context.open(
                ciphertext: ciphertext,
                nonce: nonce,
                tag: tag,
                authenticatedData: authenticatedData
            )
        } catch CryptoBoringWrapperError.underlyingCoreCryptoError(let errorCode) {
            throw error(CryptoKitError.underlyingCoreCryptoError(error: errorCode))
        }
        #endif
    }

    /// Open a given message in place.
    public func open(
        message: inout MutableRawSpan,
        key: SymmetricKey,
        nonce: RawSpan,
        tag: RawSpan,
        authenticatedData: RawSpan
    ) throws(CryptoKitMetaError) {
        do {
            let context = try AEADContext(cipher: self, key: key.bytes)
            return try context.open(
                message: &message,
                nonce: nonce,
                tag: tag,
                authenticatedData: authenticatedData
            )
        } catch {
            throw self.convert(error)
        }
    }
}

enum OpenSSLChaChaPolyImpl {
    static func encrypt<M: DataProtocol, AD: DataProtocol>(
        key: SymmetricKey,
        message: M,
        nonce: ChaChaPoly.Nonce?,
        authenticatedData: AD?
    ) throws(CryptoKitMetaError) -> ChaChaPoly.SealedBox {
        guard key.bitCount == ChaChaPoly.keyBitsCount else {
            throw error(CryptoKitError.incorrectKeySize)
        }
        let nonce = nonce ?? ChaChaPoly.Nonce()

        let combined: Data
        if let ad = authenticatedData {
            combined = try BoringSSLAEAD.chacha20.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: ad
            )
        } else {
            combined = try BoringSSLAEAD.chacha20.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: []
            )
        }

        return ChaChaPoly.SealedBox(combined: combined, nonceByteCount: nonce.count)
    }

    static func encrypt(
        key: SymmetricKey,
        inPlace message: inout MutableRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan?,
        tag: inout OutputRawSpan
    ) throws(CryptoKitMetaError) {
        guard key.bitCount == ChaChaPoly.keyBitsCount else {
            throw error(CryptoKitError.incorrectKeySize)
        }

        if let ad = authenticatedData {
            try BoringSSLAEAD.chacha20.seal(
                message: &message,
                key: key,
                nonce: nonce,
                authenticatedData: ad,
                tag: &tag
            )
        } else {
            try BoringSSLAEAD.chacha20.seal(
                message: &message,
                key: key,
                nonce: nonce,
                authenticatedData: RawSpan(),
                tag: &tag
            )
        }
    }

    static func decrypt<AD: DataProtocol>(
        key: SymmetricKey,
        ciphertext: ChaChaPoly.SealedBox,
        authenticatedData: AD?
    ) throws(CryptoKitMetaError) -> Data {
        guard key.bitCount == ChaChaPoly.keyBitsCount else {
            throw error(CryptoKitError.incorrectKeySize)
        }

        if let ad = authenticatedData {
            return try BoringSSLAEAD.chacha20.open(
                ciphertext: ciphertext.ciphertext,
                key: key,
                nonce: ciphertext.nonce,
                tag: ciphertext.tag,
                authenticatedData: ad
            )
        } else {
            return try BoringSSLAEAD.chacha20.open(
                ciphertext: ciphertext.ciphertext,
                key: key,
                nonce: ciphertext.nonce,
                tag: ciphertext.tag,
                authenticatedData: []
            )
        }
    }

    static func decrypt(
        key: SymmetricKey,
        inPlace message: inout MutableRawSpan,
        nonce: RawSpan,
        tag: RawSpan,
        authenticatedData: RawSpan?
    ) throws(CryptoKitMetaError) {
        guard key.bitCount == ChaChaPoly.keyBitsCount else {
            throw error(CryptoKitError.incorrectKeySize)
        }

        if let authenticatedData {
            try BoringSSLAEAD.chacha20.open(
                message: &message,
                key: key,
                nonce: nonce,
                tag: tag,
                authenticatedData: authenticatedData
            )
        } else {
            try BoringSSLAEAD.chacha20.open(
                message: &message,
                key: key,
                nonce: nonce,
                tag: tag,
                authenticatedData: RawSpan()
            )
        }

    }
}
#endif  // canImport(CryptoKit)
