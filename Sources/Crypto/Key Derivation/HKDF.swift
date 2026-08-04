//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
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


#if canImport(CryptoKit) && !SWIFT_CRYPTO_PURE_SWIFT
import CryptoKit
#else


/// A standards-based implementation of an HMAC-based Key Derivation Function
/// (HKDF).
///
/// The key derivation functions allow you to derive one or more secrets of the
/// size of your choice from a main key or passcode. The key derivation function
/// is compliant with IETF RFC 5869. Use one of the `deriveKey` functions, such
/// as ``deriveKey(inputKeyMaterial:outputByteCount:)`` or
/// ``deriveKey(inputKeyMaterial:salt:info:outputByteCount:)``, to derive a key
/// from a main secret or passcode in a single function.
///
/// To derive a key with more fine-grained control, use
/// ``extract(inputKeyMaterial:salt:)`` to create cryptographically strong key
/// material in the form of a hashed authentication code, then call
/// ``expand(pseudoRandomKey:info:outputByteCount:)`` using that key material to
/// generate a symmetric key of the length you specify.
public struct HKDF<H: HashFunction>: Sendable {
    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation with information and salt you specify.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - salt: The salt to use for key derivation.
    ///   - info: The shared information to use for key derivation.
    ///   - outputKey: An output span that will be populated with the derived
    ///   symmetric key.
    public static func deriveKey(inputKeyMaterial: SymmetricKey,
                                 salt: RawSpan? = nil,
                                 info: RawSpan? = nil,
                                 output outputKey: inout OutputRawSpan) {
        preconditionValidOutputByteCount(outputKey.freeCapacity)
        withExtractedKeyBytes(
            salt: salt,
            updateInputKeyMaterial: { authenticator in
                authenticator.update(bytes: inputKeyMaterial.bytes)
            }
        ) { codeBytes in
            expandValidated(
                pseudoRandomKey: codeBytes.bytes,
                into: &outputKey,
                updateInfo: { authenticator in
                    if let info {
                        authenticator.update(bytes: info)
                    }
                }
            )
        }
    }

    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation with information and salt you specify.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - salt: The salt to use for key derivation.
    ///   - info: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Salt: DataProtocol, Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt,
        info: Info,
        outputByteCount: Int
    ) -> SymmetricKey {
        preconditionValidOutputByteCount(outputByteCount)
        return SymmetricKey(capacity: outputByteCount) { output in
            withExtractedKeyBytes(
                salt: Optional(salt),
                updateInputKeyMaterial: { authenticator in
                    authenticator.update(bytes: inputKeyMaterial.bytes)
                }
            ) { codeBytes in
                expandValidated(
                    pseudoRandomKey: codeBytes.bytes,
                    into: &output,
                    updateInfo: { authenticator in
                        authenticator.update(data: info)
                    }
                )
            }
        }
    }

    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation with information you specify.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - info: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Info: DataProtocol>(inputKeyMaterial: SymmetricKey,
                                                     info: Info,
                                                     outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, salt: [UInt8](), info: info, outputByteCount: outputByteCount)
    }

    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation with salt that you specify.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - salt: The salt to use for key derivation.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Salt: DataProtocol>(inputKeyMaterial: SymmetricKey,
                                                     salt: Salt,
                                                     outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, salt: salt, info: [UInt8](), outputByteCount: outputByteCount)
    }

    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func deriveKey(inputKeyMaterial: SymmetricKey,
                                 outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, salt: [UInt8](), info: [UInt8](), outputByteCount: outputByteCount)
    }

    /// Creates cryptographically strong key material from a main key or
    /// passcode that you specify.
    ///
    /// Generate a derived symmetric key from the cryptographically strong key
    /// material this function creates by calling
    /// ``expand(pseudoRandomKey:info:outputByteCount:)``.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - salt: The salt to use for key derivation.
    ///
    /// - Returns: A pseudorandom, cryptographically strong key in the form of a
    /// hashed authentication code.
    public static func extract<Salt: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt?
    ) -> HashedAuthenticationCode<H> {
        extract(salt: salt) { authenticator in
            authenticator.update(bytes: inputKeyMaterial.bytes)
        }
    }

    /// Creates cryptographically strong key material from a main key or
    /// passcode that you specify.
    ///
    /// Generate a derived symmetric key from the cryptographically strong key
    /// material this function creates by calling
    /// ``expand(pseudoRandomKey:info:outputByteCount:)``.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - salt: The salt to use for key derivation.
    ///
    /// - Returns: A pseudorandom, cryptographically strong key in the form of a
    /// hashed authentication code.
    public static func extract(
        inputKeyMaterial: SymmetricKey,
        salt: RawSpan?
    ) -> HashedAuthenticationCode<H> {
        extract(salt: salt) { authenticator in
            authenticator.update(bytes: inputKeyMaterial.bytes)
        }
    }

    /// Expands cryptographically strong key material into a derived symmetric
    /// key.
    ///
    /// Generate cryptographically strong key material to use with this function
    /// by calling ``extract(inputKeyMaterial:salt:)``.
    ///
    /// - Parameters:
    ///   - prk: A pseudorandom, cryptographically strong key generated from the
    /// ``extract(inputKeyMaterial:salt:)`` function.
    ///   - info: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func expand<PRK: ContiguousBytes, Info: DataProtocol>(
        pseudoRandomKey prk: PRK,
        info: Info?,
        outputByteCount: Int
    ) -> SymmetricKey {
        preconditionValidOutputByteCount(outputByteCount)
        return SymmetricKey(capacity: outputByteCount) { output in
            prk.withUnsafeBytes { prkBuffer in
                expandValidated(
                    pseudoRandomKey: prkBuffer.bytes,
                    into: &output,
                    updateInfo: { authenticator in
                        if let info {
                            authenticator.update(data: info)
                        }
                    }
                )
            }
        }
    }

    /// Expands cryptographically strong key material into a derived symmetric
    /// key.
    ///
    /// Generate cryptographically strong key material to use with this function
    /// by calling ``extract(inputKeyMaterial:salt:)``.
    ///
    /// - Parameters:
    ///   - prk: A pseudorandom, cryptographically strong key generated from the
    /// ``extract(inputKeyMaterial:salt:)`` function.
    ///   - info: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func expand(pseudoRandomKey prk: RawSpan, info: RawSpan?, into output: inout OutputRawSpan) {
        preconditionValidOutputByteCount(output.freeCapacity)
        expandValidated(
            pseudoRandomKey: prk,
            into: &output,
            updateInfo: { authenticator in
                if let info {
                    authenticator.update(bytes: info)
                }
            }
        )
    }

    static func extract<Salt: DataProtocol>(
        salt: Salt?,
        updateInputKeyMaterial: (inout HMAC<H>) -> Void
    ) -> HashedAuthenticationCode<H> {
        var authenticator = if let salt {
            HMAC<H>(keyMaterial: salt)
        } else {
            HMAC<H>(keyMaterial: SecureBytes())
        }
        updateInputKeyMaterial(&authenticator)
        return authenticator.finalizeAuthenticationCode()
    }

    static func extract(
        salt: RawSpan?,
        updateInputKeyMaterial: (inout HMAC<H>) -> Void
    ) -> HashedAuthenticationCode<H> {
        var authenticator = if let salt {
            HMAC<H>(keyMaterial: salt)
        } else {
            HMAC<H>(keyMaterial: SecureBytes())
        }
        updateInputKeyMaterial(&authenticator)
        return authenticator.finalizeAuthenticationCode()
    }

    static func withExtractedKeyBytes<Salt: DataProtocol, Result>(
        salt: Salt?,
        updateInputKeyMaterial: (inout HMAC<H>) -> Void,
        _ body: (UnsafeRawBufferPointer) -> Result
    ) -> Result {
        var authenticator = if let salt {
            HMAC<H>(keyMaterial: salt)
        } else {
            HMAC<H>(keyMaterial: SecureBytes())
        }
        updateInputKeyMaterial(&authenticator)
        return authenticator.withFinalizedDigestBytes(body)
    }

    static func withExtractedKeyBytes<Result>(
        salt: RawSpan?,
        updateInputKeyMaterial: (inout HMAC<H>) -> Void,
        _ body: (UnsafeRawBufferPointer) -> Result
    ) -> Result {
        var authenticator = if let salt {
            HMAC<H>(keyMaterial: salt)
        } else {
            HMAC<H>(keyMaterial: SecureBytes())
        }
        updateInputKeyMaterial(&authenticator)
        return authenticator.withFinalizedDigestBytes(body)
    }

    static func expandValidated(
        pseudoRandomKey prk: RawSpan,
        into output: inout OutputRawSpan,
        updateInfo: (inout HMAC<H>) -> Void
    ) {
        let outputByteCount = output.freeCapacity
        precondition(outputByteCount <= maximumOutputByteCount)
        guard outputByteCount > 0 else {
            return
        }

        let digestByteCount = H.Digest.byteCount
        let iterationCount = outputByteCount / digestByteCount
            + (outputByteCount.isMultiple(of: digestByteCount) ? 0 : 1)
        let keyedAuthenticator = HMAC<H>(keyMaterial: prk)
        var lastIterationBytes = 0
        for iteration in 1...iterationCount {
            var authenticator = keyedAuthenticator
            authenticator.update(bytes: output.bytes.extracting(last: lastIterationBytes))
            updateInfo(&authenticator)

            var counter = UInt8(iteration)
            withUnsafeBytes(of: &counter) { rawBuffer in
                let span = RawSpan(_unsafeBytes: rawBuffer)
                authenticator.update(bytes: span)
            }
            authenticator.withFinalizedDigestBytes { digestBytes in
                let bytesToAppend = digestBytes.bytes.extracting(first: output.freeCapacity)
                output.append(contentsOf: bytesToAppend)
                lastIterationBytes = bytesToAppend.byteCount
            }
        }
    }

    private static var maximumOutputByteCount: Int {
        let digestByteCount = H.Digest.byteCount
        precondition(digestByteCount > 0)
        let (maximumOutputByteCount, overflow) = digestByteCount.multipliedReportingOverflow(by: 255)
        return overflow ? Int.max : maximumOutputByteCount
    }

    private static func preconditionValidOutputByteCount(
        _ outputByteCount: Int
    ) {
        let maximumOutputByteCount = Self.maximumOutputByteCount
        precondition(
            outputByteCount > 0,
            "HKDF output byte count must be positive"
        )
        precondition(
            outputByteCount <= maximumOutputByteCount,
            "HKDF output byte count exceeds 255 times the digest byte count"
        )
    }
}
#endif // canImport(CryptoKit)
