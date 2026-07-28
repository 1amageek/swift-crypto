//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

extension AES {
    /// The Advanced Encryption Standard (AES) Cipher Block Chaining (CBC) cipher
    /// suite.
    public enum _CBC {
        /// Encrypts data using AES-CBC.
        public static func encrypt<Plaintext: DataProtocol>(
            _ plaintext: Plaintext,
            using key: SymmetricKey,
            iv: AES._CBC.IV
        ) throws(CryptoKitMetaError) -> Data {
            try self.encrypt(plaintext, using: key, iv: iv, noPadding: false)
        }

        /// Encrypts data using AES-CBC.
        ///
        /// When `noPadding` is `true`, the plaintext must contain complete
        /// 16-byte blocks.
        public static func encrypt<Plaintext: DataProtocol>(
            _ plaintext: Plaintext,
            using key: SymmetricKey,
            iv: AES._CBC.IV,
            noPadding: Bool
        ) throws(CryptoKitMetaError) -> Data {
            try OpenSSLAESCBCImpl.encrypt(plaintext, using: key, iv: iv, noPadding: noPadding)
        }

        /// Decrypts data using AES-CBC.
        public static func decrypt<Ciphertext: DataProtocol>(
            _ ciphertext: Ciphertext,
            using key: SymmetricKey,
            iv: AES._CBC.IV
        ) throws(CryptoKitMetaError) -> Data {
            try self.decrypt(ciphertext, using: key, iv: iv, noPadding: false)
        }

        /// Decrypts data using AES-CBC.
        ///
        /// When `noPadding` is `true`, PKCS#7 padding is not removed.
        public static func decrypt<Ciphertext: DataProtocol>(
            _ ciphertext: Ciphertext,
            using key: SymmetricKey,
            iv: AES._CBC.IV,
            noPadding: Bool
        ) throws(CryptoKitMetaError) -> Data {
            try OpenSSLAESCBCImpl.decrypt(ciphertext, using: key, iv: iv, noPadding: noPadding)
        }
    }
}

extension AES._CBC {
    /// An initialization vector.
    public struct IV: Sendable, Sequence {
        @usableFromInline
        var ivBytes: (
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
        )

        public init() {
            var rng = SystemRandomNumberGenerator()
            let (first, second) = (rng.next(), rng.next())

            self.ivBytes = (
                UInt8(truncatingIfNeeded: first),
                UInt8(truncatingIfNeeded: first >> 8),
                UInt8(truncatingIfNeeded: first >> 16),
                UInt8(truncatingIfNeeded: first >> 24),
                UInt8(truncatingIfNeeded: first >> 32),
                UInt8(truncatingIfNeeded: first >> 40),
                UInt8(truncatingIfNeeded: first >> 48),
                UInt8(truncatingIfNeeded: first >> 56),
                UInt8(truncatingIfNeeded: second),
                UInt8(truncatingIfNeeded: second >> 8),
                UInt8(truncatingIfNeeded: second >> 16),
                UInt8(truncatingIfNeeded: second >> 24),
                UInt8(truncatingIfNeeded: second >> 32),
                UInt8(truncatingIfNeeded: second >> 40),
                UInt8(truncatingIfNeeded: second >> 48),
                UInt8(truncatingIfNeeded: second >> 56)
            )
        }

        public init<IVBytes: Collection>(
            ivBytes: IVBytes
        ) throws(CryptoKitMetaError) where IVBytes.Element == UInt8 {
            guard ivBytes.count == 16 else {
                throw cryptoExtrasError(CryptoKitError.incorrectKeySize)
            }

            self.ivBytes = (
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            )

            Swift.withUnsafeMutableBytes(of: &self.ivBytes) { bytesPtr in
                bytesPtr.copyBytes(from: ivBytes)
            }
        }

        @inlinable
        public func makeIterator() -> some IteratorProtocol<UInt8> {
            withUnsafeBytes(of: ivBytes) { unsafeRawBufferPointer in
                Array(unsafeRawBufferPointer).makeIterator()
            }
        }

        mutating func withUnsafeMutableBytes<ReturnType, Failure: Error>(
            _ body: (UnsafeMutableRawBufferPointer) throws(Failure) -> ReturnType
        ) throws(Failure) -> ReturnType {
            try Swift.withUnsafeMutableBytes(of: &self.ivBytes, body)
        }
    }
}
