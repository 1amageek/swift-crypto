//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
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
    public enum _CFB {
        @inlinable
        public static func encrypt<Plaintext: DataProtocol>(
            _ plaintext: Plaintext,
            using key: SymmetricKey,
            iv: AES._CFB.IV
        ) throws(CryptoKitMetaError) -> Data {
            try AESCFBCipher.encryptOrDecrypt(.encrypt, plaintext, using: key, iv: iv)
        }

        @inlinable
        public static func decrypt<Ciphertext: DataProtocol>(
            _ ciphertext: Ciphertext,
            using key: SymmetricKey,
            iv: AES._CFB.IV
        ) throws(CryptoKitMetaError) -> Data {
            try AESCFBCipher.encryptOrDecrypt(.decrypt, ciphertext, using: key, iv: iv)
        }
    }
}

extension AES._CFB {
    public struct IV: Sendable {
        // AES CFB uses a 128-bit IV.
        private var ivBytes: (UInt64, UInt64)

        public init() {
            var rng = SystemRandomNumberGenerator()
            self.ivBytes = (rng.next(), rng.next())
        }

        public init<IVBytes: Collection>(ivBytes: IVBytes) throws(CryptoKitMetaError) where IVBytes.Element == UInt8 {
            guard ivBytes.count == 16 else {
                throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
            }

            self.ivBytes = (0, 0)

            Swift.withUnsafeMutableBytes(of: &self.ivBytes) { bytesPtr in
                bytesPtr.copyBytes(from: ivBytes)
            }
        }

        mutating func withUnsafeMutableBytes<ReturnType, E: Error>(_ body: (UnsafeMutableRawBufferPointer) throws(E) -> ReturnType) throws(E) -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.ivBytes, body)
        }
    }
}
