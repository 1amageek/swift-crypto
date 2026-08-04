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


extension HPKE {
    /// The key derivation functions to use in HPKE.
    @nonexhaustive
    public enum KDF: CaseIterable, Hashable, Sendable {
		/// An HMAC-based key derivation function that uses SHA-2 hashing with a 256-bit digest.
        case HKDF_SHA256
		/// An HMAC-based key derivation function that uses SHA-2 hashing with a 384-bit digest.
        case HKDF_SHA384
		/// An HMAC-based key derivation function that uses SHA-2 hashing with a 512-bit digest.
        case HKDF_SHA512

        /// Return the KDF algorithm identifier as defined in section 7.2 of [RFC 9180](https://www.ietf.org/rfc/rfc9180.pdf).
        internal var value: UInt16 {
            switch self {
            case .HKDF_SHA256: return 0x0001
            case .HKDF_SHA384: return 0x0002
            case .HKDF_SHA512: return 0x0003
            }
        }
        
        internal var identifier: Data {
            return I2OSP(value: Int(self.value), outputByteCount: 2)
        }
        
        /// Hash Function Output Size
        internal var Nh: Int {
            switch self {
            case .HKDF_SHA256:
                return SHA256.Digest.byteCount
            case .HKDF_SHA384:
                return SHA384.Digest.byteCount
            case .HKDF_SHA512:
                return SHA512.Digest.byteCount
            }
        }
    }
}

#endif // canImport(CryptoKit)
