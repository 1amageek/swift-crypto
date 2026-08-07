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

#if os(WASI)
import WASILibc
#elseif os(Linux)
import Glibc
#endif

#if canImport(CryptoKit) && !CRYPTO_SHA256_STATE_STANDALONE_VALIDATION && !SWIFT_CRYPTO_PURE_SWIFT
import CryptoKit
#else

protocol Zeroization {
    mutating func zeroize()
}

extension UnsafeMutableRawBufferPointer: Zeroization {
    func zeroize() {
        guard let baseAddress, count > 0 else {
            return
        }
        #if os(WASI) || os(Linux)
        // WASI and glibc expose an optimizer-resistant libc primitive. Keeping
        // this path in the platform libc keeps Pure Swift storage self-contained.
        explicit_bzero(baseAddress, count)
        #else
        memset_s(baseAddress, count, 0, count)
        #endif
    }
}

extension Array: Zeroization where Element == UInt8 {
    /// Zeroizes the array
    mutating func zeroize() {
        withUnsafeMutableBytes { bytes in
            bytes.zeroize()
        }
    }
}

extension Data: Zeroization {
    internal mutating func zeroize() {
        self.withUnsafeMutableBytes {
            $0.zeroize()
        }
    }
}

#endif  // canImport(CryptoKit) && !CRYPTO_SHA256_STATE_STANDALONE_VALIDATION
