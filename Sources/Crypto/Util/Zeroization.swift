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
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif os(Windows)
import WinSDK
#endif

#if canImport(CryptoKit) && !CRYPTO_SHA256_STATE_STANDALONE_VALIDATION && !SWIFT_CRYPTO_PURE_SWIFT
import CryptoKit
#else

// Unsafe boundary invariants:
// - The caller owns initialized storage for exactly byteCount bytes.
// - The caller retains exclusive mutable access until this function returns.
// - byteCount is nonnegative and the pointer is nonnull when byteCount is positive.
// - The platform primitive performs optimizer-resistant byte stores synchronously.
// - No pointer escapes or crosses a Sendable boundary.
@inline(never)
func zeroizeMemory(
    _ baseAddress: UnsafeMutableRawPointer,
    byteCount: Int
) {
    precondition(byteCount >= 0)
    guard byteCount > 0 else { return }

    #if os(WASI) || os(Linux)
    explicit_bzero(baseAddress, byteCount)
    #elseif os(Windows)
    _ = RtlSecureZeroMemory(baseAddress, SIZE_T(byteCount))
    #else
    _ = memset_s(baseAddress, byteCount, 0, byteCount)
    #endif
}

protocol Zeroization {
    mutating func zeroize()
}

extension UnsafeMutableRawBufferPointer: Zeroization {
    func zeroize() {
        guard let baseAddress, count > 0 else {
            return
        }
        zeroizeMemory(baseAddress, byteCount: count)
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
