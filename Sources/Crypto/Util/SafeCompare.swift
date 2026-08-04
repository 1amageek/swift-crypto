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

internal func safeCompare<LHS: ContiguousBytes, RHS: ContiguousBytes>(_ lhs: LHS, _ rhs: RHS) -> Bool {
    #if SWIFT_CRYPTO_PURE_SWIFT
    return lhs.withUnsafeBytes { lhsBytes in
        rhs.withUnsafeBytes { rhsBytes in
            guard lhsBytes.count == rhsBytes.count else { return false }
            var difference: UInt8 = 0
            for index in 0..<lhsBytes.count {
                difference |= lhsBytes[index] ^ rhsBytes[index]
            }
            return difference == 0
        }
    }
    #else
    return openSSLSafeCompare(lhs, rhs)
    #endif
}

#endif // canImport(CryptoKit)
