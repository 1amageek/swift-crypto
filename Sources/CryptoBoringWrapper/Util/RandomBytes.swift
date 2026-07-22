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


internal import CCryptoBoringSSL

extension UnsafeMutableRawBufferPointer {
    package func initializeWithRandomBytes(count: Int) {
        guard count > 0 else {
            return
        }

        precondition(count <= self.count)
        let target = UnsafeMutableRawBufferPointer(rebasing: self.prefix(count))
        guard let baseAddress = target.baseAddress else {
            preconditionFailure("A non-empty random output requires valid storage")
        }
        precondition(
            CCryptoBoringSSL_RAND_bytes(
                baseAddress.assumingMemoryBound(to: UInt8.self),
                target.count
            ) == 1,
            "The secure random number generator failed"
        )
    }
}

extension OutputRawSpan {
    package mutating func appendingRandomBytes(count: Int) {
        self.withUnsafeMutableBytes { buffer, initializedCount in
            UnsafeMutableRawBufferPointer(rebasing: buffer[initializedCount..<initializedCount + count])
                .initializeWithRandomBytes(count: count)
            initializedCount += count
        }
    }
}

extension SystemRandomNumberGenerator {
    package static func randomBytes(count: Int) -> [UInt8] {
        Array(unsafeUninitializedCapacity: count) { buffer, initializedCount in
            UnsafeMutableRawBufferPointer(start: buffer.baseAddress, count: buffer.count)
                .initializeWithRandomBytes(count: count)
            initializedCount = count
        }
    }
}
