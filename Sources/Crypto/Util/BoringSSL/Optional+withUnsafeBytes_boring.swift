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

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

extension Optional where Wrapped: DataProtocol {
#if hasFeature(Embedded)
    func withUnsafeBytes<ReturnValue, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> ReturnValue) throws(E) -> ReturnValue {
        if let self {
            return try withCryptoDataProtocolUnsafeBytes(self, body)
        } else {
            return try body(UnsafeRawBufferPointer(start: nil, count: 0))
        }
    }
#else
    func withUnsafeBytes<ReturnValue>(_ body: (UnsafeRawBufferPointer) throws -> ReturnValue) rethrows -> ReturnValue {
        if let self {
            return try self.regions.count == 1
                ? self.regions.first!.withUnsafeBytes(body)
                : Array(self).withUnsafeBytes(body)
        } else {
            return try body(UnsafeRawBufferPointer(start: nil, count: 0))
        }
    }
#endif
}
