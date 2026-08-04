//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//


#if canImport(CryptoKit) && !SWIFT_CRYPTO_PURE_SWIFT
import CryptoKit
#endif

#if SWIFT_CRYPTO_PURE_SWIFT && (canImport(FoundationEssentials) || canImport(Foundation))

@usableFromInline
package func withUnsafeBytes<Bytes: ContiguousBytes, Result, E: Error>(
    of bytes: Bytes,
    _ body: (UnsafeRawBufferPointer) throws(E) -> Result
) throws(E) -> Result {
    do {
        return try bytes.withUnsafeBytes { buffer in
            try body(buffer)
        }
    } catch let typedError as E {
        throw typedError
    } catch {
        preconditionFailure("Unexpected error type escaped ContiguousBytes.withUnsafeBytes")
    }
}

// This helper keeps package-local consumers on the same borrowed-region
// contract without materializing contiguous input at every call site.
@usableFromInline
package func withContiguousBytes<Bytes: DataProtocol, Result, E: Error>(
    of bytes: Bytes,
    _ body: (UnsafeRawBufferPointer) throws(E) -> Result
) throws(E) -> Result {
    do {
        var regions = bytes.regions.makeIterator()
        guard let firstRegion = regions.next() else {
            return try body(UnsafeRawBufferPointer(start: nil, count: 0))
        }
        if regions.next() == nil {
            return try firstRegion.withUnsafeBytes { buffer in
                try body(buffer)
            }
        }
        return try Array(bytes).withUnsafeBytes { buffer in
            try body(buffer)
        }
    } catch let typedError as E {
        throw typedError
    } catch {
        preconditionFailure("Unexpected error type escaped DataProtocol.withUnsafeBytes")
    }
}

#endif

#if canImport(FoundationEssentials)
import FoundationEssentials
public typealias ContiguousBytes = FoundationEssentials.ContiguousBytes
#elseif canImport(Foundation)
import Foundation
public typealias ContiguousBytes = Foundation.ContiguousBytes
#else
/// A minimal embedded-compatible byte container interface.
public protocol ContiguousBytes {
    func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R
}

extension UnsafeRawBufferPointer: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        body(self)
    }

    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(self)
    }
}

extension UnsafeMutableRawBufferPointer: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        body(UnsafeRawBufferPointer(self))
    }

    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(UnsafeRawBufferPointer(self))
    }
}

extension UnsafeBufferPointer: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }

    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }
}

extension UnsafeMutableBufferPointer: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }

    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }
}

extension Array: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        self.withUnsafeBufferPointer { buffer in
            body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }

    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try self.withUnsafeBufferPointer { buffer throws(E) in
            try body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }
}

extension ArraySlice: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        self.withUnsafeBufferPointer { buffer in
            body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }

    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try self.withUnsafeBufferPointer { buffer throws(E) in
            try body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }
}

extension ContiguousArray: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        self.withUnsafeBufferPointer { buffer in
            body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }

    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try self.withUnsafeBufferPointer { buffer throws(E) in
            try body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }
}
#endif
