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

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#else
/// A minimal embedded-compatible byte container interface.
public protocol ContiguousBytes {
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> R) throws(CryptoBoringWrapperError) -> R
}

extension UnsafeRawBufferPointer: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        body(self)
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> R) throws(CryptoBoringWrapperError) -> R {
        try body(self)
    }
}

extension UnsafeMutableRawBufferPointer: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        body(UnsafeRawBufferPointer(self))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> R) throws(CryptoBoringWrapperError) -> R {
        try body(UnsafeRawBufferPointer(self))
    }
}

extension UnsafeBufferPointer: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> R) throws(CryptoBoringWrapperError) -> R {
        try body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }
}

extension UnsafeMutableBufferPointer: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> R) throws(CryptoBoringWrapperError) -> R {
        try body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }
}

extension Array: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) -> R) -> R {
        self.withUnsafeBufferPointer { buffer in
            body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> R) throws(CryptoBoringWrapperError) -> R {
        return try self.withUnsafeBufferPointer { (buffer) throws(CryptoBoringWrapperError) in
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

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> R) throws(CryptoBoringWrapperError) -> R {
        return try self.withUnsafeBufferPointer { (buffer) throws(CryptoBoringWrapperError) in
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

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws(CryptoBoringWrapperError) -> R) throws(CryptoBoringWrapperError) -> R {
        return try self.withUnsafeBufferPointer { (buffer) throws(CryptoBoringWrapperError) in
            try body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }
}
#endif
