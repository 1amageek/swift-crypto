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


#if canImport(CryptoKit)
@_exported import CryptoKit
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
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(self)
    }
}

extension UnsafeMutableRawBufferPointer: ContiguousBytes {
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(UnsafeRawBufferPointer(self))
    }
}

extension UnsafeBufferPointer: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }
}

extension UnsafeMutableBufferPointer: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try body(UnsafeRawBufferPointer(start: self.baseAddress, count: self.count))
    }
}

extension Array: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try self.withUnsafeBufferPointer { buffer throws(E) in
            try body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }
}

extension ArraySlice: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try self.withUnsafeBufferPointer { buffer throws(E) in
            try body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }
}

extension ContiguousArray: ContiguousBytes where Element == UInt8 {
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try self.withUnsafeBufferPointer { buffer throws(E) in
            try body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: buffer.count))
        }
    }
}
#endif
