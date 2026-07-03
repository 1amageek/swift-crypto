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
public protocol DataProtocol: RandomAccessCollection, ContiguousBytes where Element == UInt8 {
    associatedtype Regions: Collection where Regions.Element: ContiguousBytes

    var regions: Regions { get }
}

public protocol MutableDataProtocol: DataProtocol, MutableCollection, RangeReplaceableCollection {}

@frozen
public struct Data: MutableDataProtocol, Sendable, Equatable, Hashable {
    public typealias Element = UInt8
    public typealias Index = Int
    public typealias SubSequence = Data
    public typealias Regions = CollectionOfOne<Data>

    var storage: [UInt8]

    public init() {
        self.storage = []
    }

    public init<S: Sequence>(_ elements: S) where S.Element == UInt8 {
        self.storage = Array(elements)
    }

    public init(repeating repeatedValue: UInt8, count: Int) {
        self.storage = Array(repeating: repeatedValue, count: count)
    }

    public init(count: Int) {
        self.init(repeating: 0, count: count)
    }

    public init(bytes: UnsafeRawPointer?, count: Int) {
        guard let bytes, count > 0 else {
            self.storage = []
            return
        }

        let buffer = UnsafeRawBufferPointer(start: bytes, count: count)
        self.storage = Array(buffer)
    }

    public init?<S: StringProtocol>(base64Encoded encoded: S) {
        var output = [UInt8]()
        var accumulator: UInt32 = 0
        var bits = 0
        var padding = 0

        for byte in encoded.utf8 {
            if byte == 61 {
                padding += 1
                continue
            }

            guard padding == 0 else {
                return nil
            }

            guard let value = Self.base64Value(byte) else {
                return nil
            }

            accumulator = (accumulator << 6) | UInt32(value)
            bits += 6

            if bits >= 8 {
                bits -= 8
                output.append(UInt8((accumulator >> UInt32(bits)) & 0xff))
            }
        }

        if padding > 0 {
            guard padding <= 2 else {
                return nil
            }
        }

        self.storage = output
    }

    public var startIndex: Int {
        self.storage.startIndex
    }

    public var endIndex: Int {
        self.storage.endIndex
    }

    public var regions: CollectionOfOne<Data> {
        CollectionOfOne(self)
    }

    public var bytes: RawSpan {
        self.storage.span.bytes
    }

    public subscript(position: Int) -> UInt8 {
        get {
            self.storage[position]
        }
        set {
            self.storage[position] = newValue
        }
    }

    public subscript(bounds: Range<Int>) -> Data {
        get {
            Data(self.storage[bounds])
        }
        set {
            self.storage.replaceSubrange(bounds, with: newValue.storage)
        }
    }

    public func index(after index: Int) -> Int {
        self.storage.index(after: index)
    }

    public func index(before index: Int) -> Int {
        self.storage.index(before: index)
    }

    public func distance(from start: Int, to end: Int) -> Int {
        self.storage.distance(from: start, to: end)
    }

    public func index(_ index: Int, offsetBy distance: Int) -> Int {
        self.storage.index(index, offsetBy: distance)
    }

    public mutating func replaceSubrange<C: Collection>(_ subrange: Range<Int>, with newElements: C) where C.Element == UInt8 {
        self.storage.replaceSubrange(subrange, with: newElements)
    }

    public mutating func reserveCapacity(_ minimumCapacity: Int) {
        self.storage.reserveCapacity(minimumCapacity)
    }

    public mutating func append(_ other: Data) {
        self.storage.append(contentsOf: other.storage)
    }

    public mutating func append<Other: DataProtocol>(_ other: Other) {
        self.storage.append(contentsOf: other)
    }

    public mutating func append(contentsOf bytes: RawSpan) {
        bytes.withUnsafeBytes { buffer in
            self.storage.append(contentsOf: buffer)
        }
    }

    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try self.storage.withUnsafeBytes(body)
    }

    public mutating func withUnsafeMutableBytes<R, E: Error>(
        _ body: (UnsafeMutableRawBufferPointer) throws(E) -> R
    ) throws(E) -> R {
        try self.storage.withUnsafeMutableBufferPointer { (buffer) throws(E) in
            try body(UnsafeMutableRawBufferPointer(buffer))
        }
    }

    public func subdata(in bounds: Range<Int>) -> Data {
        self[bounds]
    }

    public func base64EncodedString() -> String {
        guard !self.storage.isEmpty else {
            return ""
        }

        var output = [UInt8]()
        output.reserveCapacity(((self.storage.count + 2) / 3) * 4)

        var index = 0
        while index < self.storage.count {
            let first = UInt32(self.storage[index])
            let second = index + 1 < self.storage.count ? UInt32(self.storage[index + 1]) : 0
            let third = index + 2 < self.storage.count ? UInt32(self.storage[index + 2]) : 0
            let triple = (first << 16) | (second << 8) | third

            output.append(Self.base64Alphabet[Int((triple >> 18) & 0x3f)])
            output.append(Self.base64Alphabet[Int((triple >> 12) & 0x3f)])
            output.append(index + 1 < self.storage.count ? Self.base64Alphabet[Int((triple >> 6) & 0x3f)] : 61)
            output.append(index + 2 < self.storage.count ? Self.base64Alphabet[Int(triple & 0x3f)] : 61)

            index += 3
        }

        return String(decoding: output, as: UTF8.self)
    }

    public static func + <Other: Sequence>(lhs: Data, rhs: Other) -> Data where Other.Element == UInt8 {
        var result = lhs
        result.append(contentsOf: rhs)
        return result
    }

    private static let base64Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

    private static func base64Value(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 65...90:
            return byte - 65
        case 97...122:
            return byte - 97 + 26
        case 48...57:
            return byte - 48 + 52
        case 43:
            return 62
        case 47:
            return 63
        default:
            return nil
        }
    }
}

extension Array: DataProtocol where Element == UInt8 {
    public typealias Regions = CollectionOfOne<Array<UInt8>>

    public var regions: CollectionOfOne<Array<UInt8>> {
        CollectionOfOne(self)
    }
}

extension ArraySlice: DataProtocol where Element == UInt8 {
    public typealias Regions = CollectionOfOne<ArraySlice<UInt8>>

    public var regions: CollectionOfOne<ArraySlice<UInt8>> {
        CollectionOfOne(self)
    }
}

extension ContiguousArray: DataProtocol where Element == UInt8 {
    public typealias Regions = CollectionOfOne<ContiguousArray<UInt8>>

    public var regions: CollectionOfOne<ContiguousArray<UInt8>> {
        CollectionOfOne(self)
    }
}
#endif
