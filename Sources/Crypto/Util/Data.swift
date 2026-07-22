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
    var storageRange: Range<Int>

    public init() {
        self.storage = []
        self.storageRange = 0..<0
    }

    public init(capacity: Int) {
        precondition(capacity >= 0, "Data capacity must not be negative")
        self.storage = []
        self.storage.reserveCapacity(capacity)
        self.storageRange = 0..<0
    }

    public init(_ data: Data) {
        self = data
    }

    public init<S: Sequence>(_ elements: S) where S.Element == UInt8 {
        self.storage = Array(elements)
        self.storageRange = self.storage.indices
    }

    public init(repeating repeatedValue: UInt8, count: Int) {
        precondition(count >= 0, "Data count must not be negative")
        self.storage = Array(repeating: repeatedValue, count: count)
        self.storageRange = self.storage.indices
    }

    public init(count: Int) {
        self.init(repeating: 0, count: count)
    }

    public init(bytes: UnsafeRawPointer?, count: Int) {
        precondition(count >= 0, "Data count must not be negative")
        guard count > 0 else {
            self.storage = []
            self.storageRange = 0..<0
            return
        }
        guard let bytes else {
            preconditionFailure("A non-empty Data value requires a valid source pointer")
        }

        let buffer = UnsafeRawBufferPointer(start: bytes, count: count)
        self.storage = Array(buffer)
        self.storageRange = self.storage.indices
    }

    package init(copying data: Data) {
        self.storage = Array(data)
        self.storageRange = self.storage.indices
    }

    public init?<S: StringProtocol>(base64Encoded encoded: S) {
        let encodedCount = encoded.utf8.count
        guard encodedCount.isMultiple(of: 4) else {
            return nil
        }

        var output = [UInt8]()
        output.reserveCapacity((encodedCount / 4) * 3)
        var iterator = encoded.utf8.makeIterator()
        var consumedCount = 0

        while consumedCount < encodedCount {
            guard
                let firstByte = iterator.next(),
                let secondByte = iterator.next(),
                let thirdByte = iterator.next(),
                let fourthByte = iterator.next(),
                let firstValue = Self.base64Value(firstByte),
                let secondValue = Self.base64Value(secondByte)
            else {
                return nil
            }

            consumedCount += 4
            let isFinalQuartet = consumedCount == encodedCount
            output.append((firstValue << 2) | (secondValue >> 4))

            if thirdByte == Self.base64Padding {
                guard
                    isFinalQuartet,
                    fourthByte == Self.base64Padding,
                    secondValue & 0x0f == 0
                else {
                    return nil
                }
                continue
            }

            guard let thirdValue = Self.base64Value(thirdByte) else {
                return nil
            }
            output.append((secondValue << 4) | (thirdValue >> 2))

            if fourthByte == Self.base64Padding {
                guard isFinalQuartet, thirdValue & 0x03 == 0 else {
                    return nil
                }
                continue
            }

            guard let fourthValue = Self.base64Value(fourthByte) else {
                return nil
            }
            output.append((thirdValue << 6) | fourthValue)
        }

        guard iterator.next() == nil else {
            return nil
        }
        self.storage = output
        self.storageRange = output.indices
    }

    public var startIndex: Int {
        self.storageRange.lowerBound
    }

    public var endIndex: Int {
        self.storageRange.upperBound
    }

    public var regions: CollectionOfOne<Data> {
        CollectionOfOne(self)
    }

    public var bytes: RawSpan {
        self.storage.span.bytes.extracting(self.storageRange)
    }

    public subscript(position: Int) -> UInt8 {
        get {
            precondition(self.storageRange.contains(position), "Data index is outside the collection bounds")
            return self.storage[position]
        }
        set {
            precondition(self.storageRange.contains(position), "Data index is outside the collection bounds")
            self.storage[position] = newValue
        }
    }

    public subscript(bounds: Range<Int>) -> Data {
        get {
            precondition(
                bounds.lowerBound >= self.startIndex && bounds.upperBound <= self.endIndex,
                "Data slice is outside the collection bounds"
            )
            var slice = self
            slice.storageRange = bounds
            return slice
        }
        set {
            self.replaceSubrange(bounds, with: newValue)
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
        precondition(
            subrange.lowerBound >= self.startIndex && subrange.upperBound <= self.endIndex,
            "Replacement range is outside the collection bounds"
        )
        let replacementCount = newElements.count
        let replacedCount = subrange.count
        self.storage.replaceSubrange(subrange, with: newElements)
        self.storageRange = self.storageRange.lowerBound..<(self.storageRange.upperBound - replacedCount + replacementCount)
    }

    public mutating func reserveCapacity(_ minimumCapacity: Int) {
        self.storage.reserveCapacity(minimumCapacity)
    }

    public mutating func append(_ other: Data) {
        self.replaceSubrange(self.endIndex..<self.endIndex, with: other)
    }

    public mutating func append<Other: DataProtocol>(_ other: Other) {
        self.replaceSubrange(self.endIndex..<self.endIndex, with: other)
    }

    public mutating func append(contentsOf bytes: RawSpan) {
        bytes.withUnsafeBytes { buffer in
            self.replaceSubrange(self.endIndex..<self.endIndex, with: buffer)
        }
    }

    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try self.storage.withUnsafeBytes { (buffer) throws(E) in
            try body(UnsafeRawBufferPointer(rebasing: buffer[self.storageRange]))
        }
    }

    public mutating func withUnsafeMutableBytes<R, E: Error>(
        _ body: (UnsafeMutableRawBufferPointer) throws(E) -> R
    ) throws(E) -> R {
        try self.storage.withUnsafeMutableBufferPointer { (buffer) throws(E) in
            let mutableBytes = UnsafeMutableRawBufferPointer(buffer)
            return try body(UnsafeMutableRawBufferPointer(rebasing: mutableBytes[self.storageRange]))
        }
    }

    public func subdata(in bounds: Range<Int>) -> Data {
        self[bounds]
    }

    public func base64EncodedString() -> String {
        guard !self.storageRange.isEmpty else {
            return ""
        }

        var output = [UInt8]()
        output.reserveCapacity(((self.storageRange.count + 2) / 3) * 4)

        var index = self.startIndex
        while index < self.endIndex {
            let first = UInt32(self.storage[index])
            let second = index + 1 < self.endIndex ? UInt32(self.storage[index + 1]) : 0
            let third = index + 2 < self.endIndex ? UInt32(self.storage[index + 2]) : 0
            let triple = (first << 16) | (second << 8) | third

            output.append(Self.base64Alphabet[Int((triple >> 18) & 0x3f)])
            output.append(Self.base64Alphabet[Int((triple >> 12) & 0x3f)])
            output.append(index + 1 < self.endIndex ? Self.base64Alphabet[Int((triple >> 6) & 0x3f)] : Self.base64Padding)
            output.append(index + 2 < self.endIndex ? Self.base64Alphabet[Int(triple & 0x3f)] : Self.base64Padding)

            index += 3
        }

        return String(decoding: output, as: UTF8.self)
    }

    public static func + <Other: Sequence>(lhs: Data, rhs: Other) -> Data where Other.Element == UInt8 {
        var result = lhs
        result.append(contentsOf: rhs)
        return result
    }

    public static func == (lhs: Data, rhs: Data) -> Bool {
        lhs.count == rhs.count && lhs.elementsEqual(rhs)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.count)
        for byte in self {
            hasher.combine(byte)
        }
    }

    private static let base64Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
    private static let base64Padding: UInt8 = 61

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
