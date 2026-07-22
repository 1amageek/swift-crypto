#if !hasFeature(Embedded)
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
#endif

extension ARC {
    struct RepresentationWriter {
        private let destination: UnsafeMutableRawBufferPointer
        private var offset: Int

        init(
            destination: UnsafeMutableRawBufferPointer,
            requiredByteCount: Int
        ) throws {
            guard requiredByteCount >= 0 else {
                throw ARC.Errors.internalFailure
            }
            guard destination.count >= requiredByteCount else {
                throw ARC.Errors.insufficientOutputCapacity
            }
            self.destination = UnsafeMutableRawBufferPointer(
                rebasing: destination.prefix(requiredByteCount)
            )
            self.offset = 0
        }

        mutating func writeScalar<Scalar: GroupScalar>(
            _ scalar: borrowing Scalar
        ) throws {
            let reserved = try self.reservedBytes(
                byteCount: Scalar.rawRepresentationByteCount
            )
            try scalar.writeRawRepresentation(into: reserved.output)
            self.offset = reserved.endOffset
        }

        mutating func writeElement<Element: OPRFGroupElement>(
            _ element: borrowing Element
        ) throws {
            let reserved = try self.reservedBytes(
                byteCount: Element.oprfRepresentationByteCount
            )
            try element.writeOPRFRepresentation(into: reserved.output)
            self.offset = reserved.endOffset
        }

        mutating func copyBytes(
            from bytes: UnsafeRawBufferPointer
        ) throws {
            let reserved = try self.reservedBytes(byteCount: bytes.count)
            reserved.output.copyMemory(from: bytes)
            self.offset = reserved.endOffset
        }

        mutating func writeUInt16(_ value: UInt16) throws {
            let reserved = try self.reservedBytes(byteCount: 2)
            reserved.output[0] = UInt8(truncatingIfNeeded: value >> 8)
            reserved.output[1] = UInt8(truncatingIfNeeded: value)
            self.offset = reserved.endOffset
        }

        mutating func writeUInt32(_ value: UInt32) throws {
            let reserved = try self.reservedBytes(byteCount: 4)
            reserved.output[0] = UInt8(truncatingIfNeeded: value >> 24)
            reserved.output[1] = UInt8(truncatingIfNeeded: value >> 16)
            reserved.output[2] = UInt8(truncatingIfNeeded: value >> 8)
            reserved.output[3] = UInt8(truncatingIfNeeded: value)
            self.offset = reserved.endOffset
        }

        func finish() throws {
            guard self.offset == self.destination.count else {
                throw ARC.Errors.internalFailure
            }
        }

        static func representation(
            byteCount: Int,
            _ write: (inout Self) throws -> Void
        ) throws -> Data {
            guard byteCount >= 0 else {
                throw ARC.Errors.internalFailure
            }
            guard byteCount > 0 else {
                var writer = try Self(
                    destination: UnsafeMutableRawBufferPointer(start: nil, count: 0),
                    requiredByteCount: 0
                )
                try write(&writer)
                try writer.finish()
                return Data()
            }

            let storage = UnsafeMutableRawPointer.allocate(
                byteCount: byteCount,
                alignment: MemoryLayout<UInt8>.alignment
            )
            do {
                var writer = try Self(
                    destination: UnsafeMutableRawBufferPointer(
                        start: storage,
                        count: byteCount
                    ),
                    requiredByteCount: byteCount
                )
                try write(&writer)
                try writer.finish()
                // Data assumes ownership of the initialized allocation without copying it.
                return Data(
                    bytesNoCopy: storage,
                    count: byteCount,
                    deallocator: .custom { pointer, _ in
                        pointer.deallocate()
                    }
                )
            } catch {
                storage.deallocate()
                throw error
            }
        }

        private func reservedBytes(
            byteCount: Int
        ) throws -> (
            output: UnsafeMutableRawBufferPointer,
            endOffset: Int
        ) {
            guard
                byteCount >= 0,
                self.offset <= self.destination.count,
                byteCount <= self.destination.count - self.offset
            else {
                throw ARC.Errors.insufficientOutputCapacity
            }
            let start = self.offset
            let end = start + byteCount
            let output = UnsafeMutableRawBufferPointer(
                rebasing: self.destination[start..<end]
            )
            return (output, end)
        }
    }
}

#endif  // !hasFeature(Embedded)
