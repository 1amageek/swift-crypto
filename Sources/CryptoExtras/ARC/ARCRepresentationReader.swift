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
    struct RepresentationReader {
        private let source: UnsafeRawBufferPointer
        private var offset: Int

        init(source: UnsafeRawBufferPointer) {
            self.source = source
            self.offset = 0
        }

        mutating func readScalar<Scalar: GroupScalar>(
            _ type: Scalar.Type
        ) throws -> Scalar {
            try Scalar(
                canonicalRepresentation: self.readBytes(
                    byteCount: Scalar.rawRepresentationByteCount
                )
            )
        }

        mutating func readElement<Element: OPRFGroupElement>(
            _ type: Element.Type
        ) throws -> Element {
            try Element(
                oprfRepresentation: self.readBytes(
                    byteCount: Element.oprfRepresentationByteCount
                )
            )
        }

        mutating func readData(byteCount: Int) throws -> Data {
            Data(try self.readBytes(byteCount: byteCount))
        }

        mutating func readUInt16() throws -> UInt16 {
            let bytes = try self.readBytes(byteCount: 2)
            return UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        }

        mutating func readUInt32() throws -> UInt32 {
            let bytes = try self.readBytes(byteCount: 4)
            return UInt32(bytes[0]) << 24
                | UInt32(bytes[1]) << 16
                | UInt32(bytes[2]) << 8
                | UInt32(bytes[3])
        }

        func finish() throws {
            guard self.offset == self.source.count else {
                throw ARC.Errors.invalidEncoding
            }
        }

        private mutating func readBytes(
            byteCount: Int
        ) throws -> UnsafeRawBufferPointer {
            guard
                byteCount >= 0,
                self.offset <= self.source.count,
                byteCount <= self.source.count - self.offset
            else {
                throw ARC.Errors.invalidEncoding
            }
            let start = self.offset
            self.offset += byteCount
            return UnsafeRawBufferPointer(
                rebasing: self.source[start..<self.offset]
            )
        }
    }
}

#endif  // !hasFeature(Embedded)
