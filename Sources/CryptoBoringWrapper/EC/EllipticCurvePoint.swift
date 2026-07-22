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
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif
internal import CCryptoBoringSSL
internal import CCryptoBoringSSLShims


/// A wrapper around BoringSSL's EC_POINT with some lifetime management and value semantics.
@usableFromInline
package struct EllipticCurvePoint: @unchecked Sendable {
    @usableFromInline
    var backing: Backing

    @usableFromInline
    package init(copying pointer: OpaquePointer, on group: BoringSSLEllipticCurveGroup) throws(CryptoBoringWrapperError) {
        self.backing = try .init(copying: pointer, on: group)
    }

    @usableFromInline
    package init(_pointAtInfinityOn group: BoringSSLEllipticCurveGroup) throws(CryptoBoringWrapperError) {
        self.backing = try .init(_pointAtInfinityOn: group)
    }

    @usableFromInline
    package init(_generatorOf groupPtr: OpaquePointer) throws(CryptoBoringWrapperError) {
        self.backing = try .init(_generatorOf: groupPtr)
    }

    @usableFromInline
    package init(
        multiplying scalar: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        self.backing = try .init(multiplying: scalar, on: group, context: context)
    }

    @usableFromInline
    package mutating func multiply(
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        try self.cowIfNeeded(on: group)
        try self.backing.multiply(by: rhs, on: group, context: context)
    }

    @usableFromInline
    package init(
        multiplying lhs: EllipticCurvePoint,
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        self = lhs
        try self.multiply(by: rhs, on: group, context: context)
    }

    @usableFromInline
    package consuming func multiplying(
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        try self.multiply(by: rhs, on: group, context: context)
        return self
    }

    @usableFromInline
    package static func multiplying(
        _ lhs: consuming EllipticCurvePoint,
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        try lhs.multiplying(by: rhs, on: group, context: context)
    }

    @usableFromInline
    package mutating func add(
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        try self.cowIfNeeded(on: group)
        try self.backing.add(rhs, on: group, context: context)
    }

    @usableFromInline
    package init(
        adding lhs: EllipticCurvePoint,
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        self = lhs
        try self.add(rhs, on: group, context: context)
    }

    @usableFromInline
    package consuming func adding(
        _ rhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        try self.add(rhs, on: group, context: context)
        return self
    }

    @usableFromInline
    package static func adding(
        _ lhs: consuming EllipticCurvePoint,
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        try lhs.add(rhs, on: group, context: context)
        return lhs
    }

    @usableFromInline
    package mutating func invert(
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        try self.cowIfNeeded(on: group)
        try self.backing.invert(on: group, context: context)
    }

    @usableFromInline
    package init(
        inverting point: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        self = point
        try self.invert(on: group, context: context)
    }

    @usableFromInline
    package consuming func inverting(
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        try self.invert(on: group, context: context)
        return self
    }

    @usableFromInline
    package static func inverting(
        _ point: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        try point.invert(on: group, context: context)
        return point
    }

    @usableFromInline
    package mutating func subtract(
        _ rhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        try self.cowIfNeeded(on: group)
        try self.add(rhs.inverting(on: group), on: group, context: context)
    }

    @usableFromInline
    package init(
        subtracting rhs: consuming EllipticCurvePoint,
        from lhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        self = lhs
        try self.subtract(rhs, on: group, context: context)
    }

    @usableFromInline
    package consuming func subtracting(
        _ rhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        try self.subtract(rhs, on: group, context: context)
        return self
    }

    @usableFromInline
    package static func subtracting(
        _ rhs: consuming EllipticCurvePoint,
        from lhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        try lhs.subtract(rhs, on: group, context: context)
        return lhs
    }

    @usableFromInline
    package init<MessageBytes: ContiguousBytes, DSTBytes: ContiguousBytes>(
        hashing msg: MessageBytes,
        to group: BoringSSLEllipticCurveGroup,
        domainSeparationTag: DSTBytes
    ) throws(CryptoBoringWrapperError) {
        self.backing = try .init(hashing: msg, to: group, domainSeparationTag: domainSeparationTag)
    }

    @usableFromInline
    package func isEqual(
        to rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) -> Bool {
        self.backing.isEqual(to: rhs, on: group, context: context)
    }

    @usableFromInline
    package func isIdentity(on group: BoringSSLEllipticCurveGroup) -> Bool {
        group.withUnsafeGroupPointer { groupPointer in
            self.withPointPointer { pointPointer in
                CCryptoBoringSSL_EC_POINT_is_at_infinity(groupPointer, pointPointer) == 1
            }
        }
    }

    @usableFromInline
    package init<Bytes: ContiguousBytes>(
        x962Representation bytes: Bytes,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) {
        self.backing = try .init(x962Representation: bytes, on: group, context: context)
    }

    @usableFromInline
    package func x962RepresentationByteCount(
        compressed: Bool,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws(CryptoBoringWrapperError) -> Int {
        try self.backing.x962RepresentationByteCount(
            compressed: compressed,
            on: group,
            context: context
        )
    }

    @usableFromInline
    package func writeX962Representation(
        compressed: Bool,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil,
        into buffer: UnsafeMutableRawBufferPointer
    ) throws(CryptoBoringWrapperError) {
        try self.backing.writeX962Representation(
            compressed: compressed,
            on: group,
            context: context,
            into: buffer
        )
    }

    private mutating func cowIfNeeded(on group: BoringSSLEllipticCurveGroup) throws(CryptoBoringWrapperError) {
        if !isKnownUniquelyReferenced(&self.backing) {
            self.backing = try .init(copying: self.backing, on: group)
        }
    }
}

extension EllipticCurvePoint {
    @usableFromInline
    final class Backing {
        @usableFromInline
        let _basePoint: OpaquePointer

        fileprivate init(copying pointer: OpaquePointer, on group: BoringSSLEllipticCurveGroup) throws(CryptoBoringWrapperError) {
            self._basePoint = try group.withUnsafeGroupPointer { (groupPtr) throws(CryptoBoringWrapperError) in
                guard let pointPtr = CCryptoBoringSSL_EC_POINT_dup(pointer, groupPtr) else {
                    throw CryptoBoringWrapperError.internalBoringSSLError()
                }
                return pointPtr
            }
        }

        fileprivate convenience init(
            copying other: Backing,
            on group: BoringSSLEllipticCurveGroup
        )
            throws(CryptoBoringWrapperError)
        {
            try self.init(copying: other._basePoint, on: group)
        }

        fileprivate init(_pointAtInfinityOn group: BoringSSLEllipticCurveGroup) throws(CryptoBoringWrapperError) {
            self._basePoint = try group.withUnsafeGroupPointer { (groupPtr) throws(CryptoBoringWrapperError) in
                guard let pointPtr = CCryptoBoringSSL_EC_POINT_new(groupPtr) else {
                    throw CryptoBoringWrapperError.internalBoringSSLError()
                }
                return pointPtr
            }
        }

        fileprivate init(_generatorOf groupPtr: OpaquePointer) throws(CryptoBoringWrapperError) {
            guard
                let generatorPtr = CCryptoBoringSSL_EC_GROUP_get0_generator(groupPtr),
                let pointPtr = CCryptoBoringSSL_EC_POINT_dup(generatorPtr, groupPtr)
            else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
            self._basePoint = pointPtr
        }

        fileprivate convenience init(
            multiplying scalar: ArbitraryPrecisionInteger,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws(CryptoBoringWrapperError) {
            try self.init(_pointAtInfinityOn: group)
            try group.withUnsafeGroupPointer { (groupPtr) throws(CryptoBoringWrapperError) in
                try scalar.withUnsafeBignumPointer { (scalarPtr) throws(CryptoBoringWrapperError) in
                    let returnCode = withArithmeticWorkspace(from: context) { workspace in
                        CCryptoBoringSSL_EC_POINT_mul(
                            groupPtr,
                            self._basePoint,
                            scalarPtr,
                            nil,
                            nil,
                            workspace
                        )
                    }
                    guard returnCode == 1 else {
                        throw CryptoBoringWrapperError.internalBoringSSLError()
                    }
                }
            }
        }

        deinit {
            CCryptoBoringSSL_EC_POINT_free(self._basePoint)
        }

        fileprivate func multiply(
            by rhs: ArbitraryPrecisionInteger,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws(CryptoBoringWrapperError) {
            try self.withPointPointer { (selfPtr) throws(CryptoBoringWrapperError) in
                try rhs.withUnsafeBignumPointer { (rhsPtr) throws(CryptoBoringWrapperError) in
                    try group.withUnsafeGroupPointer { (groupPtr) throws(CryptoBoringWrapperError) in
                        let returnCode = withArithmeticWorkspace(from: context) { workspace in
                            CCryptoBoringSSL_EC_POINT_mul(
                                groupPtr,
                                selfPtr,
                                nil,
                                selfPtr,
                                rhsPtr,
                                workspace
                            )
                        }
                        guard returnCode == 1 else {
                            throw CryptoBoringWrapperError.internalBoringSSLError()
                        }
                    }
                }
            }
        }

        fileprivate func add(
            _ rhs: EllipticCurvePoint,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws(CryptoBoringWrapperError) {
            try self.withPointPointer { (selfPtr) throws(CryptoBoringWrapperError) in
                try group.withUnsafeGroupPointer { (groupPtr) throws(CryptoBoringWrapperError) in
                    try rhs.withPointPointer { (rhsPtr) throws(CryptoBoringWrapperError) in
                        guard CCryptoBoringSSL_EC_POINT_add(groupPtr, selfPtr, selfPtr, rhsPtr, nil) == 1
                        else {
                            throw CryptoBoringWrapperError.internalBoringSSLError()
                        }
                    }
                }
            }
        }

        internal func invert(on group: BoringSSLEllipticCurveGroup, context: FiniteFieldArithmeticContext? = nil) throws(CryptoBoringWrapperError)
        {
            try self.withPointPointer { (selfPtr) throws(CryptoBoringWrapperError) in
                try group.withUnsafeGroupPointer { (groupPtr) throws(CryptoBoringWrapperError) in
                    guard CCryptoBoringSSL_EC_POINT_invert(groupPtr, selfPtr, nil) == 1 else {
                        throw CryptoBoringWrapperError.internalBoringSSLError()
                    }
                }
            }
        }

        fileprivate convenience init<MessageBytes: ContiguousBytes, DSTBytes: ContiguousBytes>(
            hashing msg: MessageBytes,
            to group: BoringSSLEllipticCurveGroup,
            domainSeparationTag: DSTBytes
        ) throws(CryptoBoringWrapperError) {
            let hashToCurveFunction =
                switch group.curveName {
                case .p256: CCryptoBoringSSLShims_EC_hash_to_curve_p256_xmd_sha256_sswu
                case .p384: CCryptoBoringSSLShims_EC_hash_to_curve_p384_xmd_sha384_sswu
                // BoringSSL has no P521 hash_to_curve API.
                case .p521: throw CryptoBoringWrapperError.invalidParameter
                case .none: throw CryptoBoringWrapperError.internalBoringSSLError()
                }

            try self.init(_pointAtInfinityOn: group)
            try withCryptoBoringWrapperUnsafeBytes(msg) { (msgPtr) throws(CryptoBoringWrapperError) in
                try group.withUnsafeGroupPointer { (groupPtr) throws(CryptoBoringWrapperError) in
                    try withCryptoBoringWrapperUnsafeBytes(domainSeparationTag) { (dstPtr) throws(CryptoBoringWrapperError) in
                        guard
                            hashToCurveFunction(
                                groupPtr,
                                self._basePoint,
                                dstPtr.baseAddress,
                                dstPtr.count,
                                msgPtr.baseAddress,
                                msgPtr.count
                            ) == 1
                        else { throw CryptoBoringWrapperError.internalBoringSSLError() }
                    }
                }
            }
        }

        fileprivate func isEqual(
            to rhs: EllipticCurvePoint,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) -> Bool {
            self.withPointPointer { selfPtr in
                group.withUnsafeGroupPointer { groupPtr in
                    rhs.withPointPointer { rhsPtr in
                        switch CCryptoBoringSSL_EC_POINT_cmp(groupPtr, selfPtr, rhsPtr, nil) {
                        case 0: return true
                        case 1: return false
                        default:
                            preconditionFailure("Unable to compare elliptic-curve points")
                        }
                    }
                }
            }
        }

        fileprivate convenience init<Bytes: ContiguousBytes>(
            x962Representation bytes: Bytes,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws(CryptoBoringWrapperError) {
            try self.init(_pointAtInfinityOn: group)
            let returnCode = group.withUnsafeGroupPointer { groupPtr in
                bytes.withUnsafeBytes { dataPtr in
                    withArithmeticWorkspace(from: context) { workspace in
                        CCryptoBoringSSL_EC_POINT_oct2point(
                            groupPtr,
                            self._basePoint,
                            dataPtr.baseAddress,
                            dataPtr.count,
                            workspace
                        )
                    }
                }
            }
            guard returnCode == 1 else {
                throw CryptoBoringWrapperError.invalidParameter
            }
        }

        fileprivate func x962RepresentationByteCount(
            compressed: Bool,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws(CryptoBoringWrapperError) -> Int {
            let numBytesNeeded = group.withUnsafeGroupPointer { groupPtr in
                CCryptoBoringSSL_EC_POINT_point2oct(
                    groupPtr,
                    self._basePoint,
                    compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
                    nil,
                    0,
                    nil
                )
            }
            guard numBytesNeeded != 0 else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
            return numBytesNeeded
        }

        fileprivate func writeX962Representation(
            compressed: Bool,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil,
            into buffer: UnsafeMutableRawBufferPointer
        ) throws(CryptoBoringWrapperError) {
            let numBytesNeeded = try self.x962RepresentationByteCount(
                compressed: compressed,
                on: group,
                context: context
            )
            guard buffer.count == numBytesNeeded else {
                throw CryptoBoringWrapperError.incorrectParameterSize
            }

            let numBytesWritten = group.withUnsafeGroupPointer { groupPtr in
                CCryptoBoringSSLShims_EC_POINT_point2oct(
                    groupPtr,
                    self._basePoint,
                    compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
                    buffer.baseAddress,
                    buffer.count,
                    nil
                )
            }
            guard numBytesWritten == numBytesNeeded else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
        }
    }
}

private func withArithmeticWorkspace(
    from context: FiniteFieldArithmeticContext?,
    _ operation: (OpaquePointer?) -> Int32
) -> Int32 {
    guard let context else {
        return operation(nil)
    }
    return context.performWithArithmeticWorkspace { workspace in
        operation(workspace)
    }
}

// MARK: - Helpers

extension EllipticCurvePoint.Backing {
    @inlinable
    package func withPointPointer<T>(_ body: (OpaquePointer) -> T) -> T {
        body(self._basePoint)
    }

    @inlinable
    package func withPointPointer<T, E: Error>(
        _ body: (OpaquePointer) throws(E) -> T
    ) throws(E) -> T {
        try body(self._basePoint)
    }

    fileprivate func affineCoordinates(
        group: BoringSSLEllipticCurveGroup
    ) throws(CryptoBoringWrapperError) -> (
        x: ArbitraryPrecisionInteger, y: ArbitraryPrecisionInteger
    ) {
        var x = ArbitraryPrecisionInteger()
        var y = ArbitraryPrecisionInteger()

        try x.withUnsafeMutableBignumPointer { (xPtr) throws(CryptoBoringWrapperError) in
            try y.withUnsafeMutableBignumPointer { (yPtr) throws(CryptoBoringWrapperError) in
                try group.withUnsafeGroupPointer { (groupPtr) throws(CryptoBoringWrapperError) in
                    guard
                        CCryptoBoringSSL_EC_POINT_get_affine_coordinates_GFp(
                            groupPtr,
                            self._basePoint,
                            xPtr,
                            yPtr,
                            nil
                        ) != 0
                    else {
                        throw CryptoBoringWrapperError.internalBoringSSLError()
                    }
                }
            }
        }

        return (x: x, y: y)
    }
}

extension EllipticCurvePoint {
    @inlinable
    package func withPointPointer<T>(_ body: (OpaquePointer) -> T) -> T {
        self.backing.withPointPointer(body)
    }

    @inlinable
    package func withPointPointer<T, E: Error>(
        _ body: (OpaquePointer) throws(E) -> T
    ) throws(E) -> T {
        try self.backing.withPointPointer(body)
    }

    @usableFromInline
    package func affineCoordinates(
        group: BoringSSLEllipticCurveGroup
    ) throws(CryptoBoringWrapperError) -> (
        x: ArbitraryPrecisionInteger, y: ArbitraryPrecisionInteger
    ) {
        try self.backing.affineCoordinates(group: group)
    }
}
