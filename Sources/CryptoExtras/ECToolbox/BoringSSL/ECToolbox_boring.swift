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
import Crypto
import CryptoBoringWrapper

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

/// Describes a prime-order NIST curve supported by the hash-to-group operations.
@usableFromInline
protocol HashToGroupCurve {
    associatedtype H: HashFunction

    static var group: BoringSSLEllipticCurveGroup { get }

    static var cofactor: Int { get }

    static var orderByteCount: Int { get }

    static var compressedX962PointByteCount: Int { get }

    static var hashToFieldByteCount: Int { get }

    static var oprfCiphersuiteIdentifier: String { get }

    static func hashToGroup(
        _ data: UnsafeRawBufferPointer,
        domainSeparationString: UnsafeRawBufferPointer
    ) -> EllipticCurvePoint

    static var arithmeticContext: FiniteFieldArithmeticContext { get }
}

/// NOTE: This conformance applies to this type from the Crypto module even if it comes from the SDK.
extension P256: HashToGroupCurve {
    @usableFromInline
    typealias H = SHA256

    @usableFromInline
    static let group = requireCryptographicInvariant("Unable to initialize the P-256 group") {
        try BoringSSLEllipticCurveGroup(.p256)
    }

    @inlinable
    static var cofactor: Int { 1 }

    @inlinable
    static var orderByteCount: Int { 32 }

    @inlinable
    static var compressedX962PointByteCount: Int { 33 }

    @inlinable
    static var hashToFieldByteCount: Int { 48 }

    @inlinable
    static var oprfCiphersuiteIdentifier: String { "P256-SHA256" }

    @usableFromInline
    static func hashToGroup(
        _ data: UnsafeRawBufferPointer,
        domainSeparationString: UnsafeRawBufferPointer
    ) -> EllipticCurvePoint {
        requireCryptographicInvariant("Unable to hash to the P-256 group") {
            try EllipticCurvePoint(hashing: data, to: Self.group, domainSeparationTag: domainSeparationString)
        }
    }

    @usableFromInline
    static let arithmeticContext = requireCryptographicInvariant("Unable to initialize P-256 arithmetic") {
        try FiniteFieldArithmeticContext(modulus: P256.group.order)
    }
}

/// NOTE: This conformance applies to this type from the Crypto module even if it comes from the SDK.
extension P384: HashToGroupCurve {
    @usableFromInline
    typealias H = SHA384

    @usableFromInline
    static let group = requireCryptographicInvariant("Unable to initialize the P-384 group") {
        try BoringSSLEllipticCurveGroup(.p384)
    }

    @inlinable
    static var cofactor: Int { 1 }

    @inlinable
    static var orderByteCount: Int { 48 }

    @inlinable
    static var compressedX962PointByteCount: Int { 49 }

    @inlinable
    static var hashToFieldByteCount: Int { 72 }

    @inlinable
    static var oprfCiphersuiteIdentifier: String { "P384-SHA384" }

    @usableFromInline
    static func hashToGroup(
        _ data: UnsafeRawBufferPointer,
        domainSeparationString: UnsafeRawBufferPointer
    ) -> EllipticCurvePoint {
        requireCryptographicInvariant("Unable to hash to the P-384 group") {
            try EllipticCurvePoint(hashing: data, to: Self.group, domainSeparationTag: domainSeparationString)
        }
    }

    @usableFromInline
    static let arithmeticContext = requireCryptographicInvariant("Unable to initialize P-384 arithmetic") {
        try FiniteFieldArithmeticContext(modulus: P384.group.order)
    }
}

struct PrimeOrderCurveScalar<C: HashToGroupCurve>: GroupScalar, CustomStringConvertible {
    var integer: ArbitraryPrecisionInteger

    init(_ integer: ArbitraryPrecisionInteger) {
        self.integer = integer
    }

    /// Deserializes the fixed-width canonical scalar representation defined by RFC 9497.
    init(canonicalRepresentation: Data) throws(CryptoKitMetaError) {
        guard canonicalRepresentation.count == C.orderByteCount else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        let integer = try ArbitraryPrecisionInteger(cryptoBytes: canonicalRepresentation)
        guard integer < C.group.order else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        self.init(integer)
    }

    static func reducing<Bytes: Crypto.ContiguousBytes>(
        _ uniformBytes: Bytes,
        modulo modulus: ScalarReductionModulus
    ) throws(CryptoKitMetaError) -> Self {
        let integer = try ArbitraryPrecisionInteger(cryptoBytes: uniformBytes)
        let reducedInteger = try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            switch modulus {
            case .groupOrder:
                return try C.arithmeticContext.residue(integer)
            case .fieldPrime:
                return try integer.modulo(C.group.weierstrassCoefficients.field, nonNegative: true)
            }
        }
        return Self(reducedInteger)
    }

    static var random: Self {
        requireCryptographicInvariant("Unable to generate a group scalar") {
            try Self(.random(inclusiveMin: 1, exclusiveMax: C.group.order))
        }
    }

    static var zero: Self {
        Self(.zero)
    }

    static func + (left: Self, right: Self) -> Self {
        requireCryptographicInvariant("Unable to add group scalars") {
            try Self(C.arithmeticContext.add(left.integer, right.integer))
        }
    }

    static func - (left: Self, right: Self) -> Self {
        requireCryptographicInvariant("Unable to subtract group scalars") {
            try Self(C.arithmeticContext.subtract(right.integer, from: left.integer))
        }
    }

    func inverted() throws(CryptoKitMetaError) -> Self {
        let inverse = try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            try C.arithmeticContext.inverse(self.integer)
        }
        guard let inverse else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        return Self(inverse)
    }

    static func * (left: Self, right: Self) -> Self {
        requireCryptographicInvariant("Unable to multiply group scalars") {
            try Self(C.arithmeticContext.multiply(left.integer, right.integer))
        }
    }

    static prefix func - (left: Self) -> Self {
        requireCryptographicInvariant("Unable to negate a group scalar") {
            try Self(C.arithmeticContext.subtract(left.integer, from: ArbitraryPrecisionInteger.zero))
        }
    }

    static func == (left: Self, right: Self) -> Bool {
        left.integer == right.integer
    }

    var rawRepresentation: Data {
        var representation = Data(count: C.orderByteCount)
        requireCryptographicInvariant("Unable to serialize a group scalar") {
            try representation.withUnsafeMutableBytes { destination in
                try self.writeRawRepresentation(into: destination)
            }
        }
        return representation
    }

    func writeRawRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws(CryptoKitMetaError) {
        try self.integer.writeBigEndianBytes(
            paddedToSize: C.orderByteCount,
            into: destination
        )
    }

    var description: String {
        self.rawRepresentation.hexString
    }
}

struct PrimeOrderCurvePoint<C: HashToGroupCurve>: GroupElement {
    var point: EllipticCurvePoint
    typealias Scalar = PrimeOrderCurveScalar<C>

    init(point: EllipticCurvePoint) {
        self.point = point
    }

    static var generator: Self {
        Self(point: C.group.generator)
    }

    var isIdentity: Bool {
        self.point.isIdentity(on: C.group)
    }

    static var random: Self {
        let randomBytes = SystemRandomNumberGenerator.randomBytes(count: C.group.order.byteCount)
        let dst = Data("Random EC Point Generation".utf8)
        let point = requireCryptographicInvariant("Unable to generate a group element") {
            try EllipticCurvePoint(hashing: randomBytes, to: C.group, domainSeparationTag: dst)
        }
        return Self(point: point)
    }

    static func + (left: consuming Self, right: consuming Self) -> Self {
        requireCryptographicInvariant("Unable to add group elements") {
            try Self(point: left.point.adding(right.point, on: C.group))
        }
    }

    static func - (left: consuming Self, right: consuming Self) -> Self {
        requireCryptographicInvariant("Unable to subtract group elements") {
            try Self(point: left.point.subtracting(right.point, on: C.group))
        }
    }

    static prefix func - (left: Self) -> Self {
        requireCryptographicInvariant("Unable to negate a group element") {
            try Self(point: left.point.inverting(on: C.group))
        }
    }

    static func * (left: consuming Scalar, right: consuming Self) -> Self {
        requireCryptographicInvariant("Unable to multiply a group element") {
            try Self(point: right.point.multiplying(by: left.integer, on: C.group, context: C.arithmeticContext))
        }
    }

    static func == (left: Self, right: Self) -> Bool {
        left.point.isEqual(to: right.point, on: C.group)
    }
}

extension PrimeOrderCurvePoint {
    var compressedRepresentation: Data {
        var representation = Data(count: C.compressedX962PointByteCount)
        requireCryptographicInvariant("Unable to serialize a group element") {
            try representation.withUnsafeMutableBytes { buffer in
                try self.point.writeX962Representation(
                    compressed: true,
                    on: C.group,
                    into: buffer
                )
            }
        }
        return representation
    }
}

extension PrimeOrderCurvePoint: OPRFGroupElement {
    static var oprfRepresentationByteCount: Int {
        C.compressedX962PointByteCount
    }

    init(oprfRepresentation data: Data) throws(CryptoKitMetaError) {
        guard data.count == C.compressedX962PointByteCount else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        let point = try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            try EllipticCurvePoint(x962Representation: data, on: C.group, context: C.arithmeticContext)
        }
        self.init(point: point)
    }

    var oprfRepresentation: Data { self.compressedRepresentation }

    func writeOPRFRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws(CryptoKitMetaError) {
        do throws(CryptoBoringWrapperError) {
            try self.point.writeX962Representation(
                compressed: true,
                on: C.group,
                into: destination
            )
        } catch {
            throw cryptoExtrasError(error)
        }
    }
}

struct PrimeOrderCurveGroup<C: HashToGroupCurve>: Group {
    typealias Element = PrimeOrderCurvePoint<C>

    static var cofactor: Int {
        // NOTE: Practically, this is always 1, because this type is only generic over our NIST curves.
        C.cofactor
    }
}

struct CurveHashToGroup<C: HashToGroupCurve>: HashToGroup {
    typealias H = C.H
    typealias GE = PrimeOrderCurvePoint<C>
    typealias G = PrimeOrderCurveGroup<C>

    static var oprfCiphersuiteIdentifier: String { C.oprfCiphersuiteIdentifier }

    static func hashToScalar(
        domainSeparationTag: Data,
        updateInput: (inout C.H) throws(CryptoKitMetaError) -> Void
    ) throws(CryptoKitMetaError) -> GE.Scalar {
        return try HashToField<C>.hashToFieldElement(
            dst: domainSeparationTag,
            reductionModulus: .groupOrder,
            updateInput: updateInput
        )
    }

    static func hashToGroup<Bytes: Crypto.ContiguousBytes>(
        _ data: Bytes,
        domainSeparationString: Data
    ) -> GE {
        precondition(G.cofactor == 1, "H2C doesn't have support for clearing co-factors.")
        precondition(!domainSeparationString.isEmpty, "DST must be non-empty.")
        return data.withUnsafeBytes { dataBytes in
            domainSeparationString.withUnsafeBytes { domainSeparationStringBytes in
                PrimeOrderCurvePoint<C>(
                    point: C.hashToGroup(
                        dataBytes,
                        domainSeparationString: domainSeparationStringBytes
                    )
                )
            }
        }
    }
}

@usableFromInline
func requireCryptographicInvariant<Result>(
    _ message: StaticString,
    _ operation: () throws -> Result
) -> Result {
    do {
        return try operation()
    } catch {
        preconditionFailure("\(message)")
    }
}
