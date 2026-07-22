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
import Synchronization

#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

/// Describes a prime-order NIST curve supported by the hash-to-group operations.
@usableFromInline
protocol HashToGroupCurve {
    associatedtype H: HashFunction

    static func runtime() throws(CryptoBoringWrapperError) -> PrimeOrderCurveRuntime

    static var cofactor: Int { get }

    static var orderByteCount: Int { get }

    static var compressedX962PointByteCount: Int { get }

    static var hashToFieldByteCount: Int { get }

    static var oprfCiphersuiteIdentifier: String { get }

    static func hashToGroup(
        _ data: UnsafeRawBufferPointer,
        domainSeparationString: UnsafeRawBufferPointer
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint

}

@usableFromInline
struct PrimeOrderCurveRuntime: Sendable {
    @usableFromInline
    let group: BoringSSLEllipticCurveGroup

    @usableFromInline
    let scalarArithmetic: FiniteFieldArithmeticContext

    @usableFromInline
    let fieldPrime: ArbitraryPrecisionInteger

    @usableFromInline
    init(
        curve: BoringSSLEllipticCurveGroup.CurveName
    ) throws(CryptoBoringWrapperError) {
        let group = try BoringSSLEllipticCurveGroup(curve)
        let scalarArithmetic = try FiniteFieldArithmeticContext(modulus: group.order)
        let fieldPrime = group.weierstrassCoefficients.field

        self.group = group
        self.scalarArithmetic = scalarArithmetic
        self.fieldPrime = fieldPrime
    }
}

/// NOTE: This conformance applies to this type from the Crypto module even if it comes from the SDK.
extension P256: HashToGroupCurve {
    @usableFromInline
    typealias H = SHA256

    private static let primeOrderCurveRuntime = Mutex<PrimeOrderCurveRuntime?>(nil)

    @usableFromInline
    static func runtime() throws(CryptoBoringWrapperError) -> PrimeOrderCurveRuntime {
        let result: Result<PrimeOrderCurveRuntime, CryptoBoringWrapperError> =
            primeOrderCurveRuntime.withLock { runtime in
            if let runtime {
                return .success(runtime)
            }
            do throws(CryptoBoringWrapperError) {
                let initializedRuntime = try PrimeOrderCurveRuntime(curve: .p256)
                runtime = initializedRuntime
                return .success(initializedRuntime)
            } catch let error {
                return .failure(error)
            }
        }
        switch result {
        case .success(let runtime):
            return runtime
        case .failure(let error):
            throw error
        }
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
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        let runtime = try Self.runtime()
        return try EllipticCurvePoint(
            hashing: data,
            to: runtime.group,
            domainSeparationTag: domainSeparationString
        )
    }
}

/// NOTE: This conformance applies to this type from the Crypto module even if it comes from the SDK.
extension P384: HashToGroupCurve {
    @usableFromInline
    typealias H = SHA384

    private static let primeOrderCurveRuntime = Mutex<PrimeOrderCurveRuntime?>(nil)

    @usableFromInline
    static func runtime() throws(CryptoBoringWrapperError) -> PrimeOrderCurveRuntime {
        let result: Result<PrimeOrderCurveRuntime, CryptoBoringWrapperError> =
            primeOrderCurveRuntime.withLock { runtime in
            if let runtime {
                return .success(runtime)
            }
            do throws(CryptoBoringWrapperError) {
                let initializedRuntime = try PrimeOrderCurveRuntime(curve: .p384)
                runtime = initializedRuntime
                return .success(initializedRuntime)
            } catch let error {
                return .failure(error)
            }
        }
        switch result {
        case .success(let runtime):
            return runtime
        case .failure(let error):
            throw error
        }
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
    ) throws(CryptoBoringWrapperError) -> EllipticCurvePoint {
        let runtime = try Self.runtime()
        return try EllipticCurvePoint(
            hashing: data,
            to: runtime.group,
            domainSeparationTag: domainSeparationString
        )
    }
}

struct PrimeOrderCurveScalar<C: HashToGroupCurve>: GroupScalar, CustomStringConvertible {
    var integer: ArbitraryPrecisionInteger

    init(_ integer: ArbitraryPrecisionInteger) {
        self.integer = integer
    }

    /// Deserializes the fixed-width canonical scalar representation defined by RFC 9497.
    init(
        canonicalRepresentation: UnsafeRawBufferPointer
    ) throws(CryptoKitMetaError) {
        guard canonicalRepresentation.count == C.orderByteCount else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        let integer = try withCryptoExtrasBoringError {
            () throws(CryptoBoringWrapperError) in
            try ArbitraryPrecisionInteger(bytes: canonicalRepresentation)
        }
        let groupOrder = try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            try C.runtime().group.order
        }
        guard integer < groupOrder else {
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
            let runtime = try C.runtime()
            switch modulus {
            case .groupOrder:
                return try runtime.scalarArithmetic.residue(integer)
            case .fieldPrime:
                return try integer.modulo(runtime.fieldPrime, nonNegative: true)
            }
        }
        return Self(reducedInteger)
    }

    static var random: Self {
        requireCryptographicInvariant("Unable to generate a group scalar") {
            try Self.randomNonzero()
        }
    }

    static func randomNonzero() throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try Self(.random(inclusiveMin: 1, exclusiveMax: runtime.group.order))
        }
    }

    consuming func adding(_ other: consuming Self) throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try Self(runtime.scalarArithmetic.add(self.integer, other.integer))
        }
    }

    consuming func subtracting(_ other: consuming Self) throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try Self(runtime.scalarArithmetic.subtract(other.integer, from: self.integer))
        }
    }

    consuming func multiplied(by other: consuming Self) throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try Self(runtime.scalarArithmetic.multiply(self.integer, other.integer))
        }
    }

    consuming func negated() throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try Self(
                runtime.scalarArithmetic.subtract(
                    self.integer,
                    from: ArbitraryPrecisionInteger.zero
                )
            )
        }
    }

    static var zero: Self {
        Self(.zero)
    }

    static func + (left: Self, right: Self) -> Self {
        requireCryptographicInvariant("Unable to add group scalars") {
            try left.adding(right)
        }
    }

    static func - (left: Self, right: Self) -> Self {
        requireCryptographicInvariant("Unable to subtract group scalars") {
            try left.subtracting(right)
        }
    }

    func inverted() throws(CryptoKitMetaError) -> Self {
        let inverse = try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try runtime.scalarArithmetic.inverse(self.integer)
        }
        guard let inverse else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        return Self(inverse)
    }

    static func * (left: Self, right: Self) -> Self {
        requireCryptographicInvariant("Unable to multiply group scalars") {
            try left.multiplied(by: right)
        }
    }

    static prefix func - (left: Self) -> Self {
        requireCryptographicInvariant("Unable to negate a group scalar") {
            try left.negated()
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

    static func generator() throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            Self(point: try C.runtime().group.generator)
        }
    }

    func isIdentity() throws(CryptoKitMetaError) -> Bool {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            try self.point.isIdentity(on: C.runtime().group)
        }
    }

    func isEqual(to other: Self) throws(CryptoKitMetaError) -> Bool {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            try self.point.isEqual(to: other.point, on: C.runtime().group)
        }
    }

    static var random: Self {
        requireCryptographicInvariant("Unable to generate a group element") {
            let runtime = try C.runtime()
            let randomBytes = SystemRandomNumberGenerator.randomBytes(count: runtime.group.order.byteCount)
            let dst = Data("Random EC Point Generation".utf8)
            let point = try EllipticCurvePoint(
                hashing: randomBytes,
                to: runtime.group,
                domainSeparationTag: dst
            )
            return Self(point: point)
        }
    }

    consuming func adding(_ other: consuming Self) throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try Self(point: self.point.adding(other.point, on: runtime.group))
        }
    }

    consuming func subtracting(_ other: consuming Self) throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try Self(point: self.point.subtracting(other.point, on: runtime.group))
        }
    }

    consuming func multiplied(by scalar: consuming Scalar) throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try Self(
                point: self.point.multiplying(
                    by: scalar.integer,
                    on: runtime.group,
                    context: runtime.scalarArithmetic
                )
            )
        }
    }

    consuming func negated() throws(CryptoKitMetaError) -> Self {
        try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try Self(point: self.point.inverting(on: runtime.group))
        }
    }

    static func + (left: Self, right: Self) -> Self {
        requireCryptographicInvariant("Unable to add group elements") {
            try left.adding(right)
        }
    }

    static func - (left: Self, right: Self) -> Self {
        requireCryptographicInvariant("Unable to subtract group elements") {
            try left.subtracting(right)
        }
    }

    static prefix func - (left: Self) -> Self {
        requireCryptographicInvariant("Unable to negate a group element") {
            try left.negated()
        }
    }

    static func * (left: Scalar, right: Self) -> Self {
        requireCryptographicInvariant("Unable to multiply a group element") {
            try right.multiplied(by: left)
        }
    }

    static func == (left: Self, right: Self) -> Bool {
        requireCryptographicInvariant("Unable to compare group elements") {
            try left.isEqual(to: right)
        }
    }
}

extension PrimeOrderCurvePoint {
    var compressedRepresentation: Data {
        var representation = Data(count: C.compressedX962PointByteCount)
        requireCryptographicInvariant("Unable to serialize a group element") {
            let runtime = try C.runtime()
            try representation.withUnsafeMutableBytes { buffer in
                try self.point.writeX962Representation(
                    compressed: true,
                    on: runtime.group,
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

    init(
        oprfRepresentation data: UnsafeRawBufferPointer
    ) throws(CryptoKitMetaError) {
        guard data.count == C.compressedX962PointByteCount else {
            throw cryptoExtrasError(CryptoKitError.incorrectParameterSize)
        }
        let point = try withCryptoExtrasBoringError { () throws(CryptoBoringWrapperError) in
            let runtime = try C.runtime()
            return try EllipticCurvePoint(
                x962Representation: data,
                on: runtime.group,
                context: runtime.scalarArithmetic
            )
        }
        self.init(point: point)
    }

    var oprfRepresentation: Data { self.compressedRepresentation }

    func writeOPRFRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws(CryptoKitMetaError) {
        do throws(CryptoBoringWrapperError) {
            let runtime = try C.runtime()
            try self.point.writeX962Representation(
                compressed: true,
                on: runtime.group,
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
    ) throws(CryptoKitMetaError) -> GE {
        precondition(G.cofactor == 1, "H2C doesn't have support for clearing co-factors.")
        precondition(!domainSeparationString.isEmpty, "DST must be non-empty.")
        do throws(CryptoBoringWrapperError) {
            return try Crypto.withUnsafeBytes(of: data) { (dataBytes) throws(CryptoBoringWrapperError) in
                try Crypto.withUnsafeBytes(of: domainSeparationString) { (domainSeparationStringBytes) throws(CryptoBoringWrapperError) in
                    PrimeOrderCurvePoint<C>(
                        point: try C.hashToGroup(
                            dataBytes,
                            domainSeparationString: domainSeparationStringBytes
                        )
                    )
                }
            }
        } catch {
            throw cryptoExtrasError(error)
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
