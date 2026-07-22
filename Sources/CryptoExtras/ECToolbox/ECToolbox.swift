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
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

/// A prime-order group
protocol Group {
    /// Group element
    associatedtype Element: GroupElement

    /// Group scalar (mod p) where p is the order of the group
    typealias Scalar = Element.Scalar

    /// Cofactor of the group
    static var cofactor: Int { get }
}

protocol HashToGroup {
    associatedtype H: HashFunction
    associatedtype G: Group where G.Element: OPRFGroupElement

    static var oprfCiphersuiteIdentifier: String { get }
    static func hashToScalar(
        _ data: Data,
        domainSeparationTag: Data
    ) throws(CryptoKitMetaError) -> G.Scalar
    static func hashToScalar(
        domainSeparationTag: Data,
        updateInput: (inout H) throws(CryptoKitMetaError) -> Void
    ) throws(CryptoKitMetaError) -> G.Scalar
    static func hashToGroup<Bytes: Crypto.ContiguousBytes>(
        _ data: Bytes,
        domainSeparationString: Data
    ) throws(CryptoKitMetaError) -> G.Element
}

extension HashToGroup {
    static func hashToScalar(
        _ data: Data,
        domainSeparationTag: Data
    ) throws(CryptoKitMetaError) -> G.Scalar {
        try hashToScalar(domainSeparationTag: domainSeparationTag) { hasher in
            hasher.update(data: data)
        }
    }

    static func hashToScalarDomainSeparationTag(context: Data) -> Data {
        let prefix = Data("HashToScalar-".utf8)
        var domainSeparationTag = Data(capacity: prefix.count + context.count)
        domainSeparationTag.append(prefix)
        domainSeparationTag.append(context)
        return domainSeparationTag
    }

    static func hashToGroupDomainSeparationTag(context: Data) -> Data {
        let prefix = Data("HashToGroup-".utf8)
        var domainSeparationTag = Data(capacity: prefix.count + context.count)
        domainSeparationTag.append(prefix)
        domainSeparationTag.append(context)
        return domainSeparationTag
    }

    static func hashToScalar(
        _ data: Data,
        domainSeparationContext: Data
    ) throws(CryptoKitMetaError) -> G.Scalar {
        try hashToScalar(
            data,
            domainSeparationTag: hashToScalarDomainSeparationTag(
                context: domainSeparationContext
            )
        )
    }
}

enum ScalarReductionModulus {
    case groupOrder
    case fieldPrime
}

protocol GroupScalar: Sendable, Equatable {
    init(
        canonicalRepresentation: UnsafeRawBufferPointer
    ) throws(CryptoKitMetaError)

    static func reducing<Bytes: Crypto.ContiguousBytes>(
        _ uniformBytes: Bytes,
        modulo modulus: ScalarReductionModulus
    ) throws(CryptoKitMetaError) -> Self

    var rawRepresentation: Data { get }

    func writeRawRepresentation(
        into destination: UnsafeMutableRawBufferPointer
    ) throws(CryptoKitMetaError)

    /// Generates a uniformly random nonzero scalar.
    static func randomNonzero() throws(CryptoKitMetaError) -> Self

    consuming func adding(_ other: consuming Self) throws(CryptoKitMetaError) -> Self

    consuming func subtracting(_ other: consuming Self) throws(CryptoKitMetaError) -> Self

    consuming func multiplied(by other: consuming Self) throws(CryptoKitMetaError) -> Self

    consuming func negated() throws(CryptoKitMetaError) -> Self

    static var zero: Self { get }

    func inverted() throws(CryptoKitMetaError) -> Self

    // Constant-time Comparison
    static func == (left: Self, right: Self) -> Bool
}

extension GroupScalar {
    init<Bytes: Crypto.ContiguousBytes>(
        canonicalRepresentation bytes: Bytes
    ) throws(CryptoKitMetaError) {
        self = try Crypto.withUnsafeBytes(of: bytes) {
            (buffer: UnsafeRawBufferPointer) throws(CryptoKitMetaError) in
            try Self(canonicalRepresentation: buffer)
        }
    }
}

protocol GroupElement: Sendable {
    associatedtype Scalar: GroupScalar

    static func generator() throws(CryptoKitMetaError) -> Self

    func isIdentity() throws(CryptoKitMetaError) -> Bool

    func isEqual(to other: Self) throws(CryptoKitMetaError) -> Bool

    consuming func adding(_ other: consuming Self) throws(CryptoKitMetaError) -> Self

    consuming func subtracting(_ other: consuming Self) throws(CryptoKitMetaError) -> Self

    consuming func multiplied(by scalar: consuming Scalar) throws(CryptoKitMetaError) -> Self

    consuming func negated() throws(CryptoKitMetaError) -> Self

}
