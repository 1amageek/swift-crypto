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
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif
import Crypto

struct ScalarVar {
    var index: Int
}

struct PointVar {
    var index: Int
}

enum ZKPErrors: Error {
    case invalidVariableAllocation
    case invalidInputLength
    case invalidProofFields
    case invalidScalar
}

internal func cryptoExtrasError(_ error: ZKPErrors) -> CryptoKitMetaError {
    #if hasFeature(Embedded)
    cryptoExtrasError(CryptoKitError.incorrectParameterSize)
    #else
    error
    #endif
}

// A Schnorr proof, which stores the challenge instead of 
// commitments to the prover's randomness (blindedPoints).
struct Proof<H2G: HashToGroup> {
    typealias Group = H2G.G
    public let challenge: Group.Scalar
    public let responses: [Group.Scalar]

    static func composeChallenge(
        label: String,
        points: [Group.Element],
        blindedPoints: [Group.Element]
    ) throws(CryptoKitMetaError) -> Group.Scalar {
        let representationByteCount = Group.Element.oprfRepresentationByteCount
        guard
            representationByteCount > 0,
            representationByteCount <= Int(UInt16.max)
        else {
            throw cryptoExtrasError(OPRF.Errors.transcriptElementTooLong)
        }
        let domainSeparationTag = H2G.hashToScalarDomainSeparationTag(
            context: Data(label.utf8)
        )
        return try H2G.hashToScalar(
            domainSeparationTag: domainSeparationTag
        ) { (hasher: inout H2G.H) throws(CryptoKitMetaError) in
            for point in points {
                try Self.update(
                    &hasher,
                    with: point,
                    representationByteCount: representationByteCount
                )
            }
            for point in blindedPoints {
                try Self.update(
                    &hasher,
                    with: point,
                    representationByteCount: representationByteCount
                )
            }
        }
    }

    private static func update(
        _ hasher: inout H2G.H,
        with point: Group.Element,
        representationByteCount: Int
    ) throws(CryptoKitMetaError) {
        try OPRF.update(
            &hasher,
            withTwoByteInteger: representationByteCount
        )
        try withUnsafeTemporaryAllocation(
            byteCount: representationByteCount,
            alignment: 1
        ) {
            (representation: UnsafeMutableRawBufferPointer) throws(CryptoKitMetaError) in
            try point.writeOPRFRepresentation(into: representation)
            hasher.update(
                bufferPointer: UnsafeRawBufferPointer(representation)
            )
        }
    }
}

protocol ProofParticipant {
    associatedtype Point: GroupElement
    var label: String { get }
    var scalarLabels: [String] { get set }
    var points: [Point] { get set }
    var pointLabels: [String] { get set }
    var constraints: [(PointVar, [(ScalarVar, PointVar)])] { get set }
}

extension ProofParticipant {
    mutating func constrain(result: PointVar, linearCombination: [(ScalarVar, PointVar)]) {
        self.constraints.append((result, linearCombination))
    }

    mutating func appendPoint(label: String, assignment: Point) -> PointVar {
        self.pointLabels.append(label)
        self.points.append(assignment)
        return PointVar(index: self.points.count - 1)
    }
}
