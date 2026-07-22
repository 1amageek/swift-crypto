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

struct Prover<H2G: HashToGroup>: ProofParticipant {
    typealias Group = H2G.G
    var label: String
    var scalars: [Group.Scalar]
    var scalarLabels: [String]
    var points: [Group.Element]
    var pointLabels: [String]
    var constraints: [(PointVar, [(ScalarVar, PointVar)])]

    init(label: String) {
        self.label = label
        self.scalars = []
        self.scalarLabels = []
        self.points = []
        self.pointLabels = []
        self.constraints = []
    }

    mutating func appendScalar(label: String, assignment: Group.Scalar) -> ScalarVar {
        self.scalarLabels.append(label)
        self.scalars.append(assignment)
        return ScalarVar(index: self.scalars.count - 1)
    }

    func prove() throws(CryptoKitMetaError) -> Proof<H2G> {
        try self.prove(randomScalar: Group.Scalar.randomNonzero)
    }

    func prove(
        randomScalar: () throws(CryptoKitMetaError) -> Group.Scalar
    ) throws(CryptoKitMetaError) -> Proof<H2G> {
        // Create a blinding scalar for each scalar variable.
        var blindings: [Group.Scalar] = []
        blindings.reserveCapacity(self.scalars.count)
        for _ in self.scalars.indices {
            blindings.append(try randomScalar())
        }
        return try self.proveWithFixedRandomness(blindings: blindings)
    }

    // Pass in externally generated blinding values, for generating or testing against test vectors.
    func proveWithFixedRandomness(blindings: [Group.Scalar]) throws(CryptoKitMetaError) -> Proof<H2G> {
        // Perform size checks on proof fields.
        if (self.scalars.count != self.scalarLabels.count) || (self.points.count != self.pointLabels.count) {
            throw cryptoExtrasError(ZKPErrors.invalidProofFields)
        }
        // Check that there is one blinding scalar for each allocated scalar variable.
        if (blindings.count != self.scalars.count) {
            throw cryptoExtrasError(ZKPErrors.invalidInputLength)
        }
        if blindings.contains(.zero) {
            throw cryptoExtrasError(ZKPErrors.invalidScalar)
        }

        // For each constraint, compute the blinded version of the constraint element.
        // Example: if the constraint is A=x*B, compute ABlind=xBlind*B for blinding scalar xBlind.
        // Example: if the constraint is A=x*B+y*C, compute ABlind=xBlind*B + yBlind*C for blinding scalars xBlind, yBlind.
        var blindedPoints: [Group.Element] = []
        for (constraintPoint, linearCombination) in self.constraints {
            // Check that all PointVar and ScalarVar variables in the constraint have been correctly allocated.
            if !(0..<self.points.count).contains(constraintPoint.index) {
                throw cryptoExtrasError(ZKPErrors.invalidVariableAllocation)
            }
            for (scalarVar, pointVar) in linearCombination {
                if !(0..<self.scalars.count).contains(scalarVar.index) || !(0..<self.points.count).contains(pointVar.index) {
                    throw cryptoExtrasError(ZKPErrors.invalidVariableAllocation)
                }
            }

            guard let firstTerm = linearCombination.first else {
                throw cryptoExtrasError(ZKPErrors.invalidProofFields)
            }

            var blindedPoint = try self.points[firstTerm.1.index].multiplied(
                by: blindings[firstTerm.0.index]
            )
            for (scalar, point) in linearCombination.dropFirst() {
                let product = try self.points[point.index].multiplied(
                    by: blindings[scalar.index]
                )
                blindedPoint = try blindedPoint.adding(product)
            }

            blindedPoints.append(blindedPoint)
        }

        // Obtain a scalar challenge.
        let challenge = try Proof<H2G>.composeChallenge(
            label: self.label,
            points: self.points,
            blindedPoints: blindedPoints
        )

        // Compute response scalars from the challenge, scalars, and blindings.
        // Example: if the scalar is m, compute mResponse = mBlind - challenge * m for blinding scalar xBlind.
        var responses: [Group.Scalar] = []
        for (index, scalar) in self.scalars.enumerated() {
            let blinding = blindings[index]
            let challengeResponse = try challenge.multiplied(by: scalar)
            responses.append(try blinding.subtracting(challengeResponse))
        }

        return Proof(challenge: challenge, responses: responses)
    }
}
