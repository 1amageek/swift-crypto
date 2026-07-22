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

struct Verifier<H2G: HashToGroup>: ProofParticipant {
    typealias Group = H2G.G
    var label: String
    var scalarLabels: [String]
    var points: [Group.Element]
    var pointLabels: [String]
    var constraints: [(PointVar, [(ScalarVar, PointVar)])]

    init(label: String) {
        self.label = label
        self.scalarLabels = []
        self.points = []
        self.pointLabels = []
        self.constraints = []
    }

    mutating func appendScalar(label: String) -> ScalarVar {
        self.scalarLabels.append(label)
        return ScalarVar(index: self.scalarLabels.count - 1)
    }

    func verify(proof: Proof<H2G>) throws(CryptoKitMetaError) -> Bool {
        // Perform size checks on proof fields.
        if self.points.count != self.pointLabels.count
            || proof.responses.count != self.scalarLabels.count
        {
            throw cryptoExtrasError(ZKPErrors.invalidProofFields)
        }

        // For each constraint, recompute the blinded version of the constraint element.
        // Example: if the constraint is A=x*B, compute ABlind=challenge*A + xResponse*B
        // Example: if the constraint is A=x*B+y*C, compute ABlind=challenge*A + xResponse*B + yResponse*C
        var blindedPoints: [Group.Element] = []
        for (constraintPoint, linearCombination) in self.constraints {
            guard !linearCombination.isEmpty else {
                throw cryptoExtrasError(ZKPErrors.invalidProofFields)
            }

            // Check that all PointVar and ScalarVar variables in the constraint have been correctly allocated.
            if !(0..<self.points.count).contains(constraintPoint.index) {
                throw cryptoExtrasError(ZKPErrors.invalidVariableAllocation)
            }
            for (scalarVar, pointVar) in linearCombination {
                if !(0..<proof.responses.count).contains(scalarVar.index)
                    || !(0..<self.points.count).contains(pointVar.index)
                {
                    throw cryptoExtrasError(ZKPErrors.invalidVariableAllocation)
                }
            }

            // challenge * constraintPoint
            var blindedPoint = try self.points[constraintPoint.index].multiplied(
                by: proof.challenge
            )
            for (scalar, point) in linearCombination {
                let responsePoint = try self.points[point.index].multiplied(
                    by: proof.responses[scalar.index]
                )
                blindedPoint = try blindedPoint.adding(responsePoint)
            }

            blindedPoints.append(blindedPoint)
        }

        // Obtain a scalar challenge.
        let challenge = try Proof<H2G>.composeChallenge(
            label: self.label,
            points: self.points,
            blindedPoints: blindedPoints
        )

        return challenge == proof.challenge
    }
}
