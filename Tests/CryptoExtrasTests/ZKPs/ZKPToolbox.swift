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
@testable import CryptoExtras
import XCTest

class ZKPToolboxTests: XCTestCase {
    private enum InjectedFailure: Error {
        case randomScalarGeneration
    }

    typealias H2G = CurveHashToGroup<P384>
    typealias Group = H2G.G

    private func randomElement() throws -> Group.Element {
        let generator = try Group.Element.generator()
        return try generator.multiplied(by: Group.Scalar.randomNonzero())
    }

    /// Tests the workflow for proof creation and verification, for a simple DL proof: A=x*B for a secret scalar x
    func runDiscreteLogWorkflow() throws {
        // Prover's scope
        let (proof, point, result) = try {
            let point = try self.randomElement()
            let scalar = try Group.Scalar.randomNonzero()
            let result = try point.multiplied(by: scalar)

            var prover = Prover<H2G>(label: "DL1Test")
            let scalarVar = prover.appendScalar(label: "scalar", assignment: scalar)
            let pointVar = prover.appendPoint(label: "point", assignment: point)
            let resultVar = prover.appendPoint(label: "result", assignment: result)
            prover.constrain(result: resultVar, linearCombination: [(scalarVar, pointVar)])
            let proof = try prover.prove()
            return (proof, point, result)
        }()

        // Verifier's scope
        var verifier = Verifier<H2G>(label: "DL1Test")
        let scalarVar = verifier.appendScalar(label: "scalar")
        let pointVar = verifier.appendPoint(label: "point", assignment: point)
        let resultVar = verifier.appendPoint(label: "result", assignment: result)
        verifier.constrain(result: resultVar, linearCombination: [(scalarVar, pointVar)])
        let proofVerifies = try verifier.verify(proof: proof)
        XCTAssert(proofVerifies)

        // Test that incorrect proof elements causes proof verification to fail
        var failVerifier = Verifier<H2G>(label: "DL1Test")
        let failScalarVar = failVerifier.appendScalar(label: "scalar")
        let _ = failVerifier.appendPoint(label: "point", assignment: point)
        let failResultVar = failVerifier.appendPoint(label: "result", assignment: result)
        failVerifier.constrain(result: failResultVar, linearCombination: [(failScalarVar, failResultVar)]) // Incorrect point
        let failProofVerifies = try failVerifier.verify(proof: proof)
        XCTAssertFalse(failProofVerifies)
    }

    func testDL1() throws {
        try runDiscreteLogWorkflow()
    }

    /// Allocate group element variables and define the constraints for a DLEQ proof:
    /// result1 = scalar * point1 and result2 = scalar * point2
    /// such that log_point1(result1)==log_point2(result2), for a secret scalar.
    func constrainDiscreteLogEquality<P: ProofParticipant>(participant: inout P, scalarVar: ScalarVar,
                                            point1: Group.Element, result1: Group.Element,
                                            point2: Group.Element, result2: Group.Element) where P.Point == Group.Element {
        let point1Var = participant.appendPoint(label: "point1", assignment: point1)
        let result1Var = participant.appendPoint(label: "result1", assignment: result1)
        let point2Var = participant.appendPoint(label: "point2", assignment: point2)
        let result2Var = participant.appendPoint(label: "result2", assignment: result2)
        participant.constrain(result: result1Var, linearCombination: [(scalarVar, point1Var)])
        participant.constrain(result: result2Var, linearCombination: [(scalarVar, point2Var)])
    }

    /// Tests the workflow for proof creation and verification, for a simple DLEQ proof:
    /// For a secret scalar x, the relation between B=x*A and D=x*C is such that log_A(B)==log_C(D)
    func runDiscreteLogEqualityWorkflow() throws {
        // Prover's scope
        let (proof, point1, point2, result1, result2) = try {
            let point1 = try self.randomElement()
            let point2 = try self.randomElement()
            let scalar = try Group.Scalar.randomNonzero()
            let result1 = try point1.multiplied(by: scalar)
            let result2 = try point2.multiplied(by: scalar)

            var prover = Prover<H2G>(label: "DLEqualityTest")
            let scalarVar = prover.appendScalar(label: "scalar", assignment: scalar)
            constrainDiscreteLogEquality(participant: &prover, scalarVar: scalarVar, point1: point1, result1: result1, point2: point2, result2: result2)
            let proof = try prover.prove()
            return (proof, point1, point2, result1, result2)
        }()

        // Verifier's scope
        var verifier = Verifier<H2G>(label: "DLEqualityTest")
        let scalarVar = verifier.appendScalar(label: "scalar")
        constrainDiscreteLogEquality(participant: &verifier, scalarVar: scalarVar, point1: point1, result1: result1, point2: point2, result2: result2)
        let proofVerifies = try verifier.verify(proof: proof)
        XCTAssert(proofVerifies)

        // Test that incorrect ProofParticipant label causes proof verification to fail
        var failVerifier = Verifier<H2G>(label: "WrongTestLabel")
        let failScalarVar = failVerifier.appendScalar(label: "scalar")
        constrainDiscreteLogEquality(participant: &failVerifier, scalarVar: failScalarVar, point1: point1, result1: result1, point2: point2, result2: result2)
        let failProofVerifies = try failVerifier.verify(proof: proof)
        XCTAssertFalse(failProofVerifies)
    }

    func testDLEquality() throws {
        try runDiscreteLogEqualityWorkflow()
    }

    /// Tests the workflow for proof creation and verification, for a commitment proof: A=x*B+y*C for secret scalars x, y
    func runTwoScalarDiscreteLogWorkflow() throws {
        // Prover's scope
        let (proof, point1, point2, result) = try {
            let point1 = try self.randomElement()
            let point2 = try self.randomElement()
            let scalar1 = try Group.Scalar.randomNonzero()
            let scalar2 = try Group.Scalar.randomNonzero()
            let firstTerm = try point1.multiplied(by: scalar1)
            let secondTerm = try point2.multiplied(by: scalar2)
            let result = try firstTerm.adding(secondTerm)

            var prover = Prover<H2G>(label: "DL2Test")
            let scalar1Var = prover.appendScalar(label: "scalar1", assignment: scalar1)
            let scalar2Var = prover.appendScalar(label: "scalar2", assignment: scalar2)
            let point1Var = prover.appendPoint(label: "point1", assignment: point1)
            let point2Var = prover.appendPoint(label: "point2", assignment: point2)
            let resultVar = prover.appendPoint(label: "result", assignment: result)
            prover.constrain(result: resultVar, linearCombination: [(scalar1Var, point1Var), (scalar2Var, point2Var)])
            let proof = try prover.prove()
            return (proof, point1, point2, result)
        }()

        // Verifier's scope
        var verifier = Verifier<H2G>(label: "DL2Test")
        let scalar1Var = verifier.appendScalar(label: "scalar1")
        let scalar2Var = verifier.appendScalar(label: "scalar2")
        let point1Var = verifier.appendPoint(label: "point1", assignment: point1)
        let point2Var = verifier.appendPoint(label: "point2", assignment: point2)
        let resultVar = verifier.appendPoint(label: "result", assignment: result)
        verifier.constrain(result: resultVar, linearCombination: [(scalar1Var, point1Var), (scalar2Var, point2Var)])
        let proofVerifies = try verifier.verify(proof: proof)
        XCTAssert(proofVerifies)
    }

    func testDL2() throws {
        try runTwoScalarDiscreteLogWorkflow()
    }

    /// Tests an empty workflow, where no variables are allocated.
    func runEmptyWorkflow() throws {
        // Prover's scope
        let proof = try {
            let prover = Prover<H2G>(label: "EmptyTest")
            let proof = try prover.prove()
            return proof
        }()

        // Verifier's scope
        let verifier = Verifier<H2G>(label: "EmptyTest")
        let result = try verifier.verify(proof: proof)
        XCTAssert(result)
    }

    func testEmpty() throws {
        try runEmptyWorkflow()
    }

    func testProverRejectsEmptyLinearCombination() throws {
        let point = try self.randomElement()
        var prover = Prover<H2G>(label: "EmptyConstraint")
        let result = prover.appendPoint(label: "result", assignment: point)
        prover.constrain(result: result, linearCombination: [])

        XCTAssertThrowsError(try prover.proveWithFixedRandomness(blindings: [])) { error in
            guard let error = error as? ZKPErrors,
                case .invalidProofFields = error
            else {
                return XCTFail("Expected invalidProofFields, got \(error)")
            }
        }
    }

    func testProverPropagatesRandomScalarFailure() throws {
        var prover = Prover<H2G>(label: "RandomFailure")
        _ = prover.appendScalar(
            label: "scalar",
            assignment: try Group.Scalar.randomNonzero()
        )

        XCTAssertThrowsError(
            try prover.prove(randomScalar: {
                throw InjectedFailure.randomScalarGeneration
            })
        ) { error in
            guard let error = error as? InjectedFailure,
                case .randomScalarGeneration = error
            else {
                return XCTFail("Expected injected random failure, got \(error)")
            }
        }
    }

    func testProverRejectsZeroFixedBlinding() throws {
        var prover = Prover<H2G>(label: "ZeroBlinding")
        _ = prover.appendScalar(
            label: "scalar",
            assignment: try Group.Scalar.randomNonzero()
        )

        XCTAssertThrowsError(
            try prover.proveWithFixedRandomness(blindings: [.zero])
        ) { error in
            guard let error = error as? ZKPErrors,
                case .invalidScalar = error
            else {
                return XCTFail("Expected invalidScalar, got \(error)")
            }
        }
    }

    func testVerifierRejectsMismatchedResponseCount() throws {
        let point = try self.randomElement()
        let challenge = try Group.Scalar.randomNonzero()
        var verifier = Verifier<H2G>(label: "MissingResponse")
        let scalar = verifier.appendScalar(label: "scalar")
        let pointVariable = verifier.appendPoint(label: "point", assignment: point)
        verifier.constrain(
            result: pointVariable,
            linearCombination: [(scalar, pointVariable)]
        )

        let response = try Group.Scalar.randomNonzero()
        for responses in [[], [response, response]] {
            let proof = Proof<H2G>(challenge: challenge, responses: responses)
            XCTAssertThrowsError(try verifier.verify(proof: proof)) { error in
                guard let error = error as? ZKPErrors,
                    case .invalidProofFields = error
                else {
                    return XCTFail("Expected invalidProofFields, got \(error)")
                }
            }
        }
    }

    func testVerifierRejectsEmptyLinearCombination() throws {
        let point = try self.randomElement()
        let challenge = try Group.Scalar.randomNonzero()
        let response = try Group.Scalar.randomNonzero()
        let proof = Proof<H2G>(challenge: challenge, responses: [response])

        var verifier = Verifier<H2G>(label: "EmptyConstraint")
        _ = verifier.appendScalar(label: "scalar")
        let pointVariable = verifier.appendPoint(label: "point", assignment: point)
        verifier.constrain(result: pointVariable, linearCombination: [])

        XCTAssertThrowsError(try verifier.verify(proof: proof)) { error in
            guard let error = error as? ZKPErrors,
                case .invalidProofFields = error
            else {
                return XCTFail("Expected invalidProofFields, got \(error)")
            }
        }
    }
}
