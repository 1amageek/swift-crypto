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
@testable import CryptoExtras  // NOTE: @testable import, to inject fixed values from test vectors.
import XCTest

final class VOPRFAPITests: XCTestCase {
    private func singletonVectors(in suite: OPRFSuite) -> [OPRFTestVector] {
        let singletonVectors = suite.vectors.filter { $0.batchSize == 1 }
        XCTAssertEqual(singletonVectors.count, 2)
        XCTAssertEqual(suite.vectors.filter { $0.batchSize == 2 }.count, 1)
        return singletonVectors
    }

    func testVectors() throws {
        let suite = try OPRFSuite.p384SHA384VOPRF()
        try testVectorsVOPRF(suite: suite)
        try testVectorsPRF(suite: suite)
    }

    func testVectorsVOPRF(suite: OPRFSuite) throws {
        for vector in singletonVectors(in: suite) {
            // [Server] Create the key-pair.
            let privateKey = try P384._VOPRF.PrivateKey(rawRepresentation: Data(hexString: suite.privateKey))

            // [Client] Obtain public key.
            let publicKey = privateKey.publicKey

            // [Client] Have a private input they wish to use.
            let privateInput = try Data(hexString: vector.inputs)

            // [Client] Blind the private input and send the blinded element to the server.
            let fixedBlind = try P384._VOPRF.H2G.G.Scalar(canonicalRepresentation: Data(hexString: vector.blinds))
            let blindedInput = try publicKey.blind(privateInput, with: fixedBlind)

            // [Client -> Server] Send the blinded element.
            let blindedElementBytes = blindedInput.blindedElement.oprfRepresentation

            // [CHECK] Blinded element matches test vector.
            XCTAssertEqual(blindedElementBytes.hexString, vector.blindedElements)

            // [Server] Receive the blinded element.
            let blindedElement = try P384._VOPRF.BlindedElement(oprfRepresentation: blindedElementBytes)

            // [Server] Blind evaluate the blinded element and send the evaluation, along with the proof, to the client.
            let proofVector = try XCTUnwrap(vector.proof)
            let fixedProofScalar = try P384._VOPRF.H2G.G.Scalar(
                canonicalRepresentation: Data(hexString: proofVector.proofScalar)
            )
            XCTAssertNil(vector.info, "VOPRF mode shouldn't have info.")
            let blindEvaluation = try privateKey.evaluate(blindedElement, using: fixedProofScalar)

            // [CHECK] Evaluated element matches test vector.
            XCTAssertEqual(blindEvaluation.evaluatedElement.oprfRepresentation.hexString, vector.evaluatedElements)

            // [CHECK] Proof matches test vector.
            XCTAssertEqual(blindEvaluation.proof.rawRepresentation.hexString, proofVector.proof)

            // [Server -> Client] Send the serialized blind evaluation.
            let blindEvaluationBytes = blindEvaluation.rawRepresentation

            // [Client] Receive the blind evaluation.
            let deserializedBlindEvaluation = try P384._VOPRF.BlindEvaluation(rawRepresentation: blindEvaluationBytes)

            // [Client] Finalize the evaluation by verifying the proof and unblinding to produce the output.
            let output = try publicKey.finalize(blindedInput, using: deserializedBlindEvaluation)

            // [CHECK] Final output matches test vector.
            XCTAssertEqual(output.hexString, vector.outputs)
        }
    }

    func testVectorsPRF(suite: OPRFSuite) throws {
        for vector in singletonVectors(in: suite) {
            // [Server] Create the key-pair.
            let privateKey = try P384._VOPRF.PrivateKey(rawRepresentation: Data(hexString: suite.privateKey))

            // [Server] Have an input they wish to use.
            let input = try Data(hexString: vector.inputs)

            // [Server] Compute the PRF for the input, without blinding or proof generation.
            let output = try privateKey.evaluate(input)

            // [CHECK] Final output matches test vector.
            XCTAssertEqual(output.hexString, vector.outputs)
        }
    }

    func testProofRejectsNonCanonicalScalars() throws {
        let groupOrder = try Data(
            hexString:
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
        )
        var valueAboveGroupOrder = groupOrder
        valueAboveGroupOrder[valueAboveGroupOrder.index(before: valueAboveGroupOrder.endIndex)] += 1
        let canonicalZero = Data(repeating: 0, count: P384.orderByteCount)

        XCTAssertThrowsError(
            try P384._VOPRF.Proof(rawRepresentation: groupOrder + canonicalZero)
        )
        XCTAssertThrowsError(
            try P384._VOPRF.Proof(rawRepresentation: valueAboveGroupOrder + canonicalZero)
        )
        XCTAssertThrowsError(
            try P384._VOPRF.Proof(
                rawRepresentation: Data(repeating: 0, count: P384._VOPRF.Proof.serializedByteCount - 1)
            )
        )
        XCTAssertThrowsError(
            try P384._VOPRF.Proof(
                rawRepresentation: Data(repeating: 0, count: P384._VOPRF.Proof.serializedByteCount + 1)
            )
        )
    }

    func testElementRequiresCanonicalCompressedRepresentation() throws {
        let publicKey = P384.Signing.PrivateKey().publicKey
        XCTAssertNoThrow(
            try P384._VOPRF.BlindedElement(
                oprfRepresentation: publicKey.compressedRepresentation
            )
        )
        XCTAssertThrowsError(
            try P384._VOPRF.BlindedElement(oprfRepresentation: publicKey.x963Representation)
        )
        XCTAssertThrowsError(
            try P384._VOPRF.BlindedElement(oprfRepresentation: Data([0]))
        )
        XCTAssertThrowsError(
            try P384._VOPRF.BlindedElement(
                oprfRepresentation: publicKey.compressedRepresentation.dropLast()
            )
        )
        XCTAssertThrowsError(
            try P384._VOPRF.BlindedElement(
                oprfRepresentation: publicKey.compressedRepresentation + Data([0])
            )
        )
    }
}
