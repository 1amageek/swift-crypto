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
import CryptoExtras  // NOTE: No @testable import, because we want to test the public API.
#if canImport(Dispatch)
import Dispatch
#endif
import XCTest

final class VOPRFPublicAPITests: XCTestCase {

    private func representation(
        byteCount: Int,
        write: (UnsafeMutableRawBufferPointer) throws -> Void
    ) rethrows -> Data {
        var result = Data(count: byteCount)
        try result.withUnsafeMutableBytes { destination in
            try write(destination)
        }
        return result
    }

    private func assertVOPRFError(
        _ expectedError: VOPRFError,
        file: StaticString = #filePath,
        line: UInt = #line,
        operation: () throws -> Void
    ) {
        do {
            try operation()
            XCTFail("Expected \(expectedError)", file: file, line: line)
        } catch let error as VOPRFError {
            XCTAssertEqual(error, expectedError, file: file, line: line)
        } catch {
            XCTFail("Expected \(expectedError), received \(error)", file: file, line: line)
        }
    }

    func testEndToEndVOPRF() throws {
        // [Server] Create the key-pair (other initializers are available).
        let privateKey = try P384._VOPRF.PrivateKey()

        // [Client] Obtain public key (other initializers are available).
        let publicKey = privateKey.publicKey

        // [Client] Have a private input they wish to use.
        let privateInput = Data("This is some input data".utf8)

        // [Client] Blind the private input and send the blinded element to the server.
        let blindedInput = try publicKey.blind(privateInput)

        // [Client -> Server] Send the blinded element.
        let blindedElementBytes = try blindedInput.blindedElement.oprfRepresentation()

        // [Server] Receive the blinded element.
        let blindedElement = try P384._VOPRF.BlindedElement(oprfRepresentation: blindedElementBytes)

        // [Server] Blind evaluate the blinded element and send the evaluation, along with the proof, to the client.
        let blindEvaluation = try privateKey.evaluate(blindedElement)

        // [Server -> Client] Send the serialized blind evaluation.
        let blindEvaluationBytes = try blindEvaluation.rawRepresentation()

        // [Client] Receive the blind evaluation.
        let deserializedBlindEvaluation = try P384._VOPRF.BlindEvaluation(rawRepresentation: blindEvaluationBytes)

        // [Client] Finalize the evaluation by verifying the proof and unblinding to produce the output.
        let finalizedOutput = try publicKey.finalize(blindedInput, using: deserializedBlindEvaluation)
        let directOutput = try privateKey.evaluate(privateInput)
        XCTAssertEqual(finalizedOutput, directOutput)
    }

    func testAccessToEvaluatedElementAndProof() throws {
        /// In RFC 9497, the `BlindEvaluate` routine returns both `evaluatedElement` and `proof`, which are both later
        /// provided to `Finalize`.
        ///
        /// For our API, these are bundled together into a `BlindEvaluation`, and since both are used in the final step,
        /// our `finalize` API takes the composite type too, to guide correct usage.
        ///
        /// However, for use cases that require distinct access to the evaluated element and the proof we also expose
        /// these properties as API.
        ///
        /// - See: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
        let vector = try XCTUnwrap(
            OPRFSuite.p384SHA384VOPRF().vectors.first { $0.batchSize == 1 }
        )
        let evaluatedElement = try Data(hexString: vector.evaluatedElements)
        let proof = try Data(hexString: XCTUnwrap(vector.proof).proof)
        let blindEvaluation = try P384._VOPRF.BlindEvaluation(rawRepresentation: evaluatedElement + proof)
        XCTAssertEqual(
            try blindEvaluation.evaluatedElement.oprfRepresentation(),
            evaluatedElement
        )
        XCTAssertEqual(try blindEvaluation.proof.rawRepresentation(), proof)
    }

    func testEndToEndPRF() throws {
        // [Server] Create the key-pair (other initializers are available).
        let privateKey = try P384._VOPRF.PrivateKey()

        // [Server] Have an input they wish to use.
        let input = Data("This is some input data".utf8)

        // [Server] Compute the PRF for the input, without blinding or proof generation.
        let firstOutput = try privateKey.evaluate(input)
        let secondOutput = try privateKey.evaluate(input)
        XCTAssertEqual(firstOutput, secondOutput)
    }

    func testCallerOwnedRepresentationsMatchAllocatingConveniences() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let publicKey = privateKey.publicKey
        let blindedInput = try publicKey.blind(Data("serialization".utf8))
        let blindEvaluation = try privateKey.evaluate(blindedInput.blindedElement)

        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.PrivateKey.rawRepresentationByteCount) {
                try privateKey.writeRawRepresentation(into: $0)
            },
            try privateKey.rawRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.PublicKey.oprfRepresentationByteCount) {
                try publicKey.writeOPRFRepresentation(into: $0)
            },
            try publicKey.oprfRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.BlindedElement.oprfRepresentationByteCount) {
                try blindedInput.blindedElement.writeOPRFRepresentation(into: $0)
            },
            try blindedInput.blindedElement.oprfRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.EvaluatedElement.oprfRepresentationByteCount) {
                try blindEvaluation.evaluatedElement.writeOPRFRepresentation(into: $0)
            },
            try blindEvaluation.evaluatedElement.oprfRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.Proof.rawRepresentationByteCount) {
                try blindEvaluation.proof.writeRawRepresentation(into: $0)
            },
            try blindEvaluation.proof.rawRepresentation()
        )
        XCTAssertEqual(
            try representation(byteCount: P384._VOPRF.BlindEvaluation.rawRepresentationByteCount) {
                try blindEvaluation.writeRawRepresentation(into: $0)
            },
            try blindEvaluation.rawRepresentation()
        )
    }

    func testCallerOwnedRepresentationRejectsWrongSize() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        var destination = Data(
            count: P384._VOPRF.PrivateKey.rawRepresentationByteCount - 1
        )

        assertVOPRFError(.internalFailure) {
            try destination.withUnsafeMutableBytes {
                try privateKey.writeRawRepresentation(into: $0)
            }
        }
    }

    #if canImport(Dispatch)
    func testDirectEvaluationAcceptsDiscontiguousInput() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let input = Data("discontiguous VOPRF input".utf8)
        let (_, discontiguousInput) = Array(input).asDataProtocols(splitAt: 7)

        XCTAssertEqual(
            try privateKey.evaluate(input),
            try privateKey.evaluate(discontiguousInput)
        )
    }
    #endif

    func testZeroProofIsRejectedWithoutTerminating() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let publicKey = privateKey.publicKey
        let input = Data("malicious proof".utf8)
        let blindedInput = try publicKey.blind(input)
        let validEvaluation = try privateKey.evaluate(blindedInput.blindedElement)
        let zeroProof = Data(
            repeating: 0,
            count: try validEvaluation.proof.rawRepresentation().count
        )
        let maliciousEvaluation = try P384._VOPRF.BlindEvaluation(
            rawRepresentation: try validEvaluation.evaluatedElement.oprfRepresentation() + zeroProof
        )

        assertVOPRFError(.invalidProof) {
            _ = try publicKey.finalize(blindedInput, using: maliciousEvaluation)
        }
    }

    func testPublicInputFailuresReturnTypedErrors() throws {
        let invalidCompressedPoint = Data(repeating: 0, count: 49)
        let invalidUncompressedPoint = Data(repeating: 0, count: 97)
        let zeroPrivateScalar = Data(
            repeating: 0,
            count: P384._VOPRF.PrivateKey.rawRepresentationByteCount
        )

        assertVOPRFError(.invalidPublicKey) {
            _ = try P384._VOPRF.PublicKey(
                oprfRepresentation: invalidCompressedPoint
            )
        }
        assertVOPRFError(.invalidElement) {
            _ = try P384._VOPRF.BlindedElement(
                oprfRepresentation: invalidCompressedPoint
            )
        }
        assertVOPRFError(.invalidElement) {
            _ = try P384._VOPRF.BlindedElement(
                oprfRepresentation: invalidUncompressedPoint
            )
        }
        assertVOPRFError(.invalidEncoding) {
            _ = try P384._VOPRF.BlindEvaluation(rawRepresentation: Data())
        }
        assertVOPRFError(.invalidPrivateKey) {
            _ = try P384._VOPRF.PrivateKey(
                rawRepresentation: zeroPrivateScalar
            )
        }
    }

    func testOversizedInputsReturnTypedErrors() throws {
        let privateKey = try P384._VOPRF.PrivateKey()
        let oversizedInput = Data(repeating: 0, count: Int(UInt16.max) + 1)

        assertVOPRFError(.messageTooLong) {
            _ = try privateKey.publicKey.blind(oversizedInput)
        }
        assertVOPRFError(.messageTooLong) {
            _ = try privateKey.evaluate(oversizedInput)
        }
        assertVOPRFError(.keyInfoTooLong) {
            _ = try P384._VOPRF.PrivateKey(
                seed: Data(repeating: 0, count: 32),
                keyInfo: oversizedInput
            )
        }
        assertVOPRFError(.invalidSeed) {
            _ = try P384._VOPRF.PrivateKey(
                seed: Data(repeating: 0, count: 31),
                keyInfo: Data()
            )
        }
    }

    func testDeterministicPrivateKeyMatchesRFC9497() throws {
        let suite = try OPRFSuite.p384SHA384VOPRF()
        let privateKey = try P384._VOPRF.PrivateKey(
            seed: Data(hexString: suite.seed),
            keyInfo: Data(hexString: suite.keyInfo)
        )

        XCTAssertEqual(try privateKey.rawRepresentation().hexString, suite.privateKey)
        XCTAssertEqual(
            try privateKey.publicKey.oprfRepresentation().hexString,
            try XCTUnwrap(suite.publicKey)
        )
    }
}
