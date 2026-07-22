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

struct OPRFSuite: Decodable {
    let groupDomainSeparationTag: String
    let identifier: String
    let keyInfo: String
    let mode: Int
    let privateKey: String
    let publicKey: String?
    let seed: String
    let vectors: [OPRFTestVector]

    private enum CodingKeys: String, CodingKey {
        case groupDomainSeparationTag = "groupDST"
        case identifier
        case keyInfo
        case mode
        case privateKey = "skSm"
        case publicKey = "pkSm"
        case seed
        case vectors
    }

    static func loadRFC9497Vectors() throws -> [Self] {
        let fileURL = try XCTUnwrap(
            Bundle.module.url(forResource: "OPRFVectors-RFC9497", withExtension: "json")
        )
        return try JSONDecoder().decode([Self].self, from: Data(contentsOf: fileURL))
    }

    static func p384SHA384VOPRF() throws -> Self {
        let suites = try loadRFC9497Vectors()
        return try XCTUnwrap(
            suites.first { $0.identifier == "P384-SHA384" && $0.mode == OPRF.Mode.verifiable.rawValue }
        )
    }
}

struct DLEQProofVector: Decodable {
    let proof: String
    let proofScalar: String

    private enum CodingKeys: String, CodingKey {
        case proof
        case proofScalar = "r"
    }
}

struct OPRFTestVector: Decodable {
    let batchSize: Int
    let blinds: String
    let blindedElements: String
    let evaluatedElements: String
    let info: String?
    let inputs: String
    let outputs: String
    let proof: DLEQProofVector?

    private enum CodingKeys: String, CodingKey {
        case batchSize = "Batch"
        case blinds = "Blind"
        case blindedElements = "BlindedElement"
        case evaluatedElements = "EvaluatedElement"
        case info = "Info"
        case inputs = "Input"
        case outputs = "Output"
        case proof = "Proof"
    }
}

private enum OPRFVectorError: Error {
    case invalidBatchField(field: String, expected: Int, actual: Int)
    case invalidMode(Int)
    case malformedProof
    case unexpectedInfo
}

final class ECVOPRFTests: XCTestCase {
    private func decodeBatch(
        _ encodedValues: String,
        field: String,
        expectedCount: Int
    ) throws -> [Data] {
        guard expectedCount > 0 else {
            throw OPRFVectorError.invalidBatchField(
                field: field,
                expected: 1,
                actual: expectedCount
            )
        }
        let components = encodedValues.split(separator: ",", omittingEmptySubsequences: false)
        guard components.count == expectedCount else {
            throw OPRFVectorError.invalidBatchField(
                field: field,
                expected: expectedCount,
                actual: components.count
            )
        }

        var values: [Data] = []
        values.reserveCapacity(components.count)
        for component in components {
            values.append(try Data(hexString: String(component)))
        }
        return values
    }

    private func proof<G: HashToGroupCurve>(
        from vector: DLEQProofVector,
        curve: G.Type
    ) throws -> DLEQProof<PrimeOrderCurveGroup<G>.Scalar> {
        guard vector.proof.count == 4 * G.orderByteCount else {
            throw OPRFVectorError.malformedProof
        }
        let midpoint = vector.proof.index(vector.proof.startIndex, offsetBy: vector.proof.count / 2)
        let challenge = try PrimeOrderCurveGroup<G>.Scalar(
            canonicalRepresentation: Data(hexString: String(vector.proof[..<midpoint]))
        )
        let response = try PrimeOrderCurveGroup<G>.Scalar(
            canonicalRepresentation: Data(hexString: String(vector.proof[midpoint...]))
        )
        return DLEQProof(challenge: challenge, response: response)
    }

    private func testSuite<G: HashToGroupCurve>(
        _ suite: OPRFSuite,
        curve: G.Type
    ) throws {
        guard let mode = OPRF.Mode(rawValue: suite.mode) else {
            throw OPRFVectorError.invalidMode(suite.mode)
        }
        typealias HashToGroup = CurveHashToGroup<G>
        let ciphersuite = OPRF.Ciphersuite<HashToGroup>()
        let derivedKeyPair = try OPRF.deriveKeyPair(
            seed: Data(hexString: suite.seed),
            info: Data(hexString: suite.keyInfo),
            mode: mode,
            ciphersuite: ciphersuite
        )
        XCTAssertEqual(derivedKeyPair.privateKey.rawRepresentation.hexString, suite.privateKey)
        if let publicKey = suite.publicKey {
            XCTAssertEqual(derivedKeyPair.publicKey.oprfRepresentation.hexString, publicKey)
        }
        switch mode {
        case .base:
            try testBaseSuite(suite, curve: curve)
        case .verifiable, .partiallyOblivious:
            try testVerifiableSuite(suite, curve: curve, mode: mode)
        }
    }

    private func testBaseSuite<G: HashToGroupCurve>(
        _ suite: OPRFSuite,
        curve: G.Type
    ) throws {
        typealias Group = PrimeOrderCurveGroup<G>
        typealias HashToGroup = CurveHashToGroup<G>

        let privateKey = try Group.Scalar(canonicalRepresentation: Data(hexString: suite.privateKey))
        let ciphersuite = OPRF.Ciphersuite<HashToGroup>()
        let client = OPRF.Client(ciphersuite: ciphersuite)
        let server = try OPRF.Server(ciphersuite: ciphersuite, privateKey: privateKey)

        XCTAssertNil(suite.publicKey)
        XCTAssertEqual(ciphersuite.identifier, suite.identifier)
        XCTAssertEqual(
            try Data(hexString: suite.groupDomainSeparationTag),
            Self.hashToGroupDomainSeparationTag(mode: .base, ciphersuite: ciphersuite)
        )

        for vector in suite.vectors {
            guard vector.info == nil else {
                throw OPRFVectorError.unexpectedInfo
            }
            let blinds = try decodeBatch(vector.blinds, field: "Blind", expectedCount: vector.batchSize)
            let inputs = try decodeBatch(vector.inputs, field: "Input", expectedCount: vector.batchSize)
            let expectedBlindedElements = try decodeBatch(
                vector.blindedElements,
                field: "BlindedElement",
                expectedCount: vector.batchSize
            )
            let expectedEvaluatedElements = try decodeBatch(
                vector.evaluatedElements,
                field: "EvaluatedElement",
                expectedCount: vector.batchSize
            )
            let expectedOutputs = try decodeBatch(vector.outputs, field: "Output", expectedCount: vector.batchSize)

            var blindScalars: [Group.Scalar] = []
            var blindedElements: [Group.Element] = []
            blindScalars.reserveCapacity(vector.batchSize)
            blindedElements.reserveCapacity(vector.batchSize)
            for index in inputs.indices {
                let expectedBlind = try Group.Scalar(canonicalRepresentation: blinds[index])
                let result = try client.blindMessage(inputs[index], blind: expectedBlind)
                XCTAssertEqual(result.blind, expectedBlind)
                XCTAssertEqual(result.blindedElement.oprfRepresentation, expectedBlindedElements[index])
                blindScalars.append(result.blind)
                blindedElements.append(result.blindedElement)
            }

            let evaluation = try server.evaluate(blindedElements: blindedElements)
            XCTAssertNil(evaluation.1)
            XCTAssertEqual(evaluation.0.count, vector.batchSize)
            for index in inputs.indices {
                XCTAssertEqual(evaluation.0[index].oprfRepresentation, expectedEvaluatedElements[index])
                let output = try client.finalize(
                    message: inputs[index],
                    info: nil,
                    blind: blindScalars[index],
                    evaluatedElement: evaluation.0[index]
                )
                XCTAssertEqual(output, expectedOutputs[index])
                XCTAssertTrue(
                    try server.outputMatchesDirectEvaluation(
                        message: inputs[index],
                        output: output,
                        info: nil
                    )
                )
            }
        }
    }

    private func testVerifiableSuite<G: HashToGroupCurve>(
        _ suite: OPRFSuite,
        curve: G.Type,
        mode: OPRF.Mode
    ) throws {
        typealias Group = PrimeOrderCurveGroup<G>
        typealias HashToGroup = CurveHashToGroup<G>

        let privateKey = try Group.Scalar(canonicalRepresentation: Data(hexString: suite.privateKey))
        let ciphersuite = OPRF.Ciphersuite<HashToGroup>()
        let client = try OPRF.VerifiableClient(ciphersuite: ciphersuite, mode: mode)
        let server = try OPRF.VerifiableServer(
            ciphersuite: ciphersuite,
            privateKey: privateKey,
            mode: mode
        )

        XCTAssertEqual(ciphersuite.identifier, suite.identifier)
        XCTAssertEqual(
            try Data(hexString: suite.groupDomainSeparationTag),
            Self.hashToGroupDomainSeparationTag(mode: mode, ciphersuite: ciphersuite)
        )
        XCTAssertEqual(server.publicKey.oprfRepresentation, try Data(hexString: XCTUnwrap(suite.publicKey)))

        for vector in suite.vectors {
            let proofVector = try XCTUnwrap(vector.proof)
            let blinds = try decodeBatch(vector.blinds, field: "Blind", expectedCount: vector.batchSize)
            let inputs = try decodeBatch(vector.inputs, field: "Input", expectedCount: vector.batchSize)
            let expectedBlindedElements = try decodeBatch(
                vector.blindedElements,
                field: "BlindedElement",
                expectedCount: vector.batchSize
            )
            let expectedEvaluatedElements = try decodeBatch(
                vector.evaluatedElements,
                field: "EvaluatedElement",
                expectedCount: vector.batchSize
            )
            let expectedOutputs = try decodeBatch(vector.outputs, field: "Output", expectedCount: vector.batchSize)
            let info = try vector.info.map(Data.init(hexString:))

            if mode == .verifiable {
                XCTAssertNil(info)
            } else {
                XCTAssertNotNil(info)
            }

            var blindScalars: [Group.Scalar] = []
            var blindedElements: [Group.Element] = []
            blindScalars.reserveCapacity(vector.batchSize)
            blindedElements.reserveCapacity(vector.batchSize)
            for index in inputs.indices {
                let expectedBlind = try Group.Scalar(canonicalRepresentation: blinds[index])
                let result = try client.blindMessage(inputs[index], blind: expectedBlind)
                XCTAssertEqual(result.blind, expectedBlind)
                XCTAssertEqual(result.blindedElement.oprfRepresentation, expectedBlindedElements[index])
                blindScalars.append(result.blind)
                blindedElements.append(result.blindedElement)
            }

            let proofScalar = try Group.Scalar(canonicalRepresentation: Data(hexString: proofVector.proofScalar))
            let evaluation = try server.evaluate(
                blindedElements: blindedElements,
                info: info,
                proofScalar: proofScalar
            )
            XCTAssertEqual(evaluation.0.count, vector.batchSize)
            for index in inputs.indices {
                XCTAssertEqual(evaluation.0[index].oprfRepresentation, expectedEvaluatedElements[index])
            }

            let expectedProof = try proof(from: proofVector, curve: curve)
            XCTAssertEqual(evaluation.1.challenge, expectedProof.challenge)
            XCTAssertEqual(evaluation.1.response, expectedProof.response)

            let outputs = try client.finalize(
                messages: inputs,
                info: info,
                blinds: blindScalars,
                blindedElements: blindedElements,
                evaluatedElements: evaluation.0,
                proof: expectedProof,
                publicKey: server.publicKey
            )
            XCTAssertEqual(outputs, expectedOutputs)
            for index in inputs.indices {
                XCTAssertTrue(
                    try server.outputMatchesDirectEvaluation(
                        message: inputs[index],
                        output: outputs[index],
                        info: info
                    )
                )
            }
        }
    }

    private static func hashToGroupDomainSeparationTag<H2G: HashToGroup>(
        mode: OPRF.Mode,
        ciphersuite: OPRF.Ciphersuite<H2G>
    ) -> Data {
        let prefix = Data("HashToGroup-".utf8)
        let context = OPRF.protocolContext(mode: mode, ciphersuite: ciphersuite)
        var domainSeparationTag = Data(capacity: prefix.count + context.count)
        domainSeparationTag.append(prefix)
        domainSeparationTag.append(context)
        return domainSeparationTag
    }

    func testRFC9497Vectors() throws {
        let suites = try OPRFSuite.loadRFC9497Vectors()
        var testedSuiteCount = 0
        var supportedVectorCount = 0
        var supportedBatchVectorCount = 0
        var unsupportedSuiteCount = 0
        var unsupportedVectorCount = 0
        var unsupportedIdentifiers = Set<String>()
        var modesByIdentifier: [String: Set<Int>] = [:]

        for suite in suites {
            modesByIdentifier[suite.identifier, default: []].insert(suite.mode)
            switch suite.identifier {
            case CurveHashToGroup<P256>.oprfCiphersuiteIdentifier:
                try testSuite(suite, curve: P256.self)
                testedSuiteCount += 1
                supportedVectorCount += suite.vectors.count
                supportedBatchVectorCount += suite.vectors.filter { $0.batchSize == 2 }.count
            case CurveHashToGroup<P384>.oprfCiphersuiteIdentifier:
                try testSuite(suite, curve: P384.self)
                testedSuiteCount += 1
                supportedVectorCount += suite.vectors.count
                supportedBatchVectorCount += suite.vectors.filter { $0.batchSize == 2 }.count
            default:
                unsupportedIdentifiers.insert(suite.identifier)
                unsupportedSuiteCount += 1
                unsupportedVectorCount += suite.vectors.count
            }
        }

        let expectedIdentifiers: Set<String> = [
            "ristretto255-SHA512",
            "decaf448-SHAKE256",
            "P256-SHA256",
            "P384-SHA384",
            "P521-SHA512",
        ]
        XCTAssertEqual(suites.count, 15)
        XCTAssertEqual(suites.reduce(0) { $0 + $1.vectors.count }, 40)
        XCTAssertEqual(Set(modesByIdentifier.keys), expectedIdentifiers)
        for identifier in expectedIdentifiers {
            XCTAssertEqual(modesByIdentifier[identifier], [0, 1, 2])
        }
        XCTAssertEqual(testedSuiteCount, 6)
        XCTAssertEqual(supportedVectorCount, 16)
        XCTAssertEqual(supportedBatchVectorCount, 4)
        XCTAssertEqual(unsupportedSuiteCount, 9)
        XCTAssertEqual(unsupportedVectorCount, 24)
        XCTAssertEqual(
            unsupportedIdentifiers,
            ["ristretto255-SHA512", "decaf448-SHAKE256", "P521-SHA512"]
        )
    }

    func testProtocolFailuresAreExplicit() throws {
        typealias HashToGroup = CurveHashToGroup<P256>
        typealias Group = HashToGroup.G

        let ciphersuite = OPRF.Ciphersuite<HashToGroup>()
        XCTAssertThrowsError(
            try OPRF.Server(ciphersuite: ciphersuite, privateKey: .zero),
            error: OPRF.Errors.invalidScalar
        )

        let privateKey = Group.Scalar.random
        let client = try OPRF.VerifiableClient(ciphersuite: ciphersuite, mode: .verifiable)
        let server = try OPRF.VerifiableServer(
            ciphersuite: ciphersuite,
            privateKey: privateKey,
            mode: .verifiable
        )
        let messages = [Data("first".utf8), Data("second".utf8)]
        let blinds = [Group.Scalar.random, Group.Scalar.random]
        var blindedElements: [Group.Element] = []
        blindedElements.reserveCapacity(messages.count)
        for index in messages.indices {
            blindedElements.append(
                try client.blindMessage(messages[index], blind: blinds[index]).blindedElement
            )
        }

        XCTAssertThrowsError(
            try server.evaluate(blindedElements: blindedElements, proofScalar: .zero),
            error: OPRF.Errors.invalidScalar
        )
        XCTAssertThrowsError(
            try server.evaluate(blindedElements: [Group.Element]()),
            error: OPRF.Errors.emptyBatch
        )
        XCTAssertThrowsError(
            try server.evaluate(blindedElements: blindedElements, info: Data()),
            error: OPRF.Errors.invalidModeForInfo
        )

        let evaluation = try server.evaluate(blindedElements: blindedElements)
        XCTAssertThrowsError(
            try client.finalize(
                messages: messages,
                info: nil,
                blinds: Array(blinds.dropLast()),
                blindedElements: blindedElements,
                evaluatedElements: evaluation.0,
                proof: evaluation.1,
                publicKey: server.publicKey
            ),
            error: OPRF.Errors.invalidBatchSize
        )
        XCTAssertThrowsError(
            try client.finalize(
                messages: messages,
                info: nil,
                blinds: blinds,
                blindedElements: blindedElements,
                evaluatedElements: Array(evaluation.0.reversed()),
                proof: evaluation.1,
                publicKey: server.publicKey
            ),
            error: OPRF.Errors.invalidProof
        )

        let baseClient = OPRF.Client(ciphersuite: ciphersuite)
        XCTAssertThrowsError(
            try baseClient.finalize(
                message: messages[0],
                info: nil,
                blind: .zero,
                evaluatedElement: evaluation.0[0]
            ),
            error: OPRF.Errors.invalidScalar
        )
        XCTAssertThrowsError(
            try baseClient.finalize(
                message: messages[0],
                info: Data(),
                blind: blinds[0],
                evaluatedElement: evaluation.0[0]
            ),
            error: OPRF.Errors.invalidModeForInfo
        )

        let partiallyObliviousServer = try OPRF.VerifiableServer(
            ciphersuite: ciphersuite,
            privateKey: privateKey,
            mode: .partiallyOblivious
        )
        XCTAssertThrowsError(
            try partiallyObliviousServer.evaluate(blindedElements: blindedElements),
            error: OPRF.Errors.missingInfo
        )
    }

    func testProtocolLengthLimitsFailBeforeProcessing() throws {
        typealias HashToGroup = CurveHashToGroup<P256>
        let ciphersuite = OPRF.Ciphersuite<HashToGroup>()
        let client = OPRF.Client(ciphersuite: ciphersuite)
        let oversizedMessage = Data(repeating: 0, count: Int(UInt16.max) + 1)
        XCTAssertThrowsError(
            try client.blindMessage(oversizedMessage),
            error: OPRF.Errors.messageTooLong
        )

        let oversizedInfo = Data(repeating: 0, count: Int(UInt16.max) + 1)
        XCTAssertThrowsError(
            try OPRF.hashInfoToScalar(
                oversizedInfo,
                domainSeparationTag: HashToGroup.hashToScalarDomainSeparationTag(
                    context: Data()
                ),
                using: HashToGroup.self
            ),
            error: OPRF.Errors.infoTooLong
        )

        let secretScalar = HashToGroup.G.Scalar.random
        let point = try HashToGroup.G.Element.generator()
        let oversizedBatch = repeatElement(point, count: Int(UInt16.max) + 2)
        XCTAssertThrowsError(
            try DLEQ<HashToGroup>.prove(
                secretScalar: secretScalar,
                generator: point,
                publicKey: secretScalar * point,
                inputs: oversizedBatch,
                outputs: oversizedBatch,
                context: Data(),
                hashToScalarDomainSeparationTag: HashToGroup.hashToScalarDomainSeparationTag(
                    context: Data()
                ),
                proofScalar: .random
            ),
            error: OPRF.Errors.batchTooLarge
        )
    }

    func testEmptyDLEQBatchFails() throws {
        typealias HashToGroup = CurveHashToGroup<P256>
        let secretScalar = HashToGroup.G.Scalar.random
        XCTAssertThrowsError(
            try DLEQ<HashToGroup>.prove(
                secretScalar: secretScalar,
                generator: HashToGroup.G.Element.generator(),
                publicKey: secretScalar * HashToGroup.G.Element.generator(),
                inputs: [HashToGroup.G.Element](),
                outputs: [HashToGroup.G.Element](),
                context: Data(),
                hashToScalarDomainSeparationTag: HashToGroup.hashToScalarDomainSeparationTag(
                    context: Data()
                ),
                proofScalar: .random
            )
        ) { error in
            guard case OPRF.Errors.emptyBatch = error else {
                return XCTFail("Expected emptyBatch, received \(error)")
            }
        }
    }

    func testZeroBlindFails() throws {
        typealias HashToGroup = CurveHashToGroup<P256>
        let client = OPRF.Client(ciphersuite: OPRF.Ciphersuite<HashToGroup>())
        XCTAssertThrowsError(try client.blindMessage(Data("input".utf8), blind: .zero)) { error in
            guard case OPRF.Errors.invalidScalar = error else {
                return XCTFail("Expected invalidScalar, received \(error)")
            }
        }
    }

    func testDistributivity() {
        let multiplier = PrimeOrderCurveGroup<P256>.Scalar.random
        let first = PrimeOrderCurveGroup<P256>.Scalar.random
        let second = PrimeOrderCurveGroup<P256>.Scalar.random

        let sum = first + second
        let firstProduct = first * multiplier
        let secondProduct = second * multiplier

        XCTAssertEqual(sum - second, first)
        XCTAssertEqual(sum - first, second)
        XCTAssertEqual(sum * multiplier - secondProduct, firstProduct)
        XCTAssertEqual(sum * multiplier - firstProduct, secondProduct)
    }

    func testDLEQProof() throws {
        typealias HashToGroup = CurveHashToGroup<P256>
        let secretScalar = HashToGroup.G.Scalar.random
        let generator = try HashToGroup.G.Element.generator()
        let publicKey = secretScalar * generator
        let input = HashToGroup.G.Element.random
        let output = secretScalar * input
        let hashToScalarDomainSeparationTag = HashToGroup.hashToScalarDomainSeparationTag(
            context: Data()
        )

        let proof = try DLEQ<HashToGroup>.prove(
            secretScalar: secretScalar,
            generator: generator,
            publicKey: publicKey,
            inputs: CollectionOfOne(input),
            outputs: CollectionOfOne(output),
            context: Data(),
            hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag,
            proofScalar: .random
        )

        XCTAssertTrue(
            try DLEQ<HashToGroup>.verify(
                generator: generator,
                publicKey: publicKey,
                inputs: CollectionOfOne(input),
                outputs: CollectionOfOne(output),
                proof: proof,
                context: Data(),
                hashToScalarDomainSeparationTag: hashToScalarDomainSeparationTag
            )
        )
    }
}
