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
@testable import CryptoExtras
import XCTest
import Crypto

class ARCEncodingTests: XCTestCase {
    private typealias Point = P256._ARCV1.H2G.G.Element

    private func assertEqual(_ left: Point, _ right: Point) throws {
        XCTAssertTrue(try left.isEqual(to: right))
    }

    func assertServerPublicKeyEncoding() throws {
        let ciphersuite = P256._ARCV1.ciphersuite
        let server = try ARC.Server(ciphersuite: ciphersuite)
        let publicKey = server.serverPublicKey

        let publicKeyData = try publicKey.serialize()
        let publicKey2 = try ARC.ServerPublicKey<CurveHashToGroup<P256>>.deserialize(
            serverPublicKeyData: publicKeyData
        )
        try self.assertEqual(publicKey.X0, publicKey2.X0)
        try self.assertEqual(publicKey.X1, publicKey2.X1)
        try self.assertEqual(publicKey.X2, publicKey2.X2)

        let publicKeyData2 = try publicKey2.serialize()
        XCTAssertEqual(publicKeyData, publicKeyData2)
    }

    func testServerPublicKeyEncoding() throws {
        try assertServerPublicKeyEncoding()
    }

    func assertRequestEncoding() throws {
        let ciphersuite = P256._ARCV1.ciphersuite
        let server = try ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey)
        let request = precredential.credentialRequest

        let requestData = try request.serialize()
        let request2 = try ARC.CredentialRequest<CurveHashToGroup<P256>>.deserialize(
            requestData: requestData
        )
        try self.assertEqual(request.m1Enc, request2.m1Enc)
        try self.assertEqual(request.m2Enc, request2.m2Enc)
        XCTAssert(request.proof.challenge == request2.proof.challenge)
        for (index, response) in request.proof.responses.enumerated() {
            XCTAssert(response == request2.proof.responses[index])
        }

        let requestData2 = try request2.serialize()
        XCTAssertEqual(requestData, requestData2)
    }

    func testRequestEncoding() throws {
        try assertRequestEncoding()
    }

    func assertResponseEncoding() throws {
        let ciphersuite = P256._ARCV1.ciphersuite
        let server = try ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey)
        let request = precredential.credentialRequest
        let response = try server.respond(credentialRequest: request)

        let responseData = try response.serialize()
        let response2 = try ARC.CredentialResponse<CurveHashToGroup<P256>>.deserialize(
            responseData: responseData
        )
        try self.assertEqual(response.U, response2.U)
        try self.assertEqual(response.encUPrime, response2.encUPrime)
        try self.assertEqual(response.X0Aux, response2.X0Aux)
        try self.assertEqual(response.X1Aux, response2.X1Aux)
        try self.assertEqual(response.X2Aux, response2.X2Aux)
        try self.assertEqual(response.HAux, response2.HAux)
        XCTAssert(response.proof.challenge == response2.proof.challenge)
        for (index, response) in response.proof.responses.enumerated() {
            XCTAssert(response == response2.proof.responses[index])
        }

        let responseData2 = try response2.serialize()
        XCTAssertEqual(responseData, responseData2)
    }

    func testResponseEncoding() throws {
        try assertResponseEncoding()
    }

    func assertCredentialEncoding() throws {
        let ciphersuite = P256._ARCV1.ciphersuite
        let server = try ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey)
        let request = precredential.credentialRequest
        let response = try server.respond(credentialRequest: request)
        let credential = try precredential.makeCredential(credentialResponse: response)

        let credentialData = try credential.serialize()
        let credential2 = try ARC.Credential.deserialize(credentialData: credentialData, ciphersuite: ciphersuite)
        XCTAssert(credential.m1 == credential2.m1)
        try self.assertEqual(credential.U, credential2.U)
        try self.assertEqual(credential.UPrime, credential2.UPrime)
        try self.assertEqual(credential.X1, credential2.X1)
        try self.assertEqual(credential.generatorG, credential2.generatorG)
        try self.assertEqual(credential.generatorH, credential2.generatorH)
        for (key, value) in credential.presentationState.state {
            XCTAssertEqual(value.0, credential2.presentationState.state[key]?.0)
            XCTAssertEqual(value.1, credential2.presentationState.state[key]?.1)
        }

        let credentialData2 = try credential2.serialize()
        XCTAssertEqual(credentialData, credentialData2)
    }

    func testCredentialEncoding() throws {
        try assertCredentialEncoding()
    }

    func assertPresentationEncoding() throws {
        let ciphersuite = P256._ARCV1.ciphersuite
        let server = try ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey)
        let request = precredential.credentialRequest
        let response = try server.respond(credentialRequest: request)
        var credential = try precredential.makeCredential(credentialResponse: response)
        let (presentation, _) = try credential.makePresentation(presentationContext: Data("test presentation context".utf8), presentationLimit: 1)

        let presentationData = try presentation.serialize()
        let presentation2 = try ARC.Presentation<CurveHashToGroup<P256>>.deserialize(
            presentationData: presentationData
        )
        try self.assertEqual(presentation.U, presentation2.U)
        try self.assertEqual(presentation.UPrimeCommit, presentation2.UPrimeCommit)
        try self.assertEqual(presentation.m1Commit, presentation2.m1Commit)
        try self.assertEqual(presentation.tag, presentation2.tag)
        XCTAssert(presentation.proof.challenge == presentation2.proof.challenge)
        for (index, response) in presentation.proof.responses.enumerated() {
            XCTAssert(response == presentation2.proof.responses[index])
        }

        let presentationData2 = try presentation2.serialize()
        XCTAssertEqual(presentationData, presentationData2)
    }

    func testPresentationEncoding() throws {
        try assertPresentationEncoding()
    }

    func testPresentationStateEncoding() throws {
        let emptyPresentationState = ARC.PresentationState()
        let smallPresentationState = ARC.PresentationState(state: [Data("context1".utf8): (4, [1, 2, 3]), Data("context2".utf8): (10, [4, 5, 6])])
        var largePresentationState = ARC.PresentationState()
        for presentationLimit in 1..<100 {
            let presentationContext = Data("presentationContext\(presentationLimit)".utf8)
            for nonce in 0..<presentationLimit {
                let selectedNonce = try largePresentationState.update(presentationContext:presentationContext, presentationLimit: presentationLimit, optionalNonce: nonce)
                XCTAssertEqual(selectedNonce, nonce)
            }
        }

        for state in [emptyPresentationState, smallPresentationState, largePresentationState] {
            let serializedState = try state.serialize()
            XCTAssertNotNil(serializedState, "Serialized state should not be nil")

            let deserializedState = try ARC.PresentationState.deserialize(presentationStateData: serializedState)
            for (key, value) in state.state {
                XCTAssertEqual(value.0, deserializedState.state[key]?.0)
                XCTAssertEqual(value.1, deserializedState.state[key]?.1)
            }
        }
    }

    func testPresentationStateRejectsMalformedRepresentations() throws {
        let invalidIdentifier = Data(repeating: 0, count: 8)
        let missingEntry = try ARC.RepresentationWriter.representation(
            byteCount: 8
        ) { writer in
            try writer.writeUInt32(0x4152_4301)
            try writer.writeUInt32(1)
        }
        let zeroLimit = try ARC.RepresentationWriter.representation(
            byteCount: 18
        ) { writer in
            try writer.writeUInt32(0x4152_4301)
            try writer.writeUInt32(1)
            try writer.writeUInt16(0)
            try writer.writeUInt32(0)
            try writer.writeUInt32(0)
        }
        let outOfRangeNonce = try ARC.RepresentationWriter.representation(
            byteCount: 22
        ) { writer in
            try writer.writeUInt32(0x4152_4301)
            try writer.writeUInt32(1)
            try writer.writeUInt16(0)
            try writer.writeUInt32(2)
            try writer.writeUInt32(1)
            try writer.writeUInt32(2)
        }
        let duplicateNonce = try ARC.RepresentationWriter.representation(
            byteCount: 26
        ) { writer in
            try writer.writeUInt32(0x4152_4301)
            try writer.writeUInt32(1)
            try writer.writeUInt16(0)
            try writer.writeUInt32(3)
            try writer.writeUInt32(2)
            try writer.writeUInt32(1)
            try writer.writeUInt32(1)
        }

        for representation in [
            invalidIdentifier,
            missingEntry,
            zeroLimit,
            outOfRangeNonce,
            duplicateNonce,
        ] {
            XCTAssertThrowsError(
                try ARC.PresentationState.deserialize(
                    presentationStateData: representation
                )
            ) { error in
                XCTAssertEqual(error as? ARC.Errors, .invalidEncoding)
            }
        }
    }

    func testPresentationStateRepresentationIsCanonical() throws {
        let firstContext = Data("a".utf8)
        let secondContext = Data("b".utf8)
        let first = ARC.PresentationState(
            state: [
                secondContext: (4, [3, 1]),
                firstContext: (3, [2, 0]),
            ]
        )
        let second = ARC.PresentationState(
            state: [
                firstContext: (3, [0, 2]),
                secondContext: (4, [1, 3]),
            ]
        )
        XCTAssertEqual(try first.serialize(), try second.serialize())
    }

    func testPublicErrorsArePreservedAcrossARCErrorBoundary() {
        let errors: [ARCError] = [
            .invalidPrivateKey,
            .invalidPublicKey,
            .invalidCredentialRequest,
            .invalidCredentialResponse,
            .invalidCredential,
            .invalidPresentation,
            .invalidProof,
            .invalidPresentationLimit,
            .presentationLimitExceeded,
            .insufficientOutputCapacity,
            .internalFailure,
        ]
        for expectedError in errors {
            XCTAssertThrowsError(
                try withARCError(fallback: .internalFailure) {
                    throw expectedError
                }
            ) { error in
                XCTAssertEqual(error as? ARCError, expectedError)
            }
        }
    }
}
