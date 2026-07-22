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

class ARCTests: XCTestCase {
    private typealias Group = PrimeOrderCurveGroup<P256>

    private func assertEqual(_ left: Group.Element, _ right: Group.Element) throws {
        XCTAssertTrue(try left.isEqual(to: right))
    }

    func assertEndToEndWorkflow() throws {
        let ciphersuite = P256._ARCV1.ciphersuite
        let (generatorG, generatorH) = try ARC.getGenerators(suite: ciphersuite)

        // Create a server, passing in the server keys and key blinding.
        let x0 = try Group.Scalar.randomNonzero()
        let x1 = try Group.Scalar.randomNonzero()
        let x2 = try Group.Scalar.randomNonzero()
        let x0Blinding = try Group.Scalar.randomNonzero()
        let serverPrivateKey = ARC.ServerPrivateKey(x0: x0, x1: x1, x2: x2, x0Blinding: x0Blinding)
        let server = try ARC.Server(ciphersuite: ciphersuite, x0: x0, x1: x1, x2: x2, x0Blinding: x0Blinding)
        let serverPublicKey = server.serverPublicKey
        let x0Commitment = try generatorG.multiplied(by: x0)
        let x0BlindingCommitment = try generatorH.multiplied(by: x0Blinding)
        try self.assertEqual(
            serverPublicKey.X0,
            x0Commitment.adding(x0BlindingCommitment)
        )
        try self.assertEqual(serverPublicKey.X1, generatorH.multiplied(by: x1))
        try self.assertEqual(serverPublicKey.X2, generatorH.multiplied(by: x2))

        // Create a client with two private attributes.
        let presentationLimit = 2
        let requestContext = Data("test request context".utf8)
        let m1 = try Group.Scalar.randomNonzero()
        let r1 = try Group.Scalar.randomNonzero()
        let r2 = try Group.Scalar.randomNonzero()
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, m1: m1, requestContext: requestContext, r1: r1, r2: r2, serverPublicKey: serverPublicKey)

        // Client makes an CredentialRequest using its private attributes.
        let request = precredential.credentialRequest
        let r1Commitment = try generatorH.multiplied(by: r1)
        let m1Decrypted = try request.m1Enc.subtracting(r1Commitment)
        try self.assertEqual(m1Decrypted, generatorG.multiplied(by: m1))
        let r2Commitment = try generatorH.multiplied(by: r2)
        let m2Decrypted = try request.m2Enc.subtracting(r2Commitment)
        try self.assertEqual(
            m2Decrypted,
            generatorG.multiplied(by: precredential.clientSecrets.m2)
        )
        XCTAssert(try request.verify(generatorG: generatorG, generatorH: generatorH, ciphersuite: ciphersuite))

        // Server receives the CredentialRequest, and makes an CredentialResponse with its server keys.
        let issuance = try server.respond(credentialRequest: request)
        let r1X1 = try issuance.X1Aux.multiplied(by: r1)
        let r2X2 = try issuance.X2Aux.multiplied(by: r2)
        let decryptedUPrime = try issuance.encUPrime
            .subtracting(issuance.X0Aux)
            .subtracting(r1X1)
            .subtracting(r2X2)
        let m1x1 = try m1.multiplied(by: x1)
        let m2x2 = try precredential.clientSecrets.m2.multiplied(by: x2)
        let credentialScalar = try x0.adding(m1x1).adding(m2x2)
        try self.assertEqual(
            decryptedUPrime,
            issuance.U.multiplied(by: credentialScalar)
        )

        // Client receives the CredentialResponse, and uses it to make a credential from the precredential.
        var credential = try precredential.makeCredential(credentialResponse: issuance)
        XCTAssertNotNil(credential)

        // Client makes two Presentations from the Credential.
        // Note that in practice, the definition of presentationContext would depend on the use case of the tag (e.g. rate limiting).
        let presentationContext = Data("0123456789".utf8)
        let (presentation1, nonce1) = try credential.makePresentation(presentationContext: presentationContext, presentationLimit: presentationLimit)
        let (presentation2, nonce2) = try credential.makePresentation(presentationContext: presentationContext, presentationLimit: presentationLimit)
        XCTAssertNotNil(presentation1)
        XCTAssertNotNil(presentation2)

        // We hit the limit for the presentationContext, and should not receive any new presentations
        XCTAssertThrowsError(try credential.makePresentation(presentationContext: presentationContext, presentationLimit: presentationLimit), error: ARC.Errors.presentationLimitExceeded)
        // But we can make more presentations under a different presentationContext
        let newPresentationContext = Data("ABCDEF".utf8)
        let (presentation3, nonce3) = try credential.makePresentation(presentationContext: newPresentationContext, presentationLimit: presentationLimit)
        XCTAssertNotNil(presentation3)

        // Server verifies Presentation1 with its server keys.
        XCTAssert(try server.verify(presentation: presentation1, requestContext: requestContext, presentationContext: presentationContext, presentationLimit: presentationLimit, nonce: nonce1))
        // Verify presentation individually
        let serverX1 = try generatorH.multiplied(by: x1)
        XCTAssert(try presentation1.verify(
            serverPrivateKey: serverPrivateKey,
            X1: serverX1,
            m2: precredential.clientSecrets.m2,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce1,
            generatorG: generatorG,
            generatorH: generatorH,
            ciphersuite: ciphersuite))

        // Server verifies Presentation2 with its server keys.
        XCTAssert(try server.verify(
            presentation: presentation2,
            requestContext: requestContext,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce2))
        // Verify presentation individually
        XCTAssert(try presentation2.verify(
            serverPrivateKey: serverPrivateKey,
            X1: serverX1,
            m2: precredential.clientSecrets.m2,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce2,
            generatorG: generatorG,
            generatorH: generatorH,
            ciphersuite: ciphersuite))

        // Test that two presentations with the same presentationContext and privateAttribute,
        // but difference nonces, have different tag elements
        XCTAssertNotEqual(presentation1.tag.compressedRepresentation, presentation2.tag.compressedRepresentation)

        // Server verifies Presentation3 with its server keys.
        XCTAssert(try server.verify(presentation: presentation3, requestContext: requestContext, presentationContext: newPresentationContext, presentationLimit: presentationLimit, nonce: nonce3))

        // Test that verifying Presentation3 with the wrong presentationContext fails.
        XCTAssertFalse(try server.verify(
            presentation: presentation3,
            requestContext: requestContext,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce3))
        // Test that verifying Presentation3 with an invalid presentationLimit fails.
        XCTAssertFalse(try server.verify(
            presentation: presentation3,
            requestContext: requestContext,
            presentationContext: newPresentationContext,
            presentationLimit: 0,
            nonce: nonce3))
        // Test that verifying Presentation1 with the wrong nonce fails.
        XCTAssertFalse(try server.verify(
            presentation: presentation1,
            requestContext: requestContext,
            presentationContext: newPresentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce2))
        // Test that verifying Presentation1 with the wrong request context fails.
        XCTAssertFalse(try server.verify(
            presentation: presentation1,
            requestContext: Data("wrong request context".utf8),
            presentationContext: newPresentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce1))

        // Test that verifying with the wrong server (wrong server keys) fails.
        let wrongServer = try ARC.Server(ciphersuite: ciphersuite)
        XCTAssertFalse(try wrongServer.verify(
            presentation: presentation3,
            requestContext: requestContext,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce3))
    }

    func testEndToEndWorkflow() throws {
        try assertEndToEndWorkflow()
    }

    func testFailedPresentationDoesNotConsumeNonce() throws {
        let ciphersuite = P256._ARCV1.ciphersuite
        let server = try ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("request context".utf8)
        let precredential = try ARC.Precredential(
            ciphersuite: ciphersuite,
            requestContext: requestContext,
            serverPublicKey: server.serverPublicKey
        )
        let response = try server.respond(
            credentialRequest: precredential.credentialRequest
        )
        let credential = try precredential.makeCredential(
            credentialResponse: response
        )

        var oneBytes = Data(repeating: 0, count: ciphersuite.scalarByteCount)
        oneBytes[oneBytes.index(before: oneBytes.endIndex)] = 1
        let one = try Group.Scalar(canonicalRepresentation: oneBytes)
        let negativeOne = try one.negated()
        var failingCredential = ARC.Credential(
            m1: negativeOne,
            U: credential.U,
            UPrime: credential.UPrime,
            X1: credential.X1,
            ciphersuite: credential.ciphersuite,
            generatorG: credential.generatorG,
            generatorH: credential.generatorH,
            presentationState: ARC.PresentationState()
        )

        let presentationContext = Data("presentation context".utf8)
        let a = try Group.Scalar.randomNonzero()
        let r = try Group.Scalar.randomNonzero()
        let z = try Group.Scalar.randomNonzero()
        XCTAssertThrowsError(
            try failingCredential.makePresentation(
                presentationContext: presentationContext,
                presentationLimit: 2,
                a: a,
                r: r,
                z: z,
                optionalNonce: 1
            )
        )
        XCTAssertTrue(failingCredential.presentationState.state.isEmpty)
    }

    func testPresentationState() throws {
        let context1 = Data("context1".utf8)
        let context2 = Data("context2".utf8)
        var smallPresentationState = ARC.PresentationState(state: [context1: (4, [0, 1, 2]), context2: (10, [3, 4, 5, 6])])

        // Test that a new nonce is selected correctly
        XCTAssertEqual(3, try smallPresentationState.update(presentationContext: context1, presentationLimit: 4))
        XCTAssertEqual(0, try smallPresentationState.update(presentationContext: Data("context 3".utf8), presentationLimit: 1))
        XCTAssert(try smallPresentationState.update(presentationContext: context2, presentationLimit: 10) < 10)
        // Test that exceeding the rate limit for a presentationContext throws an error
        XCTAssertThrowsError(try smallPresentationState.update(presentationContext: context1, presentationLimit: 4), error: ARC.Errors.presentationLimitExceeded)
        // Test that reusing a nonce for a presentationContext throws an error
        XCTAssertThrowsError(try smallPresentationState.update(presentationContext: context2, presentationLimit: 10, optionalNonce: 3), error: ARC.Errors.presentationLimitExceeded)
        // Test that using an incorrect presentationLimit throws an error
        XCTAssertThrowsError(try smallPresentationState.update(presentationContext: context2, presentationLimit: 9), error: ARC.Errors.invalidPresentationLimit)
        XCTAssertThrowsError(try smallPresentationState.update(presentationContext: Data("context 4".utf8), presentationLimit: 0), error: ARC.Errors.invalidPresentationLimit)

        var largePresentationState = ARC.PresentationState()
        for presentationLimit in 1..<100 {
            let presentationContext = Data("presentationContext\(presentationLimit)".utf8)
            for _ in 0..<presentationLimit {
                let nonce = try largePresentationState.update(presentationContext:presentationContext, presentationLimit: presentationLimit)
                XCTAssert(nonce < presentationLimit)
                // Test that reusing a nonce for a presentationContext throws an error
                XCTAssertThrowsError(try largePresentationState.update(presentationContext: presentationContext, presentationLimit: presentationLimit, optionalNonce: nonce), error: ARC.Errors.presentationLimitExceeded)
            }
            // Test that exceeding the rate limit for a presentationContext throws an error
            XCTAssertThrowsError(try largePresentationState.update(presentationContext: presentationContext, presentationLimit: presentationLimit), error: ARC.Errors.presentationLimitExceeded)
            guard let storedState = largePresentationState.state[presentationContext] else {
                return XCTFail("Expected stored presentation state")
            }
            XCTAssertEqual(storedState.1.count, presentationLimit)
            // Test that using an incorrect presentationLimit throws an error
            XCTAssertThrowsError(try largePresentationState.update(presentationContext: presentationContext, presentationLimit: presentationLimit-1), error: ARC.Errors.invalidPresentationLimit)
        }
    }
}
