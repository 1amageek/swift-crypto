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

let ARCEncodedTestVector = """
[
  {
    "Credential": {
      "U": "033ee1ebbcff622bc26b10932ed1eb147226d832048fb2337dc0ad7722cb07483d",
      "U_prime": "02637fe04cc143281ee607bd8f898e670293dce44a2840b9cbb9e0d1fc7a2b29b4",
      "X1": "03c413230a9bd956718aa46138a33f774f4c708d61c1d6400d404243049d4a31dc",
      "m1": "eedfe7939e2382934ab5b0f76aae44124955d2c5ebf9b41d88786259c34692d2"
    },
    "CredentialRequest": {
      "m1": "eedfe7939e2382934ab5b0f76aae44124955d2c5ebf9b41d88786259c34692d2",
      "m1_enc": "03b8f11506a5302424143573e087fa20195cb5e893a67ef354eae3a78e263c54e4",
      "m2": "911fb315257d9ae29d47ecb48c6fa27074dee6860a0489f8db6ac9a486be6a3e",
      "m2_enc": "03f1ae4d7b78ba8030bd63859d4f4a909395c52bda34716b6620a2fdd52b336fc9",
      "proof": "0f361327abbc724ff0d37db365065bc4bd60e18125842bb4c03a7e5a632a1e95e74dcc440fcb9fb39106922e0d2544e6c82ca710abf35e8b10bf5d61296c9adb7d683eaed9a76a755b73f2b4b6e763a7c7883ce4b5c21bd02cd96b9af18cfb227f1acb4ead77c85049d291ed7841405610843f163e9cc2f6a8869111582324cd32bf13000c129d274ccf5386cb90e839916d5dff7eade18e3eabec415f613911",
      "r1": "008035081690bfde3b1e68b91443c22cc791d244340fe957d5aa44d7313740df",
      "r2": "d59c5e6ff560cc597c2b8ca25256c720bceca2ab03921492c5e9e4ad3b558002",
      "request_context": "74657374207265717565737420636f6e74657874"
    },
    "CredentialResponse": {
      "H_aux": "03d3cd09eeb8d19716586a49260c69309c495a717a36cad3381f6c02ac80b70e64",
      "U": "033ee1ebbcff622bc26b10932ed1eb147226d832048fb2337dc0ad7722cb07483d",
      "X0_aux": "02d453c121324114367906bd11ffc3b6e6a77b75382497279b1a60ab8412c1dec6",
      "X1_aux": "03b0e4b1f376c6207bf34efda46ce54b132a20b90bc28b9152f3e441fe2b508b63",
      "X2_aux": "0327369efcb7577abaeb7b56940e6e042126900bdf8bd8944c0adbb7be3ad98e2a",
      "b": "e699140babbe599f7dd8f6e3e8f615e5f201d1c2b0bc2f821f19e80a0a0e1e7b",
      "enc_U_prime": "035b8e09ce8776f1a2c7ef8610c9a6a39936c5666ab8b28d6629d3685056716482",
      "proof": "dd4596175db0b4273fcdff330370d2b5e7a4bf92bf518141f4553af37ef0e1260cb8312affc2462800adba102117448b449985d1704d8afd0df9ac708231561dca56faae325cb56b0a9e8ad07bdc6ce90f6e7430090e970a7240e289218de7a17672bea9a66187d102ffef976fb01af69d8d3aa3156a5a4223dc6d08b8ce9f1d2639a2edc7052404bf1410adf6c41465bd687e3dfa5372ea71f804b56d947bae9482e5707f42dbe35f8b0e11b4a0d27a5a01e1b9a75b66d82b7945eb0b002ee400bebcdc4c3133f804b22bd2d771762058cc35a5033365d2e15150fe46d3b0e98e18ee55f0451b0b171420f73592292e4ff50603c1f0d7769dbd090936090f63"
    },
    "Presentation1": {
      "U": "032704f22133d2ec70f9e6f4bbf64c582220b666f2e2c1d37c3f8995a2a5568c7e",
      "U_prime_commit": "03533cf1b2fd53a0716e02425eb42e4c55835aa6b2992d364cba70810d0f8aeb51",
      "a": "b78e57df8f0a95d102ff12bbb97e15ed35c23e54f9b4483d30b76772ee60d886",
      "m1_commit": "03e412408579105213ed10b6447c85bcd672ba73ecae1e21c463d0df4ef7beb814",
      "nonce": "0x0",
      "presentation_context": "746573742070726573656e746174696f6e20636f6e74657874",
      "proof": "a558da5f17c04adcb0898827aaded14be1dc612dcd12b0579c11bb387ce9ae4b7dbcb3bbe413caaaf754d99e5a342abb7e0041458d670f4b58eda37e745a675295d7a7b86248141d6547b53d793e5c77896ec4dc8dd438ab66d9c8b43ef6b060938a1ca793057b154970ebc3c7ec3a23134e0852d0041f9098ce77311e5b5eca0000000000000000000000000000000000000000000000000000000000000004",
      "r": "42252210dd60ddbbf1a57e3b144e26dd693b7644a9626a8c36896ede53d12930",
      "tag": "031a774fd87a8f18f6420bea43cf5425e7426eec8ba7b8df5c13dc05f10ec652d9",
      "z": "f5a4bbcf14e55e357df9f5ccb5ded37b2b14bc2e1a68e31f86416f0606ee75d1"
    },
    "Presentation2": {
      "U": "035fd233dee2c147155c6008ea64941b6ff7b315aced12531468f2e27bf22e3ef0",
      "U_prime_commit": "02434af337b87fd21d1e3d950aebfc8033a3d2e9dd2bb8b9e7953488078754496d",
      "a": "95bcf45150a61f5c44a6cfbf343cd9e0f593f127b6f49bec0f9b20f0550504a2",
      "m1_commit": "02a578fd3a84eb5b657367b02de39b45fd48ab7781ef8f94efe601274a5ded2a07",
      "nonce": "0x1",
      "presentation_context": "746573742070726573656e746174696f6e20636f6e74657874",
      "proof": "050965cde906fc4723333b100ce0fd9f7b026315f1db16984d4cccb2bc4aa65eb7a17f5b8dfe4f14d40006506ee5fb323e829dd4cb9dc3c455b2e04dd691600aec3cc3f1939198a80acb78b7f90b3bff769cab890f33e4d69b7c302d21ad35ec457d048d3ed7d13ee82c3c0aac2129ad0c8375cf29cd8ea3948a16b9247b1cc5faf69a3116f903b9dcccc4eff31f026041e49797b53c87eca66cfe1040187ef7",
      "r": "d7ed72750b6d366ed0febdc539b52d89434f468a578c59d7ca9015b7da240ad6",
      "tag": "03084fe6fff0ecc7c33ef5c49b492dda38083f52e9a2b70b88f3d4b4ba7b50afba",
      "z": "91eedfb168c556ff5ca3b89d047f482c9279b47f584aab6c7f895f7674251771"
    },
    "ServerKey": {
      "X0": "0232b5e93dc2ff489c20a986a84757c5cc4512f057e1ea92011a26d3ad2c56288d",
      "X1": "03c413230a9bd956718aa46138a33f774f4c708d61c1d6400d404243049d4a31dc",
      "X2": "02db00f6f8e6d235786a120017bd356fe1c9d09069d3ac9352cc9be10ef1505a55",
      "x0": "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
      "x1": "f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1",
      "x2": "350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963",
      "xb": "fd293126bb49a6d793cd77d7db960f5692fec3b7ec07602c60cd32aee595dffd"
    },
    "suite": "ARCV1-P256"
  }
]
"""

struct ARCCredentialTestVector: Codable {
    let U: String
    let U_prime: String
    let X1: String
    let m1: String
}

struct ARCCredentialRequestTestVector: Codable {
    let m1: String
    let m1_enc: String
    let m2: String
    let m2_enc: String
    let proof: String
    let r1: String
    let r2: String
    let request_context: String
}

struct ARCCredentialResponseTestVector: Codable {
    let H_aux: String
    let U: String
    let X0_aux: String
    let X1_aux: String
    let X2_aux: String
    let b: String
    let enc_U_prime: String
    let proof: String
}

struct ARCPresentationTestVector: Codable {
    let U: String
    let U_prime_commit: String
    let a: String
    let m1_commit: String
    let nonce: String
    let presentation_context: String
    let proof: String
    let r: String
    let tag: String
    let z: String
}

struct ARCServerTestVector: Codable {
    let x0: String
    let x1: String
    let x2: String
    let xb: String
    let X0: String
    let X1: String
    let X2: String
}

struct ARCTestVector: Codable {
    let suite: String
    let ServerKey: ARCServerTestVector
    let CredentialRequest: ARCCredentialRequestTestVector
    let CredentialResponse: ARCCredentialResponseTestVector
    let Credential: ARCCredentialTestVector
    let Presentation1: ARCPresentationTestVector
    let Presentation2: ARCPresentationTestVector
}

class ARCTestVectors: XCTestCase {
    func testVectors() throws {
        let data = ARCEncodedTestVector.data(using: .utf8)!
        let decoder = JSONDecoder()
        let testVectors = try decoder.decode([ARCTestVector].self, from: data)
        testVectors.forEach { validateTestVector($0) }
    }

    func validate(_ tv: ARCTestVector) throws {
        let x0 = try p256Scalar(from: tv.ServerKey.x0)
        let x1 = try p256Scalar(from: tv.ServerKey.x1)
        let x2 = try p256Scalar(from: tv.ServerKey.x2)
        let xb = try p256Scalar(from: tv.ServerKey.xb)

        // Initialize server
        let ciphersuite = P256._ARCV1.ciphersuite
        let server = ARC.Server(ciphersuite: ciphersuite, x0: x0, x1: x1, x2: x2, x0Blinding: xb)
        XCTAssertEqual(server.serverPublicKey.X0.oprfRepresentation.hexString, tv.ServerKey.X0)
        XCTAssertEqual(server.serverPublicKey.X1.oprfRepresentation.hexString, tv.ServerKey.X1)
        XCTAssertEqual(server.serverPublicKey.X2.oprfRepresentation.hexString, tv.ServerKey.X2)

        // Initialize precredential, make a credential request
        let requestContext = try Data(hexString: tv.CredentialRequest.request_context)
        let m1 = try p256Scalar(from: tv.CredentialRequest.m1)
        let m2 = try p256Scalar(from: tv.CredentialRequest.m2)
        let r1 = try p256Scalar(from: tv.CredentialRequest.r1)
        let r2 = try p256Scalar(from: tv.CredentialRequest.r2)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, m1: m1, requestContext: requestContext, r1: r1, r2: r2, serverPublicKey: server.serverPublicKey)
        XCTAssertEqual(precredential.credentialRequest.m1Enc.oprfRepresentation.hexString, tv.CredentialRequest.m1_enc)
        XCTAssertEqual(precredential.credentialRequest.m2Enc.oprfRepresentation.hexString, tv.CredentialRequest.m2_enc)
        XCTAssertEqual(precredential.clientSecrets.m2.rawRepresentation.hexString, tv.CredentialRequest.m2)

        // Verify request proof, by creating a new request with the
        // tv.CredentialRequest.proof scalars and verifying it.
        let requestProof = try p256Proof(from: tv.CredentialRequest.proof, scalarCount: ARC.CredentialRequest<CurveHashToGroup<P256>>.getScalarCount())
        let newRequest = ARC.CredentialRequest(m1Enc: precredential.credentialRequest.m1Enc, m2Enc: precredential.credentialRequest.m2Enc, proof: requestProof)
        XCTAssert(try newRequest.verify(generatorG: precredential.generatorG, generatorH: precredential.generatorH, ciphersuite: ciphersuite))

        // Make a credential response, passing in randomness b
        let b = try p256Scalar(from: tv.CredentialResponse.b)
        let response = try server.respond(credentialRequest: precredential.credentialRequest, b: b)
        XCTAssertEqual(response.HAux.oprfRepresentation.hexString, tv.CredentialResponse.H_aux)
        XCTAssertEqual(response.U.oprfRepresentation.hexString, tv.CredentialResponse.U)
        XCTAssertEqual(response.X0Aux.oprfRepresentation.hexString, tv.CredentialResponse.X0_aux)
        XCTAssertEqual(response.X1Aux.oprfRepresentation.hexString, tv.CredentialResponse.X1_aux)
        XCTAssertEqual(response.X2Aux.oprfRepresentation.hexString, tv.CredentialResponse.X2_aux)
        XCTAssertEqual(response.encUPrime.oprfRepresentation.hexString, tv.CredentialResponse.enc_U_prime)

        // Verify response proof, by creating a new response with the
        // tv.CredentialResponse.proof scalars and verifying it.
        let responseProof = try p256Proof(from: tv.CredentialResponse.proof, scalarCount: ARC.CredentialResponse<CurveHashToGroup<P256>>.getScalarCount())
        let newResponse = ARC.CredentialResponse(U: response.U, encUPrime: response.encUPrime, X0Aux: response.X0Aux, X1Aux: response.X1Aux, X2Aux: response.X2Aux, HAux: response.HAux, proof: responseProof)
        XCTAssert(try newResponse.verify(request: precredential.credentialRequest, serverPublicKey: server.serverPublicKey, generatorG: server.generatorG, generatorH: server.generatorH, ciphersuite: ciphersuite))

        // Make a credential from the response
        var credential = try precredential.makeCredential(credentialResponse: response)
        XCTAssertEqual(credential.U.oprfRepresentation.hexString, tv.Credential.U)
        XCTAssertEqual(credential.UPrime.oprfRepresentation.hexString, tv.Credential.U_prime)
        XCTAssertEqual(credential.X1.oprfRepresentation.hexString, tv.Credential.X1)
        XCTAssertEqual(credential.m1.rawRepresentation.hexString, tv.Credential.m1)

        // Make a first presentation from the credential, passing in randomness a, r, z
        let presentationContext1 = try Data(hexString: tv.Presentation1.presentation_context)
        let a1 = try p256Scalar(from: tv.Presentation1.a)
        let r1Presentation = try p256Scalar(from: tv.Presentation1.r)
        let z1 = try p256Scalar(from: tv.Presentation1.z)
        let nonce1 = Int(tv.Presentation1.nonce.replacingOccurrences(of: "0x", with: ""), radix: 16)!
        let (presentation1, returnedNonce1) = try credential.makePresentation(presentationContext: presentationContext1, presentationLimit: 2, a: a1, r: r1Presentation, z: z1, optionalNonce: nonce1)
        XCTAssertEqual(nonce1, returnedNonce1)
        XCTAssertEqual(presentation1.U.oprfRepresentation.hexString, tv.Presentation1.U)
        XCTAssertEqual(presentation1.UPrimeCommit.oprfRepresentation.hexString, tv.Presentation1.U_prime_commit)
        XCTAssertEqual(presentation1.m1Commit.oprfRepresentation.hexString, tv.Presentation1.m1_commit)
        XCTAssertEqual(presentation1.tag.oprfRepresentation.hexString, tv.Presentation1.tag)

        // Verify presentation1 proof, by creating a new presentation with the
        // tv.Presentation1.proof scalars and verifying it.
        let presentation1Proof = try p256Proof(from: tv.Presentation1.proof, scalarCount: ARC.Presentation<CurveHashToGroup<P256>>.getScalarCount())
        let newPresentation1 = ARC.Presentation(U: presentation1.U, UPrimeCommit: presentation1.UPrimeCommit, m1Commit: presentation1.m1Commit, tag: presentation1.tag, proof: presentation1Proof)
        XCTAssert(try newPresentation1.verify(serverPrivateKey: server.serverPrivateKey, X1: server.serverPublicKey.X1, m2: m2, presentationContext: presentationContext1, presentationLimit: 2, nonce: nonce1, generatorG: credential.generatorG, generatorH: credential.generatorH, ciphersuite: ciphersuite))

        // Make a second presentation from the credential, passing in randomness a, r, z
        let presentationContext2 = try Data(hexString: tv.Presentation2.presentation_context)
        let a2 = try p256Scalar(from: tv.Presentation2.a)
        let r2Presentation = try p256Scalar(from: tv.Presentation2.r)
        let z2 = try p256Scalar(from: tv.Presentation2.z)
        let nonce2 = Int(tv.Presentation2.nonce.replacingOccurrences(of: "0x", with: ""), radix: 16)!
        let (presentation2, returnedNonce2) = try credential.makePresentation(presentationContext: presentationContext1, presentationLimit: 2, a: a2, r: r2Presentation, z: z2, optionalNonce: nonce2)
        XCTAssertEqual(nonce2, returnedNonce2)
        XCTAssertEqual(presentation2.U.oprfRepresentation.hexString, tv.Presentation2.U)
        XCTAssertEqual(presentation2.UPrimeCommit.oprfRepresentation.hexString, tv.Presentation2.U_prime_commit)
        XCTAssertEqual(presentation2.m1Commit.oprfRepresentation.hexString, tv.Presentation2.m1_commit)
        XCTAssertEqual(presentation2.tag.oprfRepresentation.hexString, tv.Presentation2.tag)

        // Verify presentation2 proof, by creating a new presentation with the
        // tv.Presentation2.proof scalars and verifying it.
        let presentation2Proof = try p256Proof(from: tv.Presentation2.proof, scalarCount: ARC.Presentation<CurveHashToGroup<P256>>.getScalarCount())
        let newPresentation2 = ARC.Presentation(U: presentation2.U, UPrimeCommit: presentation2.UPrimeCommit, m1Commit: presentation2.m1Commit, tag: presentation2.tag, proof: presentation2Proof)
        XCTAssert(try newPresentation2.verify(serverPrivateKey: server.serverPrivateKey, X1: server.serverPublicKey.X1, m2: m2, presentationContext: presentationContext2, presentationLimit: 2, nonce: nonce2, generatorG: credential.generatorG, generatorH: credential.generatorH, ciphersuite: ciphersuite))

        // Verify both presentations
        XCTAssertTrue(try server.verify(presentation: presentation1, requestContext: requestContext, presentationContext: presentationContext1, presentationLimit: 2, nonce: nonce1))
        XCTAssertTrue(try server.verify(presentation: presentation2, requestContext: requestContext, presentationContext: presentationContext2, presentationLimit: 2, nonce: nonce2))
    }

    func validateTestVector(_ tv: ARCTestVector) {
        XCTAssertEqual(tv.suite, "ARCV1-P256")
        XCTAssertNoThrow(try self.validate(tv))
    }
}

private func p256Scalar(from value: String) throws -> PrimeOrderCurveGroup<P256>.Element.Scalar {
    return try PrimeOrderCurveGroup<P256>.Scalar(canonicalRepresentation: Data(hexString: value))
}

private func p256Proof(from value: String, scalarCount: Int) throws -> Proof<CurveHashToGroup<P256>> {
    let scalarHexCharacterCount = P256.orderByteCount * 2
    var startIndex = value.index(value.startIndex, offsetBy: 0)
    var endIndex = value.index(value.startIndex, offsetBy: scalarHexCharacterCount)

    // Deserialize challenge
    let challengeEnc = try Data(hexString: String(value[startIndex..<endIndex]))
    let challenge = try PrimeOrderCurveGroup<P256>.Scalar(canonicalRepresentation: challengeEnc)

    // Deserialize responses
    var responses: [PrimeOrderCurveGroup<P256>.Scalar] = []
    for _ in (0..<scalarCount-1) {
        startIndex = endIndex
        endIndex = value.index(startIndex, offsetBy: scalarHexCharacterCount)

        let responseEnc = try Data(hexString: String(value[startIndex..<endIndex]))
        let response = try PrimeOrderCurveGroup<P256>.Scalar(canonicalRepresentation: responseEnc)
        responses.append(response)
    }

    return Proof(challenge: challenge, responses: responses)
}
