#if !hasFeature(Embedded)
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
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#endif

extension ARC {
    struct ServerPrivateKey<Scalar: GroupScalar> {
        let x0: Scalar
        let x1: Scalar
        let x2: Scalar
        let x0Blinding: Scalar

        init(x0: Scalar, x1: Scalar, x2: Scalar, x0Blinding: Scalar) {
            self.x0 = x0
            self.x1 = x1
            self.x2 = x2
            self.x0Blinding = x0Blinding
        }
    }

    struct ServerPublicKey<H2G: HashToGroup> {
        typealias Group = H2G.G
        let X0: Group.Element
        let X1: Group.Element
        let X2: Group.Element

        init(X0: Group.Element, X1: Group.Element, X2: Group.Element) {
            self.X0 = X0
            self.X1 = X1
            self.X2 = X2
        }

        init(
            serverPrivateKey: ServerPrivateKey<Group.Scalar>,
            generatorG: Group.Element,
            generatorH: Group.Element
        ) throws(CryptoKitMetaError) {
            let x0Commitment = try generatorG.multiplied(by: serverPrivateKey.x0)
            let x0BlindingCommitment = try generatorH.multiplied(
                by: serverPrivateKey.x0Blinding
            )
            self.X0 = try x0Commitment.adding(x0BlindingCommitment)
            self.X1 = try generatorH.multiplied(by: serverPrivateKey.x1)
            self.X2 = try generatorH.multiplied(by: serverPrivateKey.x2)
        }
     }

    struct Server<H2G: HashToGroup> {
        typealias Group = H2G.G
        let serverPrivateKey: ServerPrivateKey<Group.Scalar>
        let serverPublicKey: ServerPublicKey<H2G>
        let ciphersuite: Ciphersuite<H2G>
        let generatorG: Group.Element
        let generatorH: Group.Element

        init(ciphersuite: Ciphersuite<H2G>) throws {
            try self.init(
                ciphersuite: ciphersuite,
                x0: Group.Scalar.randomNonzero(),
                x1: Group.Scalar.randomNonzero(),
                x2: Group.Scalar.randomNonzero(),
                x0Blinding: Group.Scalar.randomNonzero()
            )
        }

        init(
            ciphersuite: Ciphersuite<H2G>,
            x0: Group.Scalar,
            x1: Group.Scalar,
            x2: Group.Scalar,
            x0Blinding: Group.Scalar
        ) throws {
            self.ciphersuite = ciphersuite
            (self.generatorG, self.generatorH) = try ARC.deriveGenerators(for: ciphersuite)

            self.serverPrivateKey = ServerPrivateKey(x0: x0, x1: x1, x2: x2, x0Blinding: x0Blinding)
            self.serverPublicKey = try ServerPublicKey(
                serverPrivateKey: self.serverPrivateKey,
                generatorG: self.generatorG,
                generatorH: self.generatorH
            )
        }

        func respond(
            credentialRequest: CredentialRequest<H2G>
        ) throws -> CredentialResponse<H2G> {
            try self.respond(
                credentialRequest: credentialRequest,
                b: Group.Scalar.randomNonzero()
            )
        }

        func respond(
            credentialRequest: CredentialRequest<H2G>,
            b: Group.Scalar
        ) throws -> CredentialResponse<H2G> {
            guard
                try credentialRequest.verify(generatorG: generatorG, generatorH: generatorH, ciphersuite: self.ciphersuite)
            else {
                throw ARC.Errors.invalidProof
            }
            return try CredentialResponse(
                request: credentialRequest,
                serverPrivateKey: self.serverPrivateKey,
                serverPublicKey: self.serverPublicKey,
                generatorG: generatorG,
                generatorH: generatorH,
                b: b,
                ciphersuite: self.ciphersuite
            )
        }

        func verify(presentation: Presentation<H2G>, requestContext: Data, presentationContext: Data, presentationLimit: Int, nonce: Int) throws -> Bool {
            let m2 = try H2G.hashToScalar(requestContext, domainSeparationContext: Data((self.ciphersuite.domain + "requestContext").utf8))
            return try presentation.verify(
                serverPrivateKey: self.serverPrivateKey,
                X1: self.serverPublicKey.X1,
                m2: m2,
                presentationContext: presentationContext,
                presentationLimit: presentationLimit,
                nonce: nonce,
                generatorG: generatorG,
                generatorH: generatorH,
                ciphersuite: self.ciphersuite
            )
        }
    }
}

#endif  // !hasFeature(Embedded)
